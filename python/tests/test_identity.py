"""Modes, socket listen, member resolution and the places where Python would decide differently from Node
if the port used Python's defaults (test/identity.test.js, plus parity checks)."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sovereign_auth import Identity, SnapshotError, SnapshotState, auth_mode, create_request_guard, normalize_origin, parse_snapshot
from sovereign_auth._js import parse_json
from sovereign_auth.snapshot import parse_timestamp_ms

VECTORS = Path(__file__).resolve().parents[2] / "vectors"
BASE = json.loads((VECTORS / "snapshot.json").read_text("utf-8"))["snapshot"]
SNAPSHOT = parse_snapshot(BASE)
PARENT = {"x-sovereign-user-id": "1001", "x-sovereign-login": "parent@example.com"}
SOCKET = "unix:/run/sovereign-apps/family-pulse/app.sock"


class GoodReader:
    def current(self):
        return SnapshotState(ok=True, snapshot=SNAPSHOT)


class StaleReader:
    def current(self):
        return SnapshotState(ok=False, reason="stale", message="old")


def changed(**fields):
    data = copy.deepcopy(BASE)
    data.update(fields)
    return data


class ModeTests(unittest.TestCase):
    def test_the_mode_is_local_or_tailnet_and_nothing_else_starts(self):
        self.assertEqual(auth_mode("local"), "local")
        self.assertEqual(auth_mode(" tailnet\n"), "tailnet")
        self.assertEqual(auth_mode("﻿tailnet"), "tailnet", "JavaScript's trim() strips a BOM")
        for bad in [None, "", "Tailnet", "both", "off", "true", "\x1ctailnet"]:
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "local or tailnet"):
                auth_mode(bad)

    def test_tailnet_mode_refuses_to_start_unless_the_app_listens_on_its_socket(self):
        for listen in [None, "", "127.0.0.1:3000", "unix:", "unix:relative.sock"]:
            with self.subTest(listen=listen), self.assertRaisesRegex(ValueError, "SOVEREIGN_LISTEN"):
                Identity(app_id="family-pulse", mode="tailnet", listen=listen, reader=GoodReader())
        with self.assertRaisesRegex(ValueError, "snapshot reader"):
            Identity(app_id="family-pulse", mode="tailnet", listen=SOCKET)
        with self.assertRaisesRegex(ValueError, "app's ID"):
            Identity(app_id="", mode="local")

    def test_tailnet_mode_resolves_the_member_from_the_snapshot(self):
        identity = Identity(app_id="family-pulse", mode="tailnet", listen=SOCKET, reader=GoodReader())
        result = identity.identify(PARENT)
        self.assertEqual(result.member.member_id, "m_parent")
        self.assertIs(result.snapshot, SNAPSHOT)
        repeated = dict(PARENT, **{"x-sovereign-login": ["parent@example.com", "parent@example.com"]})
        self.assertEqual(identity.identify(repeated).reason, "no_identity", "a repeated header is not a login")

    def test_no_snapshot_means_no_member_with_the_snapshots_reason(self):
        identity = Identity(app_id="family-pulse", mode="tailnet", listen=SOCKET, reader=StaleReader())
        result = identity.identify(PARENT)
        self.assertIsNone(result.member)
        self.assertEqual((result.reason, result.snapshot_reason, result.snapshot), ("no_snapshot", "stale", None))

    def test_local_mode_ignores_the_identity_headers_and_needs_no_socket_or_snapshot(self):
        result = Identity(app_id="family-pulse", mode="local").identify(PARENT)
        self.assertEqual((result.member, result.reason, result.snapshot), (None, "local_mode", None))


class ParityTests(unittest.TestCase):
    """Cases the vectors don't spell out, where Python's defaults differ from JavaScript's."""

    def reason(self, data):
        try:
            parse_snapshot(data)
        except SnapshotError as error:
            return error.reason
        return "ok"

    def test_json_numbers_follow_number_is_safe_integer(self):
        self.assertEqual(self.reason(changed(format=True)), "format", "true is not 1")
        self.assertEqual(self.reason(changed(format=1.0)), "ok", "JSON 1.0 is 1")
        self.assertEqual(self.reason(changed(generation=True)), "malformed")
        self.assertEqual(self.reason(changed(generation=7.0)), "ok")
        self.assertEqual(self.reason(changed(generation=2**53)), "malformed", "beyond Number.MAX_SAFE_INTEGER")
        self.assertEqual(self.reason(changed(global_epoch=False)), "malformed")
        members = copy.deepcopy(BASE["members"])
        members[0]["epoch"] = True
        self.assertEqual(self.reason(changed(members=members)), "malformed")

    def test_non_objects_where_objects_belong_are_malformed_not_errors(self):
        self.assertEqual(self.reason(changed(members=["x"])), "malformed")
        self.assertEqual(self.reason(changed(keys=[["k1"]])), "malformed")
        members = copy.deepcopy(BASE["members"])
        members[0]["role"] = ["parent"]
        self.assertEqual(self.reason(changed(members=members)), "malformed")
        self.assertEqual(self.reason(changed(written_at=12345)), "malformed")

    def test_patterns_match_the_whole_value(self):
        """Python's $ also matches before a final newline; JavaScript's doesn't, and base64 decoding would
        then drop the newline and accept the key."""
        keys = copy.deepcopy(BASE["keys"])
        keys[0]["public_key"] += "\n"
        self.assertEqual(self.reason(changed(keys=keys)), "malformed")
        self.assertEqual(self.reason(changed(written_at="2026-10-28T19:00:00.000Z\n")), "malformed")
        self.assertEqual(self.reason(changed(written_at="\uff12\uff10\uff12\uff16-10-28T19:00:00Z")), "malformed", "fullwidth digits")
        self.assertEqual(self.reason(changed(written_at="0000-01-01T00:00:00Z")), "malformed", "a year the calendar can't hold")
        with self.assertRaises(ValueError):
            normalize_origin("https://example.ts.net\n")

    def test_written_at_is_rfc_3339_with_a_zone(self):
        self.assertEqual(parse_timestamp_ms("2026-10-28T19:00:00.000Z"), 1793214000000)
        self.assertEqual(parse_timestamp_ms("2026-10-28T21:00:00+02:00"), 1793214000000)
        self.assertEqual(parse_timestamp_ms("2026-10-28T19:00:00.1239Z"), 1793214000123)
        for bad in ["2026-10-28T19:00:00", "2026-02-30T00:00:00Z", "2026-10-28T24:00:00Z", "yesterday", "2026-10-28"]:
            with self.subTest(bad=bad):
                self.assertIsNone(parse_timestamp_ms(bad))

    def test_json_refuses_nan_and_infinity(self):
        for text in ["NaN", "[Infinity]", "{\"a\": -Infinity}"]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_json(text)

    def test_origins_normalize_like_the_url_parser_or_refuse(self):
        self.assertEqual(normalize_origin("https://EXAMPLE.ts.net/"), "https://example.ts.net")
        self.assertEqual(normalize_origin("https://example.ts.net:443"), "https://example.ts.net")
        self.assertEqual(normalize_origin("http://127.0.0.1:8080"), "http://127.0.0.1:8080")
        self.assertEqual(normalize_origin("https://smith-helm.example-tailnet.ts.net"), "https://smith-helm.example-tailnet.ts.net")
        for bad in ["example.ts.net", "ftp://example.ts.net", "https://example.ts.net/app", "https://u:p@example.ts.net", "https://example.ts.net?", "https://example.ts.net#x", " https://example.ts.net", "https://bücher.example", "https:\\\\example.ts.net", "https://example.ts.net:99999", "http://127.1", "http://0x7f.0.0.1", "http://127.0.0.01", "http://1.2.3.4.", "http://[::1]", "https://example.123"]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                normalize_origin(bad)

    def test_a_repeated_header_is_joined_as_node_joins_it(self):
        guard = create_request_guard("https://pulse.example-tailnet.ts.net")
        twice = {"sec-fetch-site": ["same-origin", "same-origin"]}
        self.assertEqual(guard.check("GET", twice).reason, "fetch_metadata_malformed")
        origin = {"sec-fetch-site": "same-origin", "content-type": "application/json", "origin": ["https://pulse.example-tailnet.ts.net"] * 2}
        self.assertEqual(guard.check("POST", origin).reason, "origin_mismatch")

    def test_values_stringify_as_javascript_does(self):
        guard = create_request_guard("https://pulse.example-tailnet.ts.net")
        self.assertTrue(guard.check("GET", {"sec-fetch-site": [["same-origin"]]}).allowed, "a nested list joins to its one value")
        self.assertTrue(guard.check(["GET"], {"sec-fetch-site": "same-origin"}).allowed, "String(['GET']) is GET")
        self.assertEqual(guard.check(None, {"sec-fetch-site": "same-origin"}).reason, "origin_missing", "String(null) is not a safe method")

    def test_numbers_stringify_as_javascript_does(self):
        from sovereign_auth._js import number_to_string

        self.assertEqual([number_to_string(x) for x in [1e-7, 0.000001, 1e21, 1e20, 100.0, -0.0, 2**53 + 1]], ["1e-7", "0.000001", "1e+21", "100000000000000000000", "100", "0", "9007199254740992"])
        guard = create_request_guard("https://example.com", isolate=False, content_types=["1e-07"])
        self.assertEqual(guard.check("POST", {"origin": "https://example.com", "content-type": [1e-7]}).reason, "content_type", "String(1e-7) is 1e-7")

    def test_objects_stringify_as_plain_objects(self):
        from sovereign_auth._js import to_string

        self.assertEqual(to_string([{"x": "; a=b;"}, ["c"]]), "[object Object],c")
        guard = create_request_guard("https://example.com", isolate=False)
        smuggled = {"origin": "https://example.com", "content-type": [{"x": "application/json"}]}
        self.assertEqual(guard.check("POST", smuggled).reason, "content_type")

    def test_content_types_are_strings(self):
        with self.assertRaises(ValueError):
            create_request_guard("https://example.com", content_types=[None])

    def test_isolate_is_a_boolean(self):
        for value in [[], {}, 0, "", None, "false"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                create_request_guard("https://pulse.example-tailnet.ts.net", isolate=value)

    def test_a_guard_needs_an_origin_and_a_content_type(self):
        with self.assertRaises(ValueError):
            create_request_guard([])
        with self.assertRaises(ValueError):
            create_request_guard("https://pulse.example-tailnet.ts.net", content_types=[])


if __name__ == "__main__":
    unittest.main()
