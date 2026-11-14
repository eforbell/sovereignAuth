"""The OAuth callback helper (wire contract, section 10): vectors/oauth.json as test/oauth.test.js runs it,
the store, configuration, and the landing page compared byte for byte with Node's."""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace

from sovereign_auth.oauth import MemoryStateStore, OAuthFlow, OAuthRecord, pkce_challenge

ROOT = Path(__file__).resolve().parents[2]
VECTORS = json.loads((ROOT / "vectors" / "oauth.json").read_text("utf-8"))
CLEAR = "__Host-sv_oauth=; Secure; HttpOnly; Path=/; SameSite=Strict; Max-Age=0"


def member(user_id):
    return None if user_id is None else SimpleNamespace(user_id=user_id)


def flow(**options):
    settings = dict(hostname=VECTORS["hostname"], landing_path=VECTORS["landing_path"], completion_path="complete", done_path="../settings")
    settings.update(options)
    return OAuthFlow(**settings)


def record_from(vector: dict) -> OAuthRecord:
    return OAuthRecord(
        state=vector["state"],
        user_id=vector["userId"],
        hostname=vector["hostname"],
        correlation=vector["correlation"],
        code_verifier=vector["codeVerifier"],
        created=vector["created"],
        data=vector["data"],
    )


class OAuthVectors(unittest.TestCase):
    def test_completion(self):
        base = VECTORS["base"]
        for entry in VECTORS["cases"]:
            with self.subTest(entry["name"]):
                store = MemoryStateStore(now=lambda: VECTORS["now"])
                record = None
                if entry.get("record", "base") is not None:
                    record = record_from({**base["record"], **entry.get("record_set", {})})
                    store.put(record)
                headers = dict(base["headers"])
                for name, value in entry.get("headers_set", {}).items():
                    if value is None:
                        headers.pop(name, None)
                    else:
                        headers[name] = value
                oauth = flow(store=store, now=lambda: VECTORS["now"] + entry.get("now_offset_ms", 0))
                body = entry["body"] if "body" in entry else base["body"]
                result = asyncio.run(oauth.complete(member=member(entry["member"] if "member" in entry else base["member"]), headers=headers, body=body))
                if entry["expect"]["ok"]:
                    self.assertTrue(result.ok, result.reason)
                    self.assertEqual(result.code, base["body"]["code"])
                    self.assertEqual(result.code_verifier, base["record"]["codeVerifier"])
                    self.assertEqual(result.data, base["record"]["data"])
                else:
                    self.assertEqual(
                        {"ok": result.ok, "status": result.status, "reason": result.reason},
                        entry["expect"],
                    )
                    self.assertEqual(result.body, {"error": "oauth_refused", "reason": entry["expect"]["reason"]})
                self.assertEqual(result.clear_cookie, CLEAR)
                if record and entry["expect"].get("reason") != "malformed":
                    self.assertIsNone(store.take(record.state), "the record is used up")

    def test_pkce(self):
        for pair in VECTORS["pkce"]:
            self.assertEqual(pkce_challenge(pair["verifier"]), pair["challenge"])


class OAuthFlowTests(unittest.TestCase):
    def test_start_stores_a_single_use_record_and_the_code_works_once(self):
        clock = {"now": VECTORS["now"]}
        store = MemoryStateStore(now=lambda: clock["now"])
        oauth = flow(store=store, now=lambda: clock["now"])
        started = asyncio.run(oauth.start(member("1001"), data={"provider": "schwab"}))
        self.assertRegex(started.state, r"^[A-Za-z0-9_-]{43}\Z")
        self.assertEqual(started.code_challenge_method, "S256")
        prefix, suffix = "__Host-sv_oauth=", "; Secure; HttpOnly; Path=/; SameSite=Strict; Max-Age=600"
        self.assertTrue(started.set_cookie.startswith(prefix) and started.set_cookie.endswith(suffix))
        correlation = started.set_cookie[len(prefix) : -len(suffix)]
        self.assertRegex(correlation, r"^[A-Za-z0-9_-]{43}\Z")
        self.assertNotEqual(correlation, started.state)

        clock["now"] += 30_000
        request = dict(member=member("1001"), headers={"cookie": f"__Host-sv_oauth={correlation}"}, body={"code": "abc", "state": started.state})
        done = asyncio.run(oauth.complete(**request))
        self.assertTrue(done.ok, done.reason)
        self.assertEqual(pkce_challenge(done.code_verifier), started.code_challenge)
        self.assertEqual(done.data, {"provider": "schwab"})
        self.assertEqual(asyncio.run(oauth.complete(**request)).reason, "unknown_state", "replayed")

        plain = asyncio.run(oauth.start(member("1001"), pkce=False))
        self.assertEqual((plain.code_challenge, plain.code_challenge_method), (None, None))
        with self.assertRaisesRegex(ValueError, "starts for a member"):
            asyncio.run(oauth.start(None))

    def test_a_wrong_attempt_uses_the_state_up(self):
        oauth = flow()
        started = asyncio.run(oauth.start(member("1001")))
        correlation = started.set_cookie.split(";")[0].split("=")[1]
        right = dict(member=member("1001"), headers={"cookie": f"__Host-sv_oauth={correlation}"}, body={"code": "abc", "state": started.state})
        self.assertEqual(asyncio.run(oauth.complete(**{**right, "member": member("1002")})).reason, "wrong_member")
        self.assertEqual(asyncio.run(oauth.complete(**right)).reason, "unknown_state")

    def test_an_async_store_works(self):
        records = {}

        class AsyncStore:
            async def put(self, record):
                records[record.state] = record

            async def take(self, state):
                return records.pop(state, None)

        oauth = flow(store=AsyncStore())
        started = asyncio.run(oauth.start(member("1001")))
        correlation = started.set_cookie.split(";")[0].split("=")[1]
        done = asyncio.run(oauth.complete(member=member("1001"), headers={"cookie": f"__Host-sv_oauth={correlation}"}, body={"code": "abc", "state": started.state}))
        self.assertTrue(done.ok, done.reason)
        self.assertEqual(records, {})

    def test_codex_round_two(self):
        """Inputs Node refuses that the port accepted; expected values are Node's."""
        for hostname in ["1.2.3.999", "999.1.1.1", "0x7f.1"]:
            with self.subTest(hostname=hostname), self.assertRaisesRegex(ValueError, "hostname"):
                OAuthFlow(hostname=hostname, landing_path="/cb", completion_path="/done")
        # The clock's fractions are kept: started at 1000.9 ms, completed at 1000.5 ms is from the future.
        clock = {"now": 1000.9}
        oauth = flow(now=lambda: clock["now"], store=MemoryStateStore(now=lambda: clock["now"]))
        started = asyncio.run(oauth.start(member("1001")))
        correlation = started.set_cookie.split(";")[0].split("=")[1]
        clock["now"] = 1000.5
        done = asyncio.run(oauth.complete(member=member("1001"), headers={"cookie": f"__Host-sv_oauth={correlation}"}, body={"code": "abc", "state": started.state}))
        self.assertEqual(done.reason, "expired")
        # Member IDs compare without coercion: 1 is not True.
        store = MemoryStateStore(now=lambda: VECTORS["now"])
        store.put(record_from({**VECTORS["base"]["record"], "userId": 1}))
        done = asyncio.run(flow(store=store, now=lambda: VECTORS["now"]).complete(member=member(True), headers=VECTORS["base"]["headers"], body=VECTORS["base"]["body"]))
        self.assertEqual(done.reason, "wrong_member")
        # An object hidden in a cookie list is [object Object] to JavaScript, not a cookie.
        store = MemoryStateStore(now=lambda: VECTORS["now"])
        store.put(record_from(VECTORS["base"]["record"]))
        hidden = {"cookie": [{"x": "; " + VECTORS["base"]["headers"]["cookie"] + ";"}]}
        done = asyncio.run(flow(store=store, now=lambda: VECTORS["now"]).complete(member=member("1001"), headers=hidden, body=VECTORS["base"]["body"]))
        self.assertEqual(done.reason, "no_cookie")

    def test_an_empty_correlation_cookie_is_refused_as_node_refuses_it(self):
        store = MemoryStateStore(now=lambda: VECTORS["now"])
        store.put(record_from(VECTORS["base"]["record"]))
        result = asyncio.run(flow(store=store, now=lambda: VECTORS["now"]).complete(member=member("1001"), headers={"cookie": "__Host-sv_oauth="}, body=VECTORS["base"]["body"]))
        self.assertEqual((result.ok, result.status, result.reason), (False, 403, None))

    def test_the_memory_store_forgets_expired_records_and_stays_bounded(self):
        clock = {"now": 0}
        store = MemoryStateStore(max_entries=3, now=lambda: clock["now"])

        def put(state):
            store.put(SimpleNamespace(state=state, created=clock["now"]))

        put("a")
        clock["now"] = 601_000
        put("b")
        self.assertIsNone(store.take("a"), "expired and swept")
        put("c")
        put("d")
        put("e")
        self.assertIsNone(store.take("b"), "the oldest went to make room")
        self.assertEqual([store.take(state).state for state in "cde"], ["c", "d", "e"])
        self.assertIsNone(store.take("c"), "taken once")

    def test_configuration_that_could_point_the_page_elsewhere_is_refused(self):
        base = dict(hostname=VECTORS["hostname"], landing_path="/oauth/callback", completion_path="complete")
        cases = [
            ("upper-case hostname", {"hostname": "Smith-Helm.example.ts.net"}, "hostname"),
            ("relative landing path", {"landing_path": "oauth/callback"}, "landing_path"),
            ("landing path with a query", {"landing_path": "/oauth/callback?x=1"}, "landing_path"),
            ("completion on another origin", {"completion_path": "https://evil.example/complete"}, "completion_path"),
            ("protocol-relative completion", {"completion_path": "//evil.example/complete"}, "completion_path"),
            ("three leading slashes, a host to a browser", {"completion_path": "///evil.example/collect"}, "completion_path"),
            ("four leading slashes on the done path", {"done_path": "////evil.example/collect"}, "done_path"),
            ("javascript: done path", {"done_path": "javascript:alert(1)"}, "done_path"),
            ("backslash done path", {"done_path": "\\\\evil.example"}, "done_path"),
            ("a leading NUL before //", {"completion_path": "\x00//attacker.example/collect"}, "completion_path"),
            ("a leading tab before //", {"done_path": "\t//attacker.example"}, "done_path"),
            ("a C1 control before //", {"done_path": "\x85//attacker.example"}, "done_path"),
            ("a path that climbs to another origin", {"completion_path": "/\\attacker.example"}, "completion_path"),
            ("landing path with a NUL", {"landing_path": "/oauth/\x00callback"}, "landing_path"),
            ("a store without take", {"store": SimpleNamespace(put=lambda record: None)}, "put"),
        ]
        for name, options, message in cases:
            with self.subTest(name), self.assertRaisesRegex(ValueError, message):
                OAuthFlow(**{**base, **options})
        with self.assertRaisesRegex(ValueError, "nonce"):
            flow().landing(nonce='"><script>')
        for path in ["complete", "./complete", "/oauth/complete", "../settings", "."]:
            OAuthFlow(**{**base, "completion_path": path, "done_path": path})

    def test_the_landing_page_changes_nothing_and_sends_no_referer(self):
        page = flow().landing(nonce="abc123==")
        self.assertEqual(page.status, 200)
        self.assertEqual(page.headers, {"content-type": "text/html; charset=utf-8", "cache-control": "no-store", "referrer-policy": "no-referrer"})
        self.assertIn('<script nonce="abc123==">', page.body)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_landing_page_is_node_s_byte_for_byte(self):
        """The Node tests run the page's script against a stand-in browser; the same bytes need no second run."""
        for options in [{}, {"completion_path": "/helm/oauth/complete", "done_path": "/helm/settings?linked=1"}]:
            settings = {"completionPath": options.get("completion_path", "complete"), "donePath": options.get("done_path", "../settings")}
            script = (
                "const { createOAuthFlow } = require(process.argv[1]);"
                "const o = JSON.parse(process.argv[2]);"
                "const flow = createOAuthFlow({ hostname: o.hostname, landingPath: o.landingPath, completionPath: o.completionPath, donePath: o.donePath });"
                "process.stdout.write(JSON.stringify([flow.landing().body, flow.landing({ nonce: 'n0nce' }).body]));"
            )
            config = json.dumps({"hostname": VECTORS["hostname"], "landingPath": VECTORS["landing_path"], **settings})
            node = json.loads(subprocess.run(["node", "-e", script, str(ROOT / "src" / "oauth.js"), config], capture_output=True, text=True, check=True).stdout)
            python = flow(**options)
            self.assertEqual([python.landing().body, python.landing(nonce="n0nce").body], node, options)


if __name__ == "__main__":
    unittest.main()
