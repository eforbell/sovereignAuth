"""Runs vectors/assurance.json (tokens, request digests and assurance decisions) as
test/assurance-vectors.test.js does, plus what the Python port adds: the copied policy matrix and the
every-time path without a redeemer."""

from __future__ import annotations

import asyncio
import base64
import json
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sovereign_auth import (
    Assurance,
    AssuranceRequest,
    Identity,
    SnapshotState,
    parse_snapshot,
    request_digest,
    sign_token,
    verify_token,
)
from sovereign_auth.tokens import encode_base64url

ROOT = Path(__file__).resolve().parents[2]
VECTORS = json.loads((ROOT / "vectors" / "assurance.json").read_text("utf-8"))
SNAPSHOT = parse_snapshot(VECTORS["snapshot"])
NOW_MS = VECTORS["now"] * 1000
KEYS = {
    kid: Ed25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(seed + "=" * (-len(seed) % 4)))
    for kid, seed in VECTORS["signing_keys"].items()
}
BY_NAME = {entry["name"]: entry for entry in VECTORS["tokens"]}
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
SOCKET = "unix:/run/sovereign-apps/test/app.sock"


def claims_for(kind, change=None, digest=None):
    change = change or {}
    claims = dict(VECTORS["base_claims"][kind])
    claims.update(change.get("set", {}))
    for name in change.get("remove", []):
        claims.pop(name, None)
    if claims.get("dig") == "<digest>":
        claims["dig"] = digest
    return claims


def sign(claims, sign_with=None):
    key = KEYS[sign_with or claims.get("kid")]
    if not isinstance(claims.get("kid"), str):
        # sign_token insists on a kid, so a vector without one is signed by hand.
        signed = "v1." + encode_base64url(json.dumps(claims).encode("utf-8"))
        return f"{signed}.{encode_base64url(key.sign(signed.encode('ascii')))}"
    return sign_token(claims, key)


def token_for(entry):
    if "token" in entry:
        return entry["token"]
    token = sign(claims_for(entry["kind"], entry.get("claims")), entry.get("sign_with"))
    version, payload, signature = token.split(".")
    transform = entry.get("token_transform", "")
    if transform == "pad_payload":
        return f"{version}.{payload}=.{signature}"
    if transform == "respell_signature":
        last = ALPHABET[ALPHABET.index(signature[-1]) ^ 1]
        return f"{version}.{payload}.{signature[:-1]}{last}"
    if transform == "extra_part":
        return f"{token}.x"
    if transform == "drop_signature":
        return f"{version}.{payload}."
    if transform == "version_v2":
        return f"v2.{payload}.{signature}"
    if transform.startswith("swap_payload_from:"):
        return f"{version}.{token_for(BY_NAME[transform[18:]]).split('.')[1]}.{signature}"
    assert transform == "", f"unknown transform {transform}"
    return token


class GoodReader:
    def current(self):
        return SnapshotState(ok=True, snapshot=SNAPSHOT)


IDENTITY = Identity(app_id=VECTORS["app"], mode="tailnet", listen=SOCKET, reader=GoodReader())


class AssuranceVectors(unittest.TestCase):
    def test_tokens(self):
        for entry in VECTORS["tokens"]:
            with self.subTest(entry["name"]):
                result = verify_token(token_for(entry), keys=SNAPSHOT.keys, now=lambda: NOW_MS)
                self.assertEqual(result.ok, entry["expect"]["ok"], result.reason)
                if not entry["expect"]["ok"]:
                    self.assertEqual(result.reason, entry["expect"]["reason"])

    def test_the_respelled_signature_decodes_to_the_same_bytes(self):
        entry = next(item for item in VECTORS["tokens"] if item.get("token_transform") == "respell_signature")
        original = sign(claims_for(entry["kind"], entry.get("claims"))).split(".")[2]
        respelled = token_for(entry).split(".")[2]
        self.assertNotEqual(respelled, original)
        decode = lambda text: base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        self.assertEqual(decode(respelled), decode(original))

    def test_digests(self):
        for entry in VECTORS["digests"]:
            with self.subTest(f"{entry['method']} {entry['url']}"):
                self.assertEqual(request_digest(method=entry["method"], url=entry["url"], body=entry["body"], target=entry["target"]), entry["digest"])

    def test_assurance(self):
        for entry in VECTORS["assurance"]:
            with self.subTest(entry["name"]):
                calls = []

                async def redeem(**request):
                    calls.append(request)
                    return {"redeemed": True} if entry.get("redeem") == "redeemed" else {"redeemed": False, "reason": entry.get("redeem")}

                assurance = Assurance(
                    app_id=VECTORS["app"],
                    hostname=VECTORS["hostname"],
                    identity=IDENTITY,
                    now=lambda: NOW_MS,
                    is_administrator=lambda member: member.user_id in VECTORS["administrators"],
                    redeem=redeem,
                )
                target = entry.get("target", "")
                headers = dict(entry["identity"])
                if entry.get("cookie"):
                    headers["cookie"] = entry["cookie"].replace("<token>", sign(claims_for("assurance", entry.get("claims"))))
                if entry.get("action") is not None:  # {} is a token with the base claims
                    digest = request_digest(method=entry["request"]["method"], url=entry["request"]["url"], body=entry["request"]["body"], target=target)
                    headers["x-sovereign-action-token"] = sign(claims_for("action", entry["action"], digest))
                request = AssuranceRequest(method=entry["request"]["method"], url=entry["request"]["url"], headers=headers, body=entry["request"]["body"])
                decision = asyncio.run(assurance.check(entry["policy"], request, target))
                if entry["expect"]["allowed"]:
                    self.assertTrue(decision.allowed, decision.reason)
                    self.assertEqual(decision.level, entry["expect"]["level"])
                else:
                    self.assertEqual(
                        {"allowed": decision.allowed, "status": decision.status, "body": decision.body, "reason": decision.reason},
                        entry["expect"],
                    )
                if "redeem_calls" in entry:
                    self.assertEqual(len(calls), entry["redeem_calls"])
                for call in calls:
                    self.assertEqual(sorted(call), ["digest", "policy", "target", "token"])
                    self.assertEqual(call["policy"], entry["policy"])
                    self.assertEqual(call["target"], target)
                    self.assertEqual(call["token"], headers["x-sovereign-action-token"])


class PortTests(unittest.TestCase):
    def test_the_policy_matrix_is_the_node_librarys_byte_for_byte(self):
        copied = (ROOT / "python" / "sovereign_auth" / "policy.json").read_bytes()
        self.assertEqual(copied, (ROOT / "src" / "policy.json").read_bytes())

    def every_time_request(self):
        target = "backup 1"
        request = AssuranceRequest(method="POST", url="/api/plans", headers={"x-sovereign-user-id": "1001", "x-sovereign-login": "parent@example.com"}, body=b"{}")
        digest = request_digest(method="POST", url="/api/plans", body=b"{}", target=target)
        claims = claims_for("action", {"set": {"tgt": target}}, digest)
        request.headers["x-sovereign-action-token"] = sign(claims)
        return request, target

    def assurance(self, **options):
        settings = dict(app_id=VECTORS["app"], hostname=VECTORS["hostname"], identity=IDENTITY, now=lambda: NOW_MS, is_administrator=lambda member: True)
        settings.update(options)
        return Assurance(**settings)

    def test_without_a_redeemer_every_time_actions_are_refused_as_unavailable(self):
        request, target = self.every_time_request()
        decision = asyncio.run(self.assurance().check("privileged-plan", request, target))
        self.assertEqual((decision.allowed, decision.status, decision.reason), (False, 403, "redemption_unavailable"))

    def test_a_redeemer_that_fails_or_answers_oddly_is_a_refusal(self):
        request, target = self.every_time_request()

        def broken(**_):
            raise OSError("no socket")

        for redeem in [broken, lambda **_: None, lambda **_: {"redeemed": 1}, lambda **_: {"redeemed": "true"}]:
            decision = asyncio.run(self.assurance(redeem=redeem).check("privileged-plan", request, target))
            self.assertEqual(decision.status, 403)
            self.assertFalse(decision.allowed)
        decision = asyncio.run(self.assurance(redeem=lambda **_: {"redeemed": True}).check("privileged-plan", request, target))
        self.assertTrue(decision.allowed, decision.reason)

    def test_only_true_from_is_administrator_counts_and_it_may_be_async(self):
        cookie = "__Host-sv_assurance=" + sign(claims_for("assurance"))
        request = AssuranceRequest(method="GET", url="/", headers={"x-sovereign-user-id": "1001", "x-sovereign-login": "parent@example.com", "cookie": cookie})

        async def yes(member):
            return True

        for answer, allowed in [(lambda m: 1, False), (lambda m: "yes", False), (lambda m: True, True), (yes, True)]:
            decision = asyncio.run(self.assurance(is_administrator=answer).check("open-admin", request))
            self.assertEqual(decision.allowed, allowed, decision.reason)
        with self.assertRaisesRegex(ValueError, "is_administrator"):
            asyncio.run(self.assurance(is_administrator=None).check("open-admin", request))

    def test_claims_compare_without_coercion(self):
        request = AssuranceRequest(method="GET", url="/", headers={"x-sovereign-user-id": "1004", "x-sovereign-login": "tagged-devices"})
        self.assertEqual(asyncio.run(self.assurance().check("use-app", request)).reason, "tagged")
        # Member 1002 has epoch 1: a token claiming epoch true must not pass as 1.
        kid = {"x-sovereign-user-id": "1002", "x-sovereign-login": "kid@example.com"}
        for epoch, reason in [(True, "stale_epoch"), (1.0, None), ("1", "stale_epoch")]:
            claims = claims_for("assurance", {"set": {"sub": "1002", "epoch": epoch}})
            request = AssuranceRequest(method="GET", url="/", headers=dict(kid, cookie="__Host-sv_assurance=" + sign(claims)))
            decision = asyncio.run(self.assurance().check("open-documents", request))
            self.assertEqual(decision.reason, reason, epoch)

    def test_a_body_is_needed_when_the_headers_say_there_is_one(self):
        request, target = self.every_time_request()
        for headers, raises in [({"content-length": "2"}, True), ({"transfer-encoding": "chunked"}, True), ({"content-length": "0"}, False), ({"content-length": "abc"}, False), ({"content-length": "0x1"}, True)]:
            bodiless = AssuranceRequest(method="POST", url="/api/plans", headers={**request.headers, **headers}, body=None)
            check = self.assurance(redeem=lambda **_: {"redeemed": True}).check("privileged-plan", bodiless, target)
            if raises:
                with self.assertRaisesRegex(ValueError, "raw request body"):
                    asyncio.run(check)
            else:
                asyncio.run(check)


class CodexRoundOne(unittest.TestCase):
    """Inputs where the port decided differently from Node before; expected values are Node's."""

    def setUp(self):
        self.parent = {"x-sovereign-user-id": "1001", "x-sovereign-login": "parent@example.com"}
        self.token = sign(claims_for("assurance"))

    def assurance(self, **options):
        settings = dict(app_id=VECTORS["app"], hostname=VECTORS["hostname"], identity=IDENTITY, now=lambda: NOW_MS, is_administrator=lambda member: True)
        settings.update(options)
        return Assurance(**settings)

    def check(self, policy, headers, *, body=None, target="", **options):
        request = AssuranceRequest(method="POST", url="/api/plans", headers={**self.parent, **headers}, body=body)
        return asyncio.run(self.assurance(**options).check(policy, request, target))

    def test_a_nested_cookie_list_still_shows_the_duplicate(self):
        cookie = "__Host-sv_assurance=" + self.token
        decision = self.check("open-documents", {"cookie": [cookie, [cookie]]})
        self.assertEqual((decision.status, decision.reason), (401, "duplicate_cookie"))

    def test_an_empty_cookie_value_steps_up_with_no_reason(self):
        decision = self.check("open-documents", {"cookie": "__Host-sv_assurance="})
        self.assertEqual((decision.status, decision.reason), (401, None))

    def test_any_sign_of_a_body_needs_the_raw_body(self):
        for headers in [{"content-length": True}, {"content-length": [["1"]]}, {"transfer-encoding": None}, {"content-length": 1}]:
            with self.subTest(headers=headers), self.assertRaisesRegex(ValueError, "raw request body"):
                self.check("privileged-plan", headers, redeem=lambda **_: {"redeemed": True})
        for headers in [{"content-length": False}, {"content-length": ""}, {"content-length": [["1", "2"]]}, {"content-length": None}]:
            with self.subTest(headers=headers):
                self.check("privileged-plan", headers, redeem=lambda **_: {"redeemed": True})

    def test_a_null_action_header_is_malformed_not_missing(self):
        decision = self.check("privileged-plan", {"x-sovereign-action-token": None})
        self.assertEqual((decision.status, decision.reason), (401, "malformed"))

    def test_the_redeemers_reason_passes_through(self):
        digest = request_digest(method="POST", url="/api/plans", body=b"{}", target="t")
        token = sign(claims_for("action", {"set": {"tgt": "t"}}, digest))
        for answer, reason, body_reason in [({"redeemed": False, "reason": None}, "redemption_null", None), ({"redeemed": False}, "redemption_undefined", "absent")]:
            decision = self.check("privileged-plan", {"x-sovereign-action-token": token}, body=b"{}", target="t", redeem=lambda **_: answer)
            self.assertEqual(decision.reason, reason)
            if body_reason == "absent":
                self.assertNotIn("reason", decision.body)
            else:
                self.assertIsNone(decision.body["reason"])

    def test_a_deeply_nested_unsigned_payload_is_malformed(self):
        token = "v1." + encode_base64url(("[" * 100_000 + "0" + "]" * 100_000).encode())[:4000] + ".AA"
        self.assertFalse(verify_token(token, keys=SNAPSHOT.keys, now=lambda: NOW_MS).ok)
        nested = "v1." + encode_base64url(("[" * 1100 + "0" + "]" * 1100).encode()) + ".AA"
        self.assertEqual(verify_token(nested, keys=SNAPSHOT.keys, now=lambda: NOW_MS).reason, "malformed")

    def test_lone_surrogates_digest_as_node_encodes_them(self):
        # Node's UTF-8 encoder writes a lone surrogate as U+FFFD (EF BF BD); a pair as the character.
        self.assertEqual(request_digest(method="POST", url="/", body="\ud800", target=""), request_digest(method="POST", url="/", body="\ufffd", target=""))
        self.assertEqual(request_digest(method="POST", url="/", body="\ud83d\ude00", target=""), request_digest(method="POST", url="/", body="\U0001F600", target=""))
        self.assertEqual(request_digest(method="POST", url="/", body="", target="\udfff"), request_digest(method="POST", url="/", body="", target="\ufffd"))


if __name__ == "__main__":
    unittest.main()
