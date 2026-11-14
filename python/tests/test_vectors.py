"""Runs the language-neutral conformance vectors in ../../vectors, unchanged, as test/vectors.test.js does."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sovereign_auth import SnapshotError, create_request_guard, parse_snapshot, resolve_member

VECTORS = Path(__file__).resolve().parents[2] / "vectors"


def load(name: str):
    return json.loads((VECTORS / name).read_text("utf-8"))


GUARDS = load("request-guards.json")
SNAPSHOTS = load("snapshot.json")


def apply_changes(document, changes):
    result = copy.deepcopy(document)
    for change in changes:
        if not change["path"]:
            result = copy.deepcopy(change["value"])
            continue
        parent = result
        for key in change["path"][:-1]:
            parent = parent[key]
        key = change["path"][-1]
        if change.get("remove"):
            del parent[key]
        else:
            parent[key] = copy.deepcopy(change["value"])
    return result


class RequestGuardVectors(unittest.TestCase):
    def test_every_case(self):
        for group in GUARDS["groups"]:
            config = group["guard"]
            options = {"isolate": config["isolate"]} if "isolate" in config else {}
            if "contentTypes" in config:
                options["content_types"] = config["contentTypes"]
            guard = create_request_guard(config["origin"], **options)
            for case in group["cases"]:
                with self.subTest(group=group["name"], case=case["name"]):
                    request = case["request"]
                    decision = guard.check(request.get("method", "GET"), request.get("headers", {}))
                    self.assertEqual(decision.allowed, case["expect"]["allowed"])
                    if not case["expect"]["allowed"]:
                        self.assertEqual(decision.reason, case["expect"]["reason"])
                        self.assertEqual(decision.status, 403)

    def test_the_vectors_cover_every_refusal_reason_and_both_outcomes(self):
        cases = [case for group in GUARDS["groups"] for case in group["cases"]]
        reasons = sorted({case["expect"]["reason"] for case in cases if case["expect"].get("reason")})
        self.assertEqual(reasons, ["content_type", "fetch_metadata_malformed", "fetch_metadata_missing", "fetch_site", "not_same_origin", "origin_mismatch", "origin_missing"])
        self.assertTrue(any(case["expect"]["allowed"] for case in cases))


class SnapshotVectors(unittest.TestCase):
    def test_format(self):
        for case in SNAPSHOTS["format"]:
            with self.subTest(case=case["name"]):
                data = apply_changes(SNAPSHOTS["snapshot"], case["changes"])
                if case["expect"]["ok"]:
                    self.assertEqual(parse_snapshot(data).generation, data["generation"])
                else:
                    with self.assertRaises(SnapshotError) as caught:
                        parse_snapshot(data)
                    self.assertEqual(caught.exception.reason, case["expect"]["reason"])

    def test_member_resolution(self):
        snapshot = parse_snapshot(SNAPSHOTS["snapshot"])
        for case in SNAPSHOTS["members"]:
            with self.subTest(case=case["name"]):
                result = resolve_member(snapshot, case["headers"], app_id=case["appId"])
                if case["expect"].get("member_id"):
                    self.assertIsNotNone(result.member)
                    self.assertEqual(result.member.member_id, case["expect"]["member_id"])
                else:
                    self.assertIsNone(result.member)
                    self.assertEqual(result.reason, case["expect"]["reason"])


if __name__ == "__main__":
    unittest.main()
