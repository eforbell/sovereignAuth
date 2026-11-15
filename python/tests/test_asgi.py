"""The ASGI guard middleware (test/guards.test.js's adapter cases), driven with plain ASGI messages so no
framework is needed."""

from __future__ import annotations

import asyncio
import json
import unittest

from sovereign_auth import create_request_guard
from sovereign_auth.asgi import GuardMiddleware, headers_from_scope

ORIGIN = "https://pulse.example-tailnet.ts.net"
SIBLING_SCRIPT = [(b"sec-fetch-site", b"same-site"), (b"sec-fetch-mode", b"no-cors"), (b"sec-fetch-dest", b"script")]
OWN_PAGE = [(b"sec-fetch-site", b"same-origin")]


def scope(method="GET", headers=(), path="/api/accounts", query=b""):
    return {"type": "http", "method": method, "path": path, "query_string": query, "headers": list(headers)}


class Recorder:
    def __init__(self, vary=None):
        self.calls = 0
        self.vary = vary

    async def __call__(self, scope, receive, send):
        self.calls += 1
        headers = [(b"content-type", b"text/plain")]
        if self.vary:
            headers.append((b"Vary", self.vary))
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        await send({"type": "http.response.body", "body": b"ok"})


def run(middleware, request):
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(middleware(request, receive, send))
    start = next(message for message in sent if message["type"] == "http.response.start")
    body = b"".join(message.get("body", b"") for message in sent if message["type"] == "http.response.body")
    headers = {}
    for name, value in start["headers"]:
        headers.setdefault(name.decode("latin-1").lower(), []).append(value.decode("latin-1"))
    return start["status"], headers, body


class GuardMiddlewareTests(unittest.TestCase):
    def setUp(self):
        self.logged = []

    def middleware(self, app, mode="enforce", **guard_options):
        return GuardMiddleware(app, guard=create_request_guard(ORIGIN, **guard_options), mode=mode, log=self.logged.append)

    def test_enforce_answers_403_with_the_refusal_body_and_stops(self):
        app = Recorder()
        status, headers, body = run(self.middleware(app), scope(headers=SIBLING_SCRIPT, query=b"code=secret"))
        self.assertEqual(status, 403)
        self.assertEqual(app.calls, 0)
        self.assertEqual(json.loads(body)["reason"], "not_same_origin")
        self.assertEqual(json.loads(body)["error"], "request_refused")
        self.assertEqual(headers["cache-control"], ["no-store"])
        self.assertEqual(headers["vary"], ["Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest"])
        self.assertEqual(len(self.logged), 1)
        self.assertIn("refused GET /api/accounts: not_same_origin", self.logged[0])
        self.assertNotIn("secret", self.logged[0], "the query never reaches the log")

    def test_report_logs_and_lets_the_request_through(self):
        app = Recorder()
        status, headers, _ = run(self.middleware(app, mode="report"), scope(headers=SIBLING_SCRIPT))
        self.assertEqual((status, app.calls), (200, 1))
        self.assertIn("would refuse", self.logged[0])
        self.assertEqual(headers["vary"], ["Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest"])

    def test_off_passes_everything_and_adds_nothing(self):
        app = Recorder()
        status, headers, _ = run(self.middleware(app, mode="off"), scope(headers=SIBLING_SCRIPT))
        self.assertEqual((status, app.calls, self.logged), (200, 1, []))
        self.assertNotIn("vary", headers)

    def test_an_isolating_guard_appends_to_the_apps_vary(self):
        status, headers, _ = run(self.middleware(Recorder(vary=b"Accept-Encoding, sec-fetch-site")), scope(headers=OWN_PAGE))
        self.assertEqual(status, 200)
        self.assertEqual(headers["vary"], ["Accept-Encoding, sec-fetch-site, Sec-Fetch-Mode, Sec-Fetch-Dest"])
        _, star, _ = run(self.middleware(Recorder(vary=b"*")), scope(headers=OWN_PAGE))
        self.assertEqual(star["vary"], ["*"])

    def test_a_shared_hostname_guard_checks_mutations_only_and_adds_no_vary(self):
        app = Recorder()
        status, headers, _ = run(self.middleware(app, isolate=False), scope(headers=SIBLING_SCRIPT))
        self.assertEqual((status, app.calls), (200, 1))
        self.assertNotIn("vary", headers)
        form = [(b"origin", ORIGIN.encode()), (b"content-type", b"text/plain")]
        status, _, body = run(self.middleware(app, isolate=False), scope("POST", form))
        self.assertEqual((status, json.loads(body)["reason"]), (403, "content_type"))

    def test_a_same_origin_json_write_reaches_the_app(self):
        app = Recorder()
        write = OWN_PAGE + [(b"origin", ORIGIN.encode()), (b"content-type", b"application/json; charset=utf-8")]
        status, _, _ = run(self.middleware(app), scope("POST", write))
        self.assertEqual((status, app.calls), (200, 1))

    def test_other_scopes_pass_untouched(self):
        calls = []

        async def app(scope, receive, send):
            calls.append(scope["type"])

        asyncio.run(self.middleware(app)({"type": "lifespan"}, None, None))
        self.assertEqual(calls, ["lifespan"])

    def test_a_mode_must_be_named(self):
        with self.assertRaises(ValueError):
            self.middleware(Recorder(), mode="on")

    def test_headers_are_lower_case_and_repeated_ones_become_lists(self):
        headers = headers_from_scope(scope(headers=[(b"X-Sovereign-Login", b"a@example.com"), (b"x-sovereign-login", b"b@example.com"), (b"Origin", b"https://x")]))
        self.assertEqual(headers, {"x-sovereign-login": ["a@example.com", "b@example.com"], "origin": "https://x"})


if __name__ == "__main__":
    unittest.main()
