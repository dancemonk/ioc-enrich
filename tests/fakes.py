"""Test doubles. Tests never touch the network."""

import json

from ioc_enrich.http import Response, check_allowed


def json_response(data, status=200, headers=None):
    return Response(status, headers or {}, json.dumps(data).encode())


def text_response(text, status=200):
    return Response(status, {}, text.encode())


class FakeHttp:
    """Answers requests from a routing table instead of the network.

    routes: {(method, url_prefix): Response | Exception | list-of-those}
    A list is consumed one item per call (the last item repeats).
    Every call is recorded in `calls` as (method, url, body, headers).
    """

    def __init__(self, routes=None):
        self.routes = dict(routes or {})
        self.calls = []

    def _answer(self, method, url, body, headers):
        check_allowed(method, url, body)   # same safety gate as the real client
        self.calls.append((method, url, body, headers or {}))
        # Longest matching prefix wins, so specific routes beat general ones.
        matches = [k for k in self.routes if k[0] == method and url.startswith(k[1])]
        if not matches:
            raise AssertionError(f"FakeHttp: no route for {method} {url}")
        key = max(matches, key=lambda k: len(k[1]))
        answer = self.routes[key]
        if isinstance(answer, list):
            answer = answer.pop(0) if len(answer) > 1 else answer[0]
        if isinstance(answer, BaseException):
            raise answer
        if callable(answer):
            return answer()
        return answer

    def get(self, url, headers=None):
        return self._answer("GET", url, None, headers)

    def post_json(self, url, payload, headers=None):
        return self._answer("POST", url, payload, headers)

    def post_form(self, url, form, headers=None):
        return self._answer("POST", url, form, headers)
