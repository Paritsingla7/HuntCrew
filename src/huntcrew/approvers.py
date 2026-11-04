"""Approvers that reach a human outside the process. They plug into `response.execute_plan` like any `Approver`.

`http_approver` POSTs the request as JSON to a URL you run (a chat-ops bot, a ticket system, a small approval page)
and expects `{"approved": true}` back. Anything else (an error, a timeout, a malformed or missing answer, `false`)
is a denial: an approval gate must fail closed. Only http(s) URLs are accepted.
"""
from __future__ import annotations

import json
import urllib.request
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from .response import Approver
from .schema import ProposedAction

Post = Callable[[str, dict[str, Any], float], Any]


def _urllib_post(url: str, payload: dict[str, Any], timeout: float) -> Any:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:      # noqa: S310 - scheme checked in http_approver
        return json.loads(r.read().decode())


def http_approver(url: str, timeout: float = 30.0, post: Post | None = None) -> Approver:
    if urlparse(url).scheme not in {"http", "https"}:
        raise ValueError("approval URL must be http or https")
    send = post or _urllib_post

    def approve(action: ProposedAction, reason: str) -> bool:
        payload = {"action": action.type, "target": action.target, "justification": action.justification,
                   "reason": reason, "mitigation_id": action.mitigation_id}
        try:
            answer = send(url, payload, timeout)
        except Exception:                                         # noqa: BLE001 - any failure means "not approved"
            return False
        return isinstance(answer, dict) and answer.get("approved") is True

    return approve
