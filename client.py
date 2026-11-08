import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import requests

from .errors import AgentGuardError


@dataclass
class Decision:
    allowed: bool
    decision: str
    risk: int = 0
    reasons: List[str] = field(default_factory=list)
    request_id: Optional[int] = None
    approval_id: Optional[int] = None
    raw: Dict[str, Any] = field(default_factory=dict)


class AgentGuard:
    """
    AgentGuard gateway ka client.

    fail_open=False (default): gateway down ho to tool call block hogi (secure default).
    fail_open=True: gateway down ho to call allow hogi (sirf testing ke liye).
    """

    def __init__(self, api_key, base_url="http://127.0.0.1:5000",
                 timeout=5.0, fail_open=False):
        if not api_key:
            raise AgentGuardError("api_key is required")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.fail_open = fail_open
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "agentguard-sdk/0.1.0",
        })

    def check(self, tool_name: str, parameters: Optional[Dict[str, Any]] = None) -> Decision:
        """Tool call se pehle gateway se permission maangta hai."""
        safe_params = json.loads(json.dumps(parameters or {}, default=str))
        payload = {"tool_name": tool_name, "parameters": safe_params}
        url = f"{self.base_url}/api/v1/tool-invocations"

        try:
            resp = self._session.post(url, json=payload, timeout=self.timeout)
        except requests.RequestException as exc:
            if self.fail_open:
                return Decision(True, "ALLOW", 0, ["Gateway unreachable (fail-open)"])
            raise AgentGuardError(f"Gateway unreachable: {exc}") from exc

        if resp.status_code == 401:
            raise AgentGuardError("Invalid or inactive agent API key")
        if resp.status_code == 400:
            raise AgentGuardError(f"Bad request: {resp.text}")
        if not resp.ok:
            raise AgentGuardError(f"Gateway error {resp.status_code}: {resp.text}")

        data = resp.json()
        decision_value = data.get("decision")
        if not decision_value:
            decision_value = "ALLOW" if data.get("status") == "ALLOWED" else "BLOCK"

        reasons = data.get("reasons")
        if reasons is None:
            reasons = [r.strip() for r in str(data.get("reason", "")).split(";") if r.strip()]

        return Decision(
            allowed=(decision_value == "ALLOW"),
            decision=decision_value,
            risk=int(data.get("risk", 0)),
            reasons=reasons,
            request_id=data.get("request_id"),
            approval_id=data.get("approval_id"),
            raw=data,
        )

    def wait_for_approval(self, approval_id, timeout=120.0, poll_interval=2.0) -> str:
        """REVIEW wali request par insaan ka faisla aane tak wait karta hai.
        Return: approved | denied | timeout | error"""
        if not approval_id:
            return "error"
        url = f"{self.base_url}/api/v1/approvals/{approval_id}"
        deadline = time.time() + timeout
        while True:
            try:
                resp = self._session.get(url, timeout=self.timeout)
            except requests.RequestException as exc:
                raise AgentGuardError(f"Gateway unreachable while waiting for approval: {exc}") from exc
            if not resp.ok:
                raise AgentGuardError(f"Approval check failed: {resp.status_code}")
            status = resp.json().get("status", "pending")
            if status != "pending":
                return status
            if time.time() >= deadline:
                return "timeout"
            time.sleep(poll_interval)
