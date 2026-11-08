class AgentGuardError(Exception):
    """Gateway se related error (network, auth, bad request)."""


class ToolBlockedError(Exception):
    """Gateway ne tool call ko block kiya."""

    def __init__(self, tool_name, decision):
        self.tool_name = tool_name
        self.decision = decision
        reasons = "; ".join(decision.reasons) or "No reason given"
        super().__init__(f"Tool '{tool_name}' blocked by AgentGuard: {reasons}")
