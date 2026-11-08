import json
from typing import Any, Callable, Dict

from .client import AgentGuard


def guarded_dispatch(guard: AgentGuard,
                     tool_call_name: str,
                     arguments: Any,
                     registry: Dict[str, Callable[..., Any]],
                     approval_timeout: float = 120.0) -> Dict[str, Any]:
    """
    OpenAI / Groq style function calling ke liye adapter.

    ALLOW  -> tool chalega.
    REVIEW -> insaan ki approval ka intezaar hoga; approve hone par hi tool chalega.
    BLOCK  -> tool nahi chalega.

    Return: {"ok": True, "result": ...} ya {"ok": False, "error": "...", "blocked": bool}
    """
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments or "{}")
        except json.JSONDecodeError:
            return {"ok": False, "error": "Invalid JSON arguments"}

    if tool_call_name not in registry:
        return {"ok": False, "error": f"Unknown tool '{tool_call_name}'"}

    decision = guard.check(tool_call_name, arguments)

    if decision.decision == "REVIEW":
        outcome = guard.wait_for_approval(decision.approval_id, timeout=approval_timeout)
        if outcome != "approved":
            return {"ok": False, "blocked": True,
                    "error": f"Human approval {outcome}: '{tool_call_name}' run nahi hua"}
    elif not decision.allowed:
        return {
            "ok": False,
            "blocked": True,
            "error": f"Blocked by AgentGuard: {'; '.join(decision.reasons)}",
        }

    try:
        result = registry[tool_call_name](**arguments)
        return {"ok": True, "result": result}
    except TypeError as exc:
        return {"ok": False, "error": f"Bad arguments: {exc}"}
    except Exception as exc:
        return {"ok": False, "error": f"Tool error: {exc}"}
