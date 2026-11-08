import functools
from typing import Optional

from .client import AgentGuard
from .errors import ToolBlockedError


def guard_tool(guard: AgentGuard, tool_name: Optional[str] = None):
    """
    Kisi bhi function ke upar lagayein. Call se pehle gateway check hoga.

        guard = AgentGuard(api_key="...")

        @guard_tool(guard, "file_reader")
        def read_file(path):
            ...
    """
    def decorator(fn):
        name = tool_name or fn.__name__

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            params = dict(kwargs)
            if args:
                params["_args"] = list(args)
            decision = guard.check(name, params)
            if not decision.allowed:
                raise ToolBlockedError(name, decision)
            return fn(*args, **kwargs)

        wrapper.guard_tool_name = name
        return wrapper

    return decorator
