from agent.worker import decide_status


def test_all_ok_is_done():
    assert decide_status([{"ok": True, "blocked": False}]) == "done"


def test_blocked_tool_makes_task_blocked():
    events = [{"ok": True, "blocked": False}, {"ok": False, "blocked": True}]
    assert decide_status(events) == "blocked"


def test_tool_error_makes_task_error():
    assert decide_status([{"ok": False, "blocked": False}]) == "error"


def test_no_tool_calls_is_done():
    assert decide_status([]) == "done"
