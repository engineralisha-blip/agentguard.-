import re
from pathlib import PurePosixPath

INJECTION_PATTERNS = [
    r"ignore (all |the )?(previous|prior|above) instructions",
    r"disregard (all |the )?(previous|prior) ",
    r"system prompt",
    r"you are now",
    r"<\s*script",
    r"\bdrop\s+table\b",
]

MAX_TOTAL_CHARS = 4000
SAFE_PATH = re.compile(r"^[A-Za-z0-9_\-/]+(\.[A-Za-z0-9]+)?$")
SAFE_TEXT = re.compile(r"^[A-Za-z0-9 _\-.,:@]{1,200}$")
SAFE_KEY = re.compile(r"^[a-z_]{1,40}$")
ALLOWED_FILE_EXT = {"txt", "md", "csv"}
EMAIL_FOLDERS = {"inbox", "sent", "archive"}


def _file_reader(p):
    path = p.get("path")
    if not isinstance(path, str):
        return ["path must be text"]
    v = []
    if path.startswith(("/", "\\")) or (len(path) > 1 and path[1] == ":"):
        v.append("absolute paths are not allowed")
    if ".." in PurePosixPath(path.replace("\\", "/")).parts:
        v.append("path traversal ('..') is not allowed")
    if not SAFE_PATH.match(path):
        v.append("path contains unsafe characters")
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    if ext not in ALLOWED_FILE_EXT:
        v.append("file type not allowed (txt, md, csv only)")
    return v


def _database_search(p):
    q = p.get("q")
    if not isinstance(q, str) or not SAFE_TEXT.match(q):
        return ["query must be 1-200 plain characters (letters, digits, space, - _ . , : @)"]
    return []


def _report_export(p):
    r = p.get("report")
    if not isinstance(r, str) or not SAFE_KEY.match(r):
        return ["report name must be lowercase letters or underscore only"]
    return []


def _email_viewer(p):
    if p.get("folder", "inbox") not in EMAIL_FOLDERS:
        return ["folder must be inbox, sent or archive"]
    return []


def _shell_execute(p):
    return ["shell commands are never permitted by policy"]


RULES = {
    "file_reader": _file_reader,
    "database_search": _database_search,
    "report_export": _report_export,
    "email_viewer": _email_viewer,
    "shell_execute": _shell_execute,
}


def check_parameters(tool_name, params):
    """Gateway par chalta hai. Khali list = sab theek. Warna violations ki list."""
    if not isinstance(params, dict):
        return ["parameters must be an object"]
    violations = []
    if len(str(params)) > MAX_TOTAL_CHARS:
        violations.append("parameters too large")
    for key, value in params.items():
        if not isinstance(key, str) or len(key) > 40:
            violations.append(f"invalid parameter name '{str(key)[:40]}'")
        if isinstance(value, (dict, list)):
            violations.append(f"nested value not allowed in '{key}'")
    for key, value in params.items():
        if isinstance(value, str):
            low = value.lower()
            if any(re.search(p, low) for p in INJECTION_PATTERNS):
                violations.append(f"possible prompt injection in '{key}'")
    rule = RULES.get(tool_name)
    if rule:
        violations.extend(rule(params))
    return violations
