import json
import os
import threading
import requests
from datetime import datetime, timezone, timedelta
from database import connect
from param_rules import check_parameters

CRITICAL_TOOLS = {"delete_database", "shell_execute", "user_admin", "drop_table", "export_secrets"}
PRIVILEGE_TOOLS = {"user_admin", "grant_admin", "change_role", "permission_escalation"}
# Ye tools policy mein allowed hain, lekin insaan ki approval ke bina nahi chalenge.
REVIEW_TOOLS = {"report_export"}
RATE_LIMIT_PER_MINUTE = 20

def _send_webhook(payload):
    """AGENTGUARD_WEBHOOK_URL set ho to alert bheja jata hai (Slack-compatible). Error par chup."""
    url = os.environ.get("AGENTGUARD_WEBHOOK_URL")
    if not url:
        return
    def send():
        try:
            requests.post(url, json=payload, timeout=3)
        except Exception:
            pass
    threading.Thread(target=send, daemon=True).start()

def evaluate(agent_id, agent_name, tool_name, parameters=None, source="dashboard"):
    tool_name = (tool_name or "").strip().lower()
    parameters = parameters or {}
    if not tool_name:
        return {"status": "INVALID", "reason": "Tool name is required.", "risk": 0, "alert": None}
    with connect() as db:
        agent = db.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone() if agent_id else None
        tool = db.execute("SELECT * FROM tools WHERE name=? AND active=1", (tool_name,)).fetchone()
        policy = None
        if agent and tool:
            policy = db.execute("""SELECT decision, expires_at FROM policies
                                  WHERE agent_id=? AND tool_id=?""", (agent_id, tool["id"])).fetchone()
        allowed = bool(agent and agent["status"] == "active" and policy and policy["decision"] == "allow")
        if policy and policy["expires_at"]:
            try:
                allowed = allowed and datetime.fromisoformat(policy["expires_at"]) > datetime.now()
            except ValueError:
                allowed = False
        risk = 5 if allowed else 65
        reasons = []
        if not agent:
            reasons.append("Unknown agent identity")
            risk += 20
        elif agent["status"] != "active":
            reasons.append("Agent is inactive")
            risk = 100
        if not tool:
            reasons.append("Tool is not registered or is disabled")
            risk += 15
        elif tool["sensitivity"] == "critical":
            risk += 25
            reasons.append("Critical-sensitivity tool requested")
        if tool_name in CRITICAL_TOOLS or tool_name in PRIVILEGE_TOOLS:
            risk = max(risk, 95)
            reasons.append("High-impact or privilege-related tool request")
        if any(k in str(parameters).lower() for k in ("password", "secret", "credential", "token")):
            risk += 10
            reasons.append("Sensitive parameter indicator")
        # Gateway-level parameter validation: tool ke andar nahi, yahan rukta hai.
        violations = check_parameters(tool_name, parameters)
        if violations:
            allowed = False
            risk += 30
            reasons.extend(f"Parameter rule violation: {v}" for v in violations)
        if agent_id:
            recent = db.execute("""SELECT COUNT(*) FROM invocations WHERE agent_id=?
                AND status='BLOCKED' AND created_at >= datetime('now','-10 minutes')""",
                (agent_id,)).fetchone()[0]
            if recent >= 2:
                risk = min(100, risk + 15)
                reasons.append("Repeated blocked requests in 10 minutes")
        if agent_id:
            last_minute = db.execute("""SELECT COUNT(*) FROM invocations WHERE agent_id=?
                AND created_at >= datetime('now','-60 seconds')""", (agent_id,)).fetchone()[0]
            if last_minute >= RATE_LIMIT_PER_MINUTE:
                allowed = False
                risk = max(risk, 80)
                reasons.append(f"Rate limit exceeded: more than {RATE_LIMIT_PER_MINUTE} calls in 60 seconds")
        risk = min(100, risk)
        status = "ALLOWED" if allowed and risk < 90 else "BLOCKED"
        if status == "BLOCKED" and not reasons:
            reasons.append("No active allow policy exists for this agent and tool")
        reason = "; ".join(reasons) if reasons else "Request matches the agent's active allow policy"
        if status == "ALLOWED" and tool_name in REVIEW_TOOLS:
            status = "REVIEW"
            reason = "Allowed by policy but requires human approval before execution"
        alert = None
        if status == "BLOCKED":
            severity = "critical" if risk >= 90 else ("high" if risk >= 75 else "medium")
            alert = {"severity": severity, "title": "Unauthorized tool invocation",
                     "description": f"{agent['name'] if agent else agent_name} requested {tool_name}. {reason}"}
        return {"status": status, "reason": reason, "risk": risk, "alert": alert}

def record_invocation(agent_id, agent_name, tool_name, parameters, result, source="dashboard"):
    with connect() as db:
        cur = db.execute("""INSERT INTO invocations
            (agent_id,agent_name,tool_name,parameters,status,reason,risk_score,source)
            VALUES(?,?,?,?,?,?,?,?)""",
            (agent_id, agent_name, tool_name, json.dumps(parameters or {})[:4000],
             result["status"], result["reason"], result["risk"], source))
        invocation_id = cur.lastrowid
        if agent_id:
            db.execute("UPDATE agents SET risk_score=? WHERE id=?", (result["risk"], agent_id))
        if result.get("alert"):
            a = result["alert"]
            db.execute("""INSERT INTO alerts(invocation_id,agent_id,severity,title,description)
                VALUES(?,?,?,?,?)""", (invocation_id, agent_id, a["severity"], a["title"], a["description"]))
            db.execute("INSERT INTO notifications(title,message,severity) VALUES(?,?,?)",
                       (a["title"], a["description"], a["severity"]))
            _send_webhook({"text": f"[AgentGuard {a['severity'].upper()}] {a['title']}: {a['description']}"})
        return invocation_id
