import csv, io, secrets, hashlib, json, threading, time
from functools import wraps
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, make_response, Response, stream_with_context
from werkzeug.security import check_password_hash, generate_password_hash
import os
from config import Config, production_problems
_missing = production_problems(os.environ)
if _missing:
    raise SystemExit('Production mein ye environment variables zaroori hain: ' + ', '.join(_missing))
from database import init_db, connect
from security_engine import evaluate, record_invocation

app = Flask(__name__)
app.config.from_object(Config)
with app.app_context():
    init_db()

def _chain_hash(prev_hash, log_id, username, action, details, created_at):
    payload = json.dumps([prev_hash, log_id, username, action, details, created_at])
    return hashlib.sha256(payload.encode()).hexdigest()

def audit(action, details):
    username = session.get("username", "API")
    stored = str(details)[:2000]
    with connect() as db:
        cur = db.execute("INSERT INTO audit_logs(user_id,username,action,details) VALUES(?,?,?,?)",
                         (session.get("user_id"), username, action, stored))
        log_id = cur.lastrowid
        created = db.execute("SELECT created_at FROM audit_logs WHERE id=?", (log_id,)).fetchone()["created_at"]
        last = db.execute("SELECT hash FROM audit_chain ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = last["hash"] if last else "GENESIS"
        digest = _chain_hash(prev_hash, log_id, username, action, stored, created)
        db.execute("INSERT INTO audit_chain(log_id,prev_hash,hash) VALUES(?,?,?)", (log_id, prev_hash, digest))

def verify_audit_chain():
    with connect() as db:
        chain = db.execute("""SELECT c.log_id,c.prev_hash,c.hash,l.username,l.action,l.details,l.created_at
            FROM audit_chain c JOIN audit_logs l ON l.id=c.log_id ORDER BY c.id""").fetchall()
    prev = "GENESIS"
    for r in chain:
        expected = _chain_hash(prev, r["log_id"], r["username"], r["action"], r["details"], r["created_at"])
        if r["prev_hash"] != prev or expected != r["hash"]:
            return {"ok": False, "broken_at_log_id": r["log_id"], "checked": len(chain)}
        prev = r["hash"]
    return {"ok": True, "checked": len(chain)}

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            if request.path.startswith("/api/"):
                return jsonify({"error":"Authentication required"}), 401
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped

def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if session.get("role") != "admin":
            return jsonify({"error":"Administrator permission required"}), 403
        return fn(*args, **kwargs)
    return wrapped

def rows(query, params=()):
    with connect() as db:
        return [dict(r) for r in db.execute(query, params).fetchall()]

def one(query, params=()):
    with connect() as db:
        r = db.execute(query, params).fetchone()
        return dict(r) if r else None

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    return response

LOGIN_LIMIT = 5
LOGIN_WINDOW = 900  # 15 minute
LOGIN_ATTEMPTS = {}
_attempts_lock = threading.Lock()

def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]

app.jinja_env.globals["csrf_token"] = csrf_token

@app.before_request
def csrf_protect():
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return None
    # Bearer token wale agents cookie use nahi karte, is liye CSRF lagu nahi hota.
    if request.path.startswith("/api/v1/"):
        return None
    sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    if not expected or not sent or not secrets.compare_digest(sent, expected):
        if request.path.startswith("/api/"):
            return jsonify({"error": "CSRF token missing or invalid"}), 403
        return "CSRF token missing or invalid", 403
    return None

WRITE_ROLE_RULES = [
    ("/api/users", {"admin"}),
    ("/api/agents", {"admin"}),
    ("/api/policies", {"admin"}),
    ("/api/invoke", {"analyst", "admin"}),
    ("/api/approvals/", {"analyst", "admin"}),
    ("/api/alerts/", {"analyst", "admin"}),
]

@app.before_request
def role_protect():
    """Likhne wale (POST/PUT/DELETE) actions ke liye role check. Viewer sirf dekh sakta hai."""
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return None
    if request.path.startswith("/api/v1/") or not session.get("user_id"):
        return None
    for prefix, roles in WRITE_ROLE_RULES:
        if request.path.startswith(prefix):
            if session.get("role") not in roles:
                audit("permission_denied", f"{session.get('username')} {request.method} {request.path}")
                return jsonify({"error": "Aap ke role ko ye action ki ijazat nahi"}), 403
            return None
    return None

def _login_key(username):
    return f"{request.remote_addr}|{username.lower()}"

def _is_locked(key):
    now = time.time()
    with _attempts_lock:
        recent = [t for t in LOGIN_ATTEMPTS.get(key, []) if now - t < LOGIN_WINDOW]
        LOGIN_ATTEMPTS[key] = recent
        return len(recent) >= LOGIN_LIMIT

def _record_failure(key):
    with _attempts_lock:
        LOGIN_ATTEMPTS.setdefault(key, []).append(time.time())

def _clear_failures(key):
    with _attempts_lock:
        LOGIN_ATTEMPTS.pop(key, None)

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        key = _login_key(username)
        if _is_locked(key):
            flash("Bahut zyada galat koshishein. 15 minute baad dobara try karein.", "error")
            return render_template("login.html"), 429
        user = one("SELECT * FROM users WHERE username=? AND active=1", (username,))
        if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            _clear_failures(key)
            session.clear()
            session.update(user_id=user["id"], username=user["username"], role=user["role"])
            audit("login", "Successful login")
            return redirect(url_for("dashboard"))
        _record_failure(key)
        flash("Invalid username or password.", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    if session.get("user_id"): audit("logout", "User logged out")
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    return render_template("index.html")

@app.route("/agents")
@login_required
def agents_page(): return render_template("agents.html")

@app.route("/policies")
@login_required
def policies_page(): return render_template("policies.html")

@app.route("/alerts")
@login_required
def alerts_page(): return render_template("alerts.html")

@app.route("/reports")
@login_required
def reports_page(): return render_template("reports.html")

@app.route("/users")
@login_required
def users_page(): return render_template("users.html")

@app.route("/playground")
@login_required
def playground_page(): return render_template("playground.html")

@app.route("/api/overview")
@login_required
def overview():
    with connect() as db:
        stats = {
            "total": db.execute("SELECT COUNT(*) FROM invocations").fetchone()[0],
            "allowed": db.execute("SELECT COUNT(*) FROM invocations WHERE status='ALLOWED'").fetchone()[0],
            "blocked": db.execute("SELECT COUNT(*) FROM invocations WHERE status='BLOCKED'").fetchone()[0],
            "agents": db.execute("SELECT COUNT(*) FROM agents").fetchone()[0],
            "active_agents": db.execute("SELECT COUNT(*) FROM agents WHERE status='active'").fetchone()[0],
            "open_alerts": db.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0],
            "high_risk": db.execute("SELECT COUNT(*) FROM agents WHERE risk_score>=75").fetchone()[0]
        }
    return jsonify(stats)

@app.route("/api/invocations")
@login_required
def invocations():
    status = request.args.get("status")
    q = "SELECT * FROM invocations"
    params = ()
    if status in ("ALLOWED","BLOCKED"):
        q += " WHERE status=?"; params=(status,)
    q += " ORDER BY id DESC LIMIT 250"
    return jsonify(rows(q, params))

@app.route("/api/invoke", methods=["POST"])
@login_required
def invoke():
    data = request.get_json(silent=True) or request.form
    agent_id = data.get("agent_id")
    try: agent_id = int(agent_id) if agent_id else None
    except (ValueError,TypeError): agent_id = None
    agent = one("SELECT * FROM agents WHERE id=?", (agent_id,)) if agent_id else None
    agent_name = agent["name"] if agent else str(data.get("agent_name","Unknown Agent"))[:80]
    tool_name = str(data.get("tool_name","")).strip().lower()[:100]
    parameters = data.get("parameters", {})
    if isinstance(parameters, str):
        try: parameters=json.loads(parameters)
        except Exception: parameters={"raw":parameters[:500]}
    result = evaluate(agent_id, agent_name, tool_name, parameters)
    if result["status"] == "INVALID": return jsonify(result), 400
    inv_id = record_invocation(agent_id, agent_name, tool_name, parameters, result)
    if result["status"] == "REVIEW" and agent_id:
        create_approval(inv_id, agent_id, agent_name, tool_name, parameters)
    audit("tool_invocation", f"{agent_name} -> {tool_name}: {result['status']}")
    # Tools are deliberately not executed by this educational security gateway.
    return jsonify(result)

@app.route("/api/agents", methods=["GET","POST"])
@login_required
def agents_api():
    if request.method == "GET":
        return jsonify(rows("SELECT id,name,description,status,risk_score,created_at FROM agents ORDER BY id DESC"))
    data=request.get_json(silent=True) or {}
    name=str(data.get("name","")).strip()[:100]
    if not name: return jsonify({"error":"Agent name is required"}),400
    with connect() as db:
        cur=db.execute("INSERT INTO agents(name,description) VALUES(?,?)",(name,str(data.get("description",""))[:500]))
        aid=cur.lastrowid
        # New agent receives no tools by default: least privilege.
    audit("agent_registered", name)
    return jsonify({"id":aid,"name":name,"message":"Agent registered with no tool permissions by default."}),201

@app.route("/api/agents/<int:agent_id>/status", methods=["POST"])
@login_required
def agent_status(agent_id):
    data=request.get_json(silent=True) or {}
    status=data.get("status")
    if status not in ("active","inactive"): return jsonify({"error":"Invalid status"}),400
    with connect() as db: db.execute("UPDATE agents SET status=? WHERE id=?",(status,agent_id))
    audit("agent_status_changed",f"{agent_id}: {status}")
    return jsonify({"success":True})

@app.route("/api/tools")
@login_required
def tools_api():
    return jsonify(rows("SELECT * FROM tools WHERE active=1 ORDER BY name"))

@app.route("/api/policies", methods=["GET","POST","DELETE"])
@login_required
def policies_api():
    if request.method=="GET":
        return jsonify(rows("""SELECT p.id,p.agent_id,a.name AS agent_name,p.tool_id,t.name AS tool_name,
            p.decision,p.expires_at FROM policies p JOIN agents a ON a.id=p.agent_id
            JOIN tools t ON t.id=p.tool_id ORDER BY a.name,t.name"""))
    data=request.get_json(silent=True) or {}
    if request.method=="DELETE":
        pid=data.get("id")
        with connect() as db: db.execute("DELETE FROM policies WHERE id=?",(pid,))
        audit("policy_removed",str(pid)); return jsonify({"success":True})
    try: aid=int(data["agent_id"]); tid=int(data["tool_id"])
    except Exception: return jsonify({"error":"Agent and tool are required"}),400
    decision=data.get("decision","allow")
    if decision not in ("allow","deny"): return jsonify({"error":"Decision must be allow or deny"}),400
    with connect() as db:
        db.execute("""INSERT INTO policies(agent_id,tool_id,decision,expires_at) VALUES(?,?,?,?)
          ON CONFLICT(agent_id,tool_id) DO UPDATE SET decision=excluded.decision,expires_at=excluded.expires_at""",
          (aid,tid,decision,data.get("expires_at") or None))
    audit("policy_updated",f"agent={aid}, tool={tid}, decision={decision}")
    return jsonify({"success":True})

@app.route("/api/alerts")
@login_required
def alerts_api(): return jsonify(rows("SELECT * FROM alerts ORDER BY id DESC LIMIT 250"))

@app.route("/api/alerts/<int:alert_id>/resolve",methods=["POST"])
@login_required
def resolve_alert(alert_id):
    with connect() as db: db.execute("UPDATE alerts SET status='resolved',resolved_at=CURRENT_TIMESTAMP WHERE id=?",(alert_id,))
    audit("alert_resolved",str(alert_id)); return jsonify({"success":True})

def _state_marker():
    with connect() as db:
        row = db.execute("""SELECT (SELECT COUNT(*) FROM invocations), (SELECT COUNT(*) FROM alerts),
            (SELECT COUNT(*) FROM approvals), (SELECT COUNT(*) FROM approvals WHERE status='pending'),
            (SELECT COUNT(*) FROM alerts WHERE status='open')""").fetchone()
    return ":".join(str(x) for x in row)

@app.route("/api/stream")
@login_required
def stream():
    """Server-Sent Events: jab bhi invocations, alerts ya approvals badlein, browser ko 'update' event jata hai."""
    def gen():
        last = None
        yield "event: ready\ndata: connected\n\n"
        while True:
            marker = _state_marker()
            if marker != last:
                last = marker
                yield f"event: update\ndata: {marker}\n\n"
            else:
                yield ": keepalive\n\n"
            time.sleep(2)
    return Response(stream_with_context(gen()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.route("/metrics")
def metrics():
    """Prometheus format. Login ya AGENTGUARD_METRICS_TOKEN (header X-Metrics-Token) chahiye."""
    token = os.environ.get("AGENTGUARD_METRICS_TOKEN", "")
    allowed = (bool(token) and request.headers.get("X-Metrics-Token") == token) or bool(session.get("user_id"))
    if not allowed:
        return jsonify({"error": "Login ya X-Metrics-Token zaroori hai"}), 401
    with connect() as db:
        by_status = db.execute("SELECT status, COUNT(*) FROM invocations GROUP BY status").fetchall()
        pending = db.execute("SELECT COUNT(*) FROM approvals WHERE status='pending'").fetchone()[0]
        open_alerts = db.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0]
        agents = db.execute("SELECT COUNT(*) FROM agents").fetchone()[0]
    lines = ["# HELP agentguard_invocations_total Tool invocations by decision status",
             "# TYPE agentguard_invocations_total counter"]
    for status, count in by_status:
        lines.append(f'agentguard_invocations_total{{status="{status}"}} {count}')
    lines += ["# HELP agentguard_approvals_pending Approval requests waiting for a human",
              "# TYPE agentguard_approvals_pending gauge",
              f"agentguard_approvals_pending {pending}",
              "# HELP agentguard_alerts_open Open security alerts",
              "# TYPE agentguard_alerts_open gauge",
              f"agentguard_alerts_open {open_alerts}",
              "# HELP agentguard_agents_total Registered agents",
              "# TYPE agentguard_agents_total gauge",
              f"agentguard_agents_total {agents}"]
    return Response("\n".join(lines) + "\n", mimetype="text/plain; version=0.0.4")

@app.route("/api/audit/verify")
@login_required
def audit_verify(): return jsonify(verify_audit_chain())

@app.route("/api/audit")
@login_required
def audit_api(): return jsonify(rows("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 300"))

@app.route("/api/users",methods=["GET","POST"])
@login_required
@admin_required
def users_api():
    if request.method=="GET": return jsonify(rows("SELECT id,username,role,active,created_at FROM users ORDER BY id"))
    data=request.get_json(silent=True) or {}
    username=str(data.get("username","")).strip()[:80]
    password=str(data.get("password",""))
    role=data.get("role","analyst")
    if not username or len(password)<10 or role not in ("admin","analyst","viewer"):
        return jsonify({"error":"Username, 10+ character password and valid role are required"}),400
    try:
        with connect() as db:
            db.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                       (username,generate_password_hash(password),role))
    except Exception: return jsonify({"error":"Username already exists"}),409
    audit("user_created",username); return jsonify({"success":True}),201

@app.route("/api/notifications")
@login_required
def notifications_api(): return jsonify(rows("SELECT * FROM notifications ORDER BY id DESC LIMIT 100"))

@app.route("/api/reports.pdf")
@login_required
def reports_pdf():
    from io import BytesIO
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer
    with connect() as db:
        total = db.execute("SELECT COUNT(*) FROM invocations").fetchone()[0]
        allowed = db.execute("SELECT COUNT(*) FROM invocations WHERE status='ALLOWED'").fetchone()[0]
        review = db.execute("SELECT COUNT(*) FROM invocations WHERE status='REVIEW'").fetchone()[0]
        blocked = db.execute("SELECT COUNT(*) FROM invocations WHERE status='BLOCKED'").fetchone()[0]
        recent = db.execute("SELECT id,agent_name,tool_name,status,risk_score,created_at FROM invocations ORDER BY id DESC LIMIT 50").fetchall()
    rate = round(blocked / total * 100) if total else 0
    styles = getSampleStyleSheet()
    story = [
        Paragraph("AgentGuard Security Report", styles["Title"]),
        Paragraph("Generated (UTC): " + time.strftime("%Y-%m-%d %H:%M", time.gmtime()), styles["Normal"]),
        Spacer(1, 12),
        Paragraph(f"Total: {total} | Allowed: {allowed} | Review: {review} | Blocked: {blocked} | Block rate: {rate}%", styles["Normal"]),
        Spacer(1, 14),
    ]
    data = [["ID", "Agent", "Tool", "Decision", "Risk", "Time"]]
    for r in recent:
        data.append([str(r["id"]), str(r["agent_name"]), str(r["tool_name"]),
                     str(r["status"]), str(r["risk_score"]), str(r["created_at"])])
    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b2a3d")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#00f0ff")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#17324d")),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eef6fb")]),
    ]))
    story.append(table)
    buf = BytesIO()
    SimpleDocTemplate(buf, pagesize=A4, title="AgentGuard Security Report").build(story)
    response = make_response(buf.getvalue())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = "attachment; filename=agentguard-security-report.pdf"
    return response

@app.route("/api/reports.csv")
@login_required
def reports_csv():
    output=io.StringIO(); writer=csv.writer(output)
    writer.writerow(["id","agent","tool","decision","risk_score","reason","source","created_at"])
    for r in rows("SELECT id,agent_name,tool_name,status,risk_score,reason,source,created_at FROM invocations ORDER BY id DESC"):
        writer.writerow([r[k] for k in ("id","agent_name","tool_name","status","risk_score","reason","source","created_at")])
    response=make_response(output.getvalue())
    response.headers["Content-Type"]="text/csv"
    response.headers["Content-Disposition"]="attachment; filename=agentguard-security-report.csv"
    return response

def api_agent_auth():
    auth=request.headers.get("Authorization","")
    if not auth.startswith("Bearer "): return None
    raw=auth[7:].strip()
    digest=hashlib.sha256(raw.encode()).hexdigest()
    return one("SELECT * FROM agents WHERE api_key_hash=? AND status='active'",(digest,))

@app.route("/api/v1/tool-invocations", methods=["POST"])
def external_invoke():
    agent=api_agent_auth()
    if not agent: return jsonify({"error":"Valid agent API bearer token required"}),401
    data=request.get_json(silent=True) or {}
    tool_name=str(data.get("tool_name","")).strip().lower()[:100]
    parameters=data.get("parameters",{})
    result=evaluate(agent["id"],agent["name"],tool_name,parameters,source="external_api")
    if result["status"]=="INVALID": return jsonify(result),400
    invocation_id=record_invocation(agent["id"],agent["name"],tool_name,parameters,result,source="external_api")
    approval_id=None
    if result["status"]=="REVIEW":
        approval_id=create_approval(invocation_id,agent["id"],agent["name"],tool_name,parameters)
    decision={"ALLOWED":"ALLOW","REVIEW":"REVIEW"}.get(result["status"],"BLOCK")
    return jsonify({
        "decision": decision,
        "status": result["status"],
        "risk": result["risk"],
        "reasons": [r.strip() for r in result["reason"].split(";") if r.strip()],
        "request_id": invocation_id,
        "approval_id": approval_id,
        "alert": result["alert"],
    }),200

def create_approval(invocation_id, agent_id, agent_name, tool_name, parameters):
    with connect() as db:
        cur=db.execute("""INSERT INTO approvals(invocation_id,agent_id,agent_name,tool_name,parameters,status)
            VALUES(?,?,?,?,?,'pending')""",(invocation_id,agent_id,agent_name,tool_name,json.dumps(parameters or {})[:4000]))
        return cur.lastrowid

@app.route("/approvals")
@login_required
def approvals_page(): return render_template("approvals.html")

@app.route("/api/approvals")
@login_required
def approvals_api(): return jsonify(rows("SELECT * FROM approvals ORDER BY id DESC LIMIT 250"))

@app.route("/api/approvals/<int:approval_id>/decide", methods=["POST"])
@login_required
def decide_approval(approval_id):
    data=request.get_json(silent=True) or {}
    choice=data.get("decision")
    if choice not in ("approve","deny"): return jsonify({"error":"decision must be approve or deny"}),400
    new_status="approved" if choice=="approve" else "denied"
    with connect() as db:
        cur=db.execute("UPDATE approvals SET status=?, decided_by=?, decided_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending'",
                       (new_status, session.get("username"), approval_id))
        if cur.rowcount==0: return jsonify({"error":"Approval not found or already decided"}),409
    audit("approval_"+new_status, str(approval_id))
    return jsonify({"success":True,"status":new_status})

@app.route("/api/v1/approvals/<int:approval_id>")
def agent_approval_status(approval_id):
    agent=api_agent_auth()
    if not agent: return jsonify({"error":"Valid agent API bearer token required"}),401
    row=one("SELECT id,agent_id,tool_name,status FROM approvals WHERE id=?",(approval_id,))
    if not row or row["agent_id"]!=agent["id"]: return jsonify({"error":"Not found"}),404
    return jsonify({"approval_id":row["id"],"status":row["status"],"tool_name":row["tool_name"]})

@app.route("/api/agents/<int:agent_id>/rotate-key",methods=["POST"])
@login_required
@admin_required
def rotate_key(agent_id):
    raw=secrets.token_urlsafe(32)
    digest=hashlib.sha256(raw.encode()).hexdigest()
    with connect() as db: db.execute("UPDATE agents SET api_key_hash=? WHERE id=?",(digest,agent_id))
    audit("agent_api_key_rotated",str(agent_id))
    return jsonify({"api_key":raw,"warning":"Copy this key now. It is shown only once."})

if __name__=="__main__":
    app.run(host="127.0.0.1",port=5000,debug=False)
