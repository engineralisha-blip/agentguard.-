# AgentGuard — Unauthorized Tool Invocation by Enterprise AI Agents

A full-stack educational security gateway built with Python Flask, SQLite, HTML/CSS and JavaScript. It demonstrates agent registration, tool policy enforcement, unauthorized invocation blocking, risk scoring, alerts, audit logging and an external-agent API.

## Windows setup

1. Extract this ZIP.
2. Open the `AgentGuard_FullStack` folder in VS Code.
3. Open Terminal (PowerShell):

```powershell
py -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

4. Open http://127.0.0.1:5000

First login:
- Username: `admin`
- Password: `ChangeMe123!`

Change the default password and set a strong `AGENTGUARD_SECRET_KEY` before any deployment.

## Included features

1. AI agent registration and management
2. Tool invocation monitoring
3. Authorized vs unauthorized detection
4. Per-agent tool permissions and policy enforcement
5. Unauthorized invocation blocking
6. Suspicious activity heuristics
7. Privilege escalation indicators
8. Security alerts and notifications
9. Dashboard with auto-refreshing statistics
10. Agent risk scoring (0–100)
11. Audit logs and activity history
12. Analytics and CSV reports
13. Admin and user management with roles
14. Safe AI agent simulation and testing
15. External agent API using bearer API keys

## External agent API

An administrator can issue an API key from Agent Management. Copy it immediately; only the hash is stored and the raw key is shown once.

```http
POST http://127.0.0.1:5000/api/v1/tool-invocations
Authorization: Bearer YOUR_AGENT_API_KEY
Content-Type: application/json

{"tool_name":"file_reader","parameters":{"path":"example.txt"}}
```

Agent API keys can only be issued to registered agents. Give the agent explicit policies in Tool Policies before requests are allowed.

## Important security scope

This is an educational prototype, not a production-hardened enterprise gateway. Tool requests are evaluated and logged; **the requested tools are never executed**. External API calls are authenticated by bearer key and use the same policy engine. Before production, add CSRF protection, stronger rate limiting, API key expiry/rotation workflow, strict schema validation, role-level route authorization, immutable audit storage, HTTPS, secrets management, database migrations, backups and security testing. Run behind a production WSGI server; never expose Flask's development server directly to the internet.

## Python SDK (v0.1.0)

Gateway ke saath AI agent ko judne ke liye `agentguard_sdk` use karein:

```python
from agentguard_sdk import AgentGuard, guarded_dispatch

guard = AgentGuard(api_key="YOUR_AGENT_API_KEY", base_url="http://127.0.0.1:5000")
out = guarded_dispatch(guard, "file_reader", {"path": "notes.txt"}, REGISTRY)
```

Demo: `python -m examples.run_demo` (pehle `AGENTGUARD_API_KEY` set karein).

## Real AI agent (LLM + gateway)

- `agent/` LLM loop: LLM tool call banata hai, har call pehle AgentGuard gateway se check hoti hai.
- Real tools sandbox ke andar chalte hain (`sandbox/notes.txt`, `sandbox/records.db`).
- Dangerous tools (`delete_database`, `shell_execute`, `user_admin`) sirf simulation hain.

Run: `python -m examples.run_agent --provider groq` (GROQ_API_KEY aur AGENTGUARD_API_KEY set hon)

Attack tests: `python -m examples.attack_suite --provider fake` (offline) ya `--provider groq` (asli prompt injection)

## Autonomous worker (tasks.json)

`tasks.json` mein kaam likhein (`status` `pending` ho). Worker unhe ek ek karke chalata hai aur natija `results/` mein save karta hai.

    python -m agent.worker --provider fake
    python -m agent.worker --provider groq --loop

## Human approval (REVIEW)

`report_export` jaisi tools policy mein allowed hain, lekin insaan ki approval ke bina nahi chalti. Gateway request ko `REVIEW` deta hai, aur dashboard ke **Approval Queue** mein Approve ya Deny ka option aata hai. Agent approval ka intezaar karta hai, aur timeout par tool nahi chalta.

## Tests aur CI

    pip install -r requirements-dev.txt
    pytest -q

GitHub par har push par `.github/workflows/ci.yml` tests chalata hai.

## Security features (v7)

- **Rate limit**: ek agent 60 second mein 20 se zyada calls kare to gateway block karta hai.
- **Prompt injection scan**: tool parameters mein "ignore previous instructions" jaise patterns block hote hain.
- **Tamper-evident audit log**: `GET /api/audit/verify` audit log ki chain check karta hai. Kisi entry ko badalne par `ok: false` aata hai.
- **Webhook alerts**: `AGENTGUARD_WEBHOOK_URL` set karein (Slack incoming webhook) to har naya alert wahan jata hai.

## Roles (RBAC)

- **viewer**: sirf dekh sakta hai, koi change nahi kar sakta
- **analyst**: approvals decide, alerts resolve, aur playground chala sakta hai
- **admin**: agents, policies aur users manage kar sakta hai

Ye check server par hota hai. Viewer ke dashboard par buttons nazar aa sakte hain, lekin click karne par 403 error aata hai.

## Live dashboard

Dashboard `/api/stream` (Server-Sent Events) se update hota hai. Jab invocations, alerts ya approvals badalte hain, browser ka data khud refresh ho jata hai.

## Deployment (Render)

1. Code GitHub par push karein (repo ka root wahi folder ho jis mein `render.yaml` hai).
2. Render par **New > Blueprint** choose karke repo connect karein. `render.yaml` se web service aur Postgres database ban jayenge.
3. Environment mein `AGENTGUARD_ADMIN_PASSWORD` set karein (ye sync: false hai, is liye aap ko dena hoga). Ye sirf pehle admin ke liye use hota hai, is liye strong password rakhein.
4. Deploy hone ke baad Render ka `https://...onrender.com` URL open karein aur login karein.

Production mode (`AGENTGUARD_ENV=production`) mein agar secret key, admin password ya database URL na hon, to app start nahi hota. Ye jaan boojh kar hai, taake default passwords live na chalein.

Free tier ki limits: service kuch der idle rehne par sleep hoti hai, aur free Postgres ka data ek time ke baad expire ho sakta hai. Current terms Render ki website par dekhein.

## Monitoring (Prometheus)

`GET /metrics` login ke baad ya header `X-Metrics-Token` (env `AGENTGUARD_METRICS_TOKEN`) ke saath counts deta hai: invocations by status, pending approvals, open alerts, aur agents.

## GitHub par upload karne se pehle

`.gitignore` already hai. Ye `.env`, `instance/` (database), `venv/`, `sandbox/` aur `results/` ko repo se bahar rakhta hai. Push se pehle `git status` se check karein ke in mein se koi file list mein na ho.

## Reports

Reports page par CSV aur PDF dono download ho sakte hain (`/api/reports.csv`, `/api/reports.pdf`). Dashboard ke top numbers ab live update hote hain.
