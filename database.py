import os
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from flask import current_app

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'analyst',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS agents (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT DEFAULT '',
 status TEXT NOT NULL DEFAULT 'active', api_key_hash TEXT UNIQUE,
 risk_score INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tools (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL,
 description TEXT DEFAULT '', sensitivity TEXT NOT NULL DEFAULT 'medium',
 active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS policies (
 id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id INTEGER NOT NULL,
 tool_id INTEGER NOT NULL, decision TEXT NOT NULL DEFAULT 'allow',
 expires_at TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(agent_id, tool_id), FOREIGN KEY(agent_id) REFERENCES agents(id),
 FOREIGN KEY(tool_id) REFERENCES tools(id)
);
CREATE TABLE IF NOT EXISTS invocations (
 id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id INTEGER, agent_name TEXT NOT NULL,
 tool_name TEXT NOT NULL, parameters TEXT DEFAULT '{}', status TEXT NOT NULL,
 reason TEXT NOT NULL, risk_score INTEGER NOT NULL DEFAULT 0,
 source TEXT NOT NULL DEFAULT 'dashboard', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS alerts (
 id INTEGER PRIMARY KEY AUTOINCREMENT, invocation_id INTEGER,
 agent_id INTEGER, severity TEXT NOT NULL, title TEXT NOT NULL,
 description TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, resolved_at TEXT
);
CREATE TABLE IF NOT EXISTS audit_logs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, username TEXT NOT NULL,
 action TEXT NOT NULL, details TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS notifications (
 id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, message TEXT NOT NULL,
 severity TEXT NOT NULL, read INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS approvals (
 id INTEGER PRIMARY KEY AUTOINCREMENT, invocation_id INTEGER, agent_id INTEGER NOT NULL,
 agent_name TEXT NOT NULL, tool_name TEXT NOT NULL, parameters TEXT DEFAULT '{}',
 status TEXT NOT NULL DEFAULT 'pending', decided_by TEXT, decided_at TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_chain (
 id INTEGER PRIMARY KEY AUTOINCREMENT, log_id INTEGER NOT NULL,
 prev_hash TEXT NOT NULL, hash TEXT NOT NULL
);
"""

def _norm(value):
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return value

class Row(tuple):
    """sqlite3.Row jaisa: row[0] aur row['column'] dono kaam karte hain."""
    def __new__(cls, values, names):
        obj = super().__new__(cls, values)
        obj._names = names
        return obj
    def __getitem__(self, key):
        if isinstance(key, str):
            return tuple.__getitem__(self, self._names.index(key))
        return tuple.__getitem__(self, key)
    def keys(self):
        return list(self._names)

class _Result:
    def __init__(self, rows, names, rowcount, lastrowid):
        self._rows = [Row(r, names) for r in rows]
        self.rowcount = rowcount
        self.lastrowid = lastrowid
    def fetchone(self):
        return self._rows.pop(0) if self._rows else None
    def fetchall(self):
        rows, self._rows = self._rows, []
        return rows
    def __iter__(self):
        return iter(self.fetchall())

class _Base:
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc, tb):
        if exc_type:
            self.rollback()
        else:
            self.commit()
        self.close()
        return False

class _SqliteConn(_Base):
    def __init__(self, path):
        self.raw = sqlite3.connect(path)
        self.raw.row_factory = sqlite3.Row
        self.raw.execute("PRAGMA foreign_keys = ON")
    def execute(self, sql, params=()):
        return self.raw.execute(sql, tuple(params))
    def executemany(self, sql, seq):
        return self.raw.executemany(sql, seq)
    def executescript(self, script):
        return self.raw.executescript(script)
    def commit(self):
        self.raw.commit()
    def rollback(self):
        self.raw.rollback()
    def close(self):
        self.raw.close()

def _sql_to_pg(sql, add_returning):
    s = re.sub(r"datetime\('now',\s*'-(\d+) (seconds|minutes)'\)",
               lambda m: f"(now() AT TIME ZONE 'utc' - interval '{m.group(1)} {m.group(2)}')", sql)
    if re.search(r"INSERT\s+OR\s+IGNORE\s+INTO", s, re.I):
        s = re.sub(r"INSERT\s+OR\s+IGNORE\s+INTO", "INSERT INTO", s, flags=re.I)
        if "ON CONFLICT" not in s.upper():
            s = s.rstrip() + " ON CONFLICT DO NOTHING"
    s = s.replace("?", "%s")
    if add_returning and re.match(r"\s*INSERT\b", s, re.I) and "RETURNING" not in s.upper():
        s = s.rstrip() + " RETURNING id"
    return s

def _schema_to_pg(schema):
    s = schema.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
    s = s.replace("TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP", "TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP")
    s = s.replace("resolved_at TEXT", "resolved_at TIMESTAMP").replace("decided_at TEXT", "decided_at TIMESTAMP")
    return s

class _PgConn(_Base):
    def __init__(self, url):
        import psycopg
        self.raw = psycopg.connect(url)
        with self.raw.cursor() as cur:
            cur.execute("SET TIME ZONE 'UTC'")
        self.raw.commit()
    def execute(self, sql, params=()):
        cur = self.raw.cursor()
        cur.execute(_sql_to_pg(sql, add_returning=True), tuple(params))
        if cur.description:
            names = [d.name for d in cur.description]
            rows = [tuple(_norm(v) for v in r) for r in cur.fetchall()]
        else:
            names, rows = [], []
        is_insert = bool(re.match(r"\s*INSERT\b", sql, re.I))
        lastrowid = rows[0][0] if (is_insert and rows) else None
        return _Result(rows, names, cur.rowcount, lastrowid)
    def executemany(self, sql, seq):
        cur = self.raw.cursor()
        cur.executemany(_sql_to_pg(sql, add_returning=False), [tuple(x) for x in seq])
        return _Result([], [], cur.rowcount, None)
    def executescript(self, script):
        cur = self.raw.cursor()
        for stmt in _schema_to_pg(script).split(";"):
            if stmt.strip():
                cur.execute(stmt)
    def commit(self):
        self.raw.commit()
    def rollback(self):
        self.raw.rollback()
    def close(self):
        self.raw.close()

def connect():
    """AGENTGUARD_DATABASE_URL set ho to Postgres, warna SQLite (default)."""
    url = os.environ.get("AGENTGUARD_DATABASE_URL", "")
    if url:
        return _PgConn(url)
    db_path = Path(current_app.config["DATABASE"])
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return _SqliteConn(db_path)

def init_db():
    with connect() as conn:
        conn.executescript(SCHEMA)
        # Seed safe demo tools.
        seed = [
            ("file_reader", "Read approved files", "low"),
            ("database_search", "Search approved records", "medium"),
            ("email_viewer", "View permitted email data", "medium"),
            ("report_export", "Export non-sensitive reports", "low"),
            ("delete_database", "Destructive database operation (simulation only)", "critical"),
            ("user_admin", "Manage user privileges (simulation only)", "critical"),
            ("shell_execute", "Execute system commands (never executed by demo)", "critical"),
        ]
        conn.executemany("INSERT OR IGNORE INTO tools(name,description,sensitivity) VALUES(?,?,?)", seed)
        # A default admin is created only on first run.
        row = conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()
        if not row:
            from werkzeug.security import generate_password_hash
            conn.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                         ("admin", generate_password_hash(os.environ.get("AGENTGUARD_ADMIN_PASSWORD", "ChangeMe123!")), "admin"))
        agent = conn.execute("SELECT id FROM agents WHERE name='Demo Agent'").fetchone()
        if not agent:
            cur = conn.execute("INSERT INTO agents(name,description) VALUES(?,?)",
                               ("Demo Agent", "Built-in agent for safe security simulations"))
            agent_id = cur.lastrowid
            for tool in ("file_reader", "database_search", "email_viewer", "report_export"):
                tool_id = conn.execute("SELECT id FROM tools WHERE name=?", (tool,)).fetchone()["id"]
                conn.execute("INSERT OR IGNORE INTO policies(agent_id,tool_id,decision) VALUES(?,?,?)",
                             (agent_id, tool_id, "allow"))
