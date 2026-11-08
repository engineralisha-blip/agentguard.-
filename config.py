import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    SECRET_KEY = os.environ.get("AGENTGUARD_SECRET_KEY", "change-this-before-deployment")
    DATABASE = os.environ.get("AGENTGUARD_DATABASE", str(BASE_DIR / "instance" / "agentguard.db"))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"
    MAX_CONTENT_LENGTH = 1024 * 1024


def production_problems(env):
    """AGENTGUARD_ENV=production par ye settings zaroori hain. Missing names ki list return karta hai."""
    missing = []
    if env.get("AGENTGUARD_ENV") == "production":
        for name in ("AGENTGUARD_SECRET_KEY", "AGENTGUARD_ADMIN_PASSWORD", "AGENTGUARD_DATABASE_URL"):
            if not env.get(name):
                missing.append(name)
    return missing
