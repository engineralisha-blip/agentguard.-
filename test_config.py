from config import production_problems


def test_development_needs_nothing():
    assert production_problems({}) == []


def test_production_lists_missing_settings():
    missing = production_problems({"AGENTGUARD_ENV": "production"})
    assert "AGENTGUARD_SECRET_KEY" in missing
    assert "AGENTGUARD_ADMIN_PASSWORD" in missing
    assert "AGENTGUARD_DATABASE_URL" in missing


def test_production_with_all_settings_is_ok():
    env = {"AGENTGUARD_ENV": "production", "AGENTGUARD_SECRET_KEY": "x" * 40,
           "AGENTGUARD_ADMIN_PASSWORD": "strong-pass-123", "AGENTGUARD_DATABASE_URL": "postgresql://a"}
    assert production_problems(env) == []
