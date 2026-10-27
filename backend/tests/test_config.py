import secrets

import pytest
from pydantic import ValidationError

from app.config import MIN_JWT_SECRET_LENGTH, ConfigurationError, Settings
from tests.conftest import make_settings


def test_safe_defaults_without_env_file():
    s = Settings(_env_file=None)
    assert s.app_env == "development"
    assert s.db_host == "127.0.0.1"
    assert (s.db_reader_user, s.db_app_user) == ("askq_reader", "askq_app")
    assert (s.db_university_name, s.db_system_name) == ("askq_university", "askq_system")
    assert s.jwt_algorithm == "HS256"
    assert s.cors_origin_list == ["http://localhost:5173"]
    # No fallback secrets: unset until configured.
    assert s.jwt_secret is None and s.db_app_password is None and s.db_reader_password is None
    assert s.anthropic_api_key is None
    assert s.anthropic_model == "claude-sonnet-5"
    assert s.llm_provider == "claude"
    assert (s.ollama_base_url, s.ollama_model) == ("http://127.0.0.1:11434", "qwen2.5-coder:7b")
    assert (s.ollama_timeout_seconds, s.ollama_num_ctx, s.ollama_temperature) == (120, 8192, 0)
    assert (s.sql_max_rows, s.sql_timeout_ms) == (500, 5000)


def test_loads_existing_env_variable_names(tmp_path):
    # The names shared with database/setup_db.ps1 must keep working.
    jwt = secrets.token_urlsafe(40)
    env = tmp_path / ".env"
    env.write_text(
        "APP_ENV=test\nDB_HOST=127.0.0.1\nDB_PORT=3307\n"
        "DB_UNIVERSITY_NAME=askq_university\nDB_SYSTEM_NAME=askq_system\n"
        f"DB_READER_USER=askq_reader\nDB_READER_PASSWORD={secrets.token_urlsafe(20)}\n"
        f"DB_APP_USER=askq_app\nDB_APP_PASSWORD={secrets.token_urlsafe(20)}\n"
        f"JWT_SECRET={jwt}\nJWT_ALGORITHM=HS384\nJWT_EXPIRE_MINUTES=15\n"
        "CORS_ORIGINS=http://localhost:5173, http://127.0.0.1:5173\n"
        "ANTHROPIC_API_KEY=ignored-in-this-phase\n",
        encoding="utf-8",
    )
    s = Settings(_env_file=env)
    assert s.db_port == 3307
    assert s.jwt_algorithm == "HS384" and s.jwt_expire_minutes == 15
    assert s.secret("jwt_secret") == jwt
    assert s.cors_origin_list == ["http://localhost:5173", "http://127.0.0.1:5173"]


def test_secrets_are_masked_in_repr():
    s = make_settings()
    text = repr(s) + str(s)
    for name in ("jwt_secret", "db_app_password", "db_reader_password", "anthropic_api_key"):
        assert s.secret(name) not in text


@pytest.mark.parametrize("value", [None, "", "   ", "change-me-generate-a-long-random-secret"])
def test_unset_or_placeholder_secret_is_not_configured(value):
    s = make_settings(jwt_secret=value)
    assert not s.is_configured("jwt_secret")
    with pytest.raises(ConfigurationError, match="JWT_SECRET is not configured"):
        s.secret("jwt_secret")


def test_short_jwt_secret_rejected_without_echoing_it():
    weak = "w" * (MIN_JWT_SECRET_LENGTH - 1)
    with pytest.raises(ValidationError) as info:
        make_settings(jwt_secret=weak)
    assert "JWT_SECRET must be at least" in str(info.value)
    assert weak not in str(info.value)


def test_production_requires_every_secret():
    with pytest.raises(ValidationError) as info:
        make_settings(
            app_env="production",
            cors_origins="https://askq.example",
            db_app_password="change-me-app-password",
            db_reader_password=None,
            anthropic_api_key="your-anthropic-api-key-here",
        )
    message = str(info.value)
    assert "DB_READER_PASSWORD" in message and "DB_APP_PASSWORD" in message
    assert "ANTHROPIC_API_KEY" in message


def test_production_with_ollama_does_not_require_an_anthropic_key():
    s = make_settings(
        app_env="production",
        cors_origins="https://askq.example",
        llm_provider="ollama",
        anthropic_api_key=None,
    )
    assert s.is_production and s.llm_provider == "ollama"


def test_production_with_ollama_still_requires_the_other_secrets():
    with pytest.raises(ValidationError) as info:
        make_settings(
            app_env="production",
            cors_origins="https://askq.example",
            llm_provider="ollama",
            anthropic_api_key=None,
            jwt_secret=None,
        )
    message = str(info.value)
    assert "JWT_SECRET" in message and "ANTHROPIC_API_KEY" not in message


def test_loads_ollama_settings_from_env(tmp_path):
    env = tmp_path / ".env"
    env.write_text(
        "LLM_PROVIDER=ollama\nOLLAMA_BASE_URL=http://127.0.0.1:11434\n"
        "OLLAMA_MODEL=qwen2.5-coder:7b\nOLLAMA_TIMEOUT_SECONDS=120\n"
        "OLLAMA_NUM_CTX=8192\nOLLAMA_TEMPERATURE=0\n",
        encoding="utf-8",
    )
    s = Settings(_env_file=env)
    assert s.llm_provider == "ollama" and s.ollama_model == "qwen2.5-coder:7b"
    assert s.anthropic_api_key is None


def test_production_requires_explicit_cors():
    with pytest.raises(ValidationError, match="CORS_ORIGINS"):
        make_settings(app_env="production")
    s = make_settings(app_env="production", cors_origins="https://askq.example")
    assert s.is_production


@pytest.mark.parametrize(
    ("overrides", "fragment"),
    [
        ({"app_env": "staging"}, "app_env"),
        ({"jwt_algorithm": "none"}, "JWT_ALGORITHM"),
        ({"jwt_algorithm": "RS256"}, "JWT_ALGORITHM"),
        ({"jwt_expire_minutes": 0}, "jwt_expire_minutes"),
        ({"jwt_expire_minutes": 10_000}, "jwt_expire_minutes"),
        ({"db_port": 0}, "db_port"),
        ({"cors_origins": "*"}, "CORS_ORIGINS"),
        ({"cors_origins": "http://localhost:5173,*"}, "CORS_ORIGINS"),
        ({"cors_origins": "localhost:5173"}, "CORS_ORIGINS"),
        ({"cors_origins": "http://x.example/path"}, "CORS_ORIGINS"),
        ({"db_app_user": "askq_reader"}, "different accounts"),
        ({"db_system_name": "askq_university"}, "must differ"),
        ({"db_university_name": "askq-university; DROP"}, "DB_UNIVERSITY_NAME"),
        ({"db_pool_size": 10, "db_max_overflow": 11}, "db_max_overflow"),
        ({"anthropic_model": "claude opus; rm -rf"}, "ANTHROPIC_MODEL"),
        ({"sql_max_rows": 0}, "sql_max_rows"),
        ({"sql_max_rows": 100_000}, "sql_max_rows"),
        ({"sql_timeout_ms": 10}, "sql_timeout_ms"),
        ({"anthropic_timeout_seconds": 1}, "anthropic_timeout_seconds"),
        ({"llm_provider": "openai"}, "llm_provider"),
        ({"ollama_model": "qwen; rm -rf"}, "OLLAMA_MODEL"),
        ({"ollama_base_url": "127.0.0.1:11434"}, "OLLAMA_BASE_URL"),
        ({"ollama_base_url": "http://127.0.0.1:11434/api"}, "OLLAMA_BASE_URL"),
        ({"ollama_base_url": "http://user:pw@127.0.0.1:11434"}, "OLLAMA_BASE_URL"),
        ({"ollama_base_url": "file:///etc/passwd"}, "OLLAMA_BASE_URL"),
        ({"ollama_timeout_seconds": 1}, "ollama_timeout_seconds"),
        ({"ollama_num_ctx": 2048}, "ollama_num_ctx"),
        ({"ollama_temperature": -1}, "ollama_temperature"),
    ],
)
def test_invalid_configuration_rejected(overrides, fragment):
    with pytest.raises(ValidationError, match=fragment):
        make_settings(**overrides)


def test_reader_and_app_passwords_must_differ():
    shared = secrets.token_urlsafe(24)
    with pytest.raises(ValidationError, match="must differ") as info:
        make_settings(db_app_password=shared, db_reader_password=shared)
    assert shared not in str(info.value)


def test_secret_accessor_rejects_non_secret_names():
    with pytest.raises(KeyError):
        make_settings().secret("db_host")
