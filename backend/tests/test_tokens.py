import secrets
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.auth.tokens import ISSUER, REQUIRED_CLAIMS, TokenError, TokenService
from app.config import ConfigurationError
from app.rbac.roles import Role
from tests.conftest import make_settings

SECRET = secrets.token_urlsafe(48)


@pytest.fixture
def service() -> TokenService:
    return TokenService(SECRET, "HS256", 60)


def _payload(**overrides):
    now = int(datetime.now(UTC).timestamp())
    payload = {
        "sub": "7",
        "role": "TEACHER",
        "iat": now,
        "exp": now + 600,
        "jti": "abc123",
        "iss": ISSUER,
    }
    payload.update(overrides)
    return {k: v for k, v in payload.items() if v is not None}


def test_valid_token_round_trip(service):
    issued = service.issue(42, Role.HOD)
    claims = service.decode(issued.token)
    assert (claims.user_id, claims.role) == (42, Role.HOD)
    assert claims.token_id == issued.claims.token_id
    assert issued.expires_in == 3600
    assert claims.expires_at - claims.issued_at == timedelta(minutes=60)


def test_token_carries_only_minimal_claims(service):
    token = service.issue(42, Role.STUDENT).token
    payload = jwt.decode(token, options={"verify_signature": False})
    assert set(payload) == set(REQUIRED_CLAIMS)
    assert payload["sub"] == "42" and payload["role"] == "STUDENT"


def test_each_token_has_a_unique_id(service):
    assert (
        service.issue(1, Role.ADMIN).claims.token_id != service.issue(1, Role.ADMIN).claims.token_id
    )


def test_expired_token_rejected(service):
    old = service.issue(42, Role.ADMIN, now=datetime.now(UTC) - timedelta(minutes=61))
    with pytest.raises(TokenError, match="ExpiredSignatureError"):
        service.decode(old.token)


@pytest.mark.parametrize("token", ["", "abc", "not.a.token", "a.b", "Bearer x.y.z", "é.é.é"])
def test_malformed_token_rejected(service, token):
    with pytest.raises(TokenError):
        service.decode(token)


def test_invalid_signature_rejected(service):
    forged = TokenService(secrets.token_urlsafe(48), "HS256", 60).issue(42, Role.ADMIN)
    with pytest.raises(TokenError, match="InvalidSignatureError"):
        service.decode(forged.token)


def test_tampered_payload_rejected(service):
    header, _payload_part, signature = service.issue(4, Role.STUDENT).token.split(".")
    elevated = jwt.encode(_payload(sub="4", role="ADMIN"), "x" * 40, algorithm="HS256")
    tampered = ".".join([header, elevated.split(".")[1], signature])
    with pytest.raises(TokenError):
        service.decode(tampered)


def test_alg_none_rejected(service):
    unsigned = jwt.encode(_payload(), key=None, algorithm="none")
    with pytest.raises(TokenError):
        service.decode(unsigned)


def test_other_hmac_algorithm_rejected(service):
    token = jwt.encode(_payload(), SECRET, algorithm="HS512")
    with pytest.raises(TokenError, match="InvalidAlgorithmError"):
        service.decode(token)


@pytest.mark.parametrize("claim", REQUIRED_CLAIMS)
def test_missing_required_claim_rejected(service, claim):
    token = jwt.encode(_payload(**{claim: None}), SECRET, algorithm="HS256")
    with pytest.raises(TokenError):
        service.decode(token)


@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "someone-else"},
        {"sub": "admin"},
        {"sub": "-1"},
        {"role": "SUPERUSER"},
        {"role": "admin"},
        {"jti": ""},
    ],
)
def test_invalid_claim_values_rejected(service, overrides):
    token = jwt.encode(_payload(**overrides), SECRET, algorithm="HS256")
    with pytest.raises(TokenError):
        service.decode(token)


def test_error_messages_never_contain_the_token(service):
    token = service.issue(1, Role.ADMIN).token + "x"
    with pytest.raises(TokenError) as info:
        service.decode(token)
    assert token not in str(info.value)


def test_no_fallback_secret():
    with pytest.raises(ConfigurationError):
        TokenService.from_settings(make_settings(jwt_secret=None))
