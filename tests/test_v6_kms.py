import os
import pytest
from interceptor.config import PolicyConfig
from interceptor.auth import JwtVerifier, AuthError
from interceptor.kms import get_kms_client, LocalMockKMS, AWSKMSProvider, HashiCorpVaultProvider

def test_kms_client_factory():
    local_client = get_kms_client("local")
    assert isinstance(local_client.provider, LocalMockKMS)
    
    aws_client = get_kms_client("aws")
    assert isinstance(aws_client.provider, AWSKMSProvider)
    
    vault_client = get_kms_client("vault")
    assert isinstance(vault_client.provider, HashiCorpVaultProvider)

def test_kms_caching():
    client = get_kms_client("local")
    os.environ["GATEWAY_JWT_SECRET"] = "secret_value"
    
    val1 = client.resolve_secret("GATEWAY_JWT_SECRET")
    assert val1 == "secret_value"
    
    # Change env var, but cache should hold old value
    os.environ["GATEWAY_JWT_SECRET"] = "new_secret_value"
    val2 = client.resolve_secret("GATEWAY_JWT_SECRET")
    assert val2 == "secret_value"

def test_jwt_verifier_uses_kms(monkeypatch):
    monkeypatch.setenv("GATEWAY_ENV", "dev")
    monkeypatch.setenv("GATEWAY_JWT_ALG", "HS256")
    monkeypatch.setenv("GATEWAY_JWT_SECRET", "this_is_a_very_long_secret_key_for_testing_purposes_123456789")
    monkeypatch.setenv("GATEWAY_KMS_PROVIDER", "local")
    
    cfg = PolicyConfig()
    cfg.env = "dev"
    cfg.jwt_alg = "HS256"
    cfg.kms_provider = "local"
    # DO NOT set cfg.jwt_secret directly to force it to use KMS layer
    cfg.jwt_secret = None
    
    verifier = JwtVerifier(cfg)
    assert verifier._key == "this_is_a_very_long_secret_key_for_testing_purposes_123456789"
