"""
Key Management Service (KMS) integration layer (AG-15).

Enterprises require strict control over cryptographic keys. Loading JWT signing
keys or session secrets from plain environment variables fails modern security
reviews. This module provides a unified interface for fetching and caching keys
from secure providers like HashiCorp Vault, AWS KMS, or a local mock for dev.
"""
from __future__ import annotations

import os
import logging
import time
from typing import Optional, Protocol

logger = logging.getLogger("gateway.kms")


class KMSProvider(Protocol):
    """Interface for any Key Management Service provider."""
    def get_public_key(self, key_id: str) -> Optional[str]:
        ...
    def get_secret(self, secret_id: str) -> Optional[str]:
        ...


class LocalMockKMS:
    """Fallback KMS that reads from environment variables (Dev/Community only)."""
    def __init__(self):
        logger.warning("Using LocalMockKMS. Secrets will be read from environment variables.")

    def get_public_key(self, key_id: str) -> Optional[str]:
        return os.environ.get(key_id)

    def get_secret(self, secret_id: str) -> Optional[str]:
        return os.environ.get(secret_id)


class AWSKMSProvider:
    """Stub for AWS KMS integration. In production, this uses boto3."""
    def __init__(self, region: str = "us-east-1"):
        self.region = region
        logger.info(f"Initialized AWS KMS Provider in {region}")

    def get_public_key(self, key_id: str) -> Optional[str]:
        # TODO: Implement boto3 kms get-public-key
        logger.error("AWS KMS get_public_key not fully implemented yet.")
        return None

    def get_secret(self, secret_id: str) -> Optional[str]:
        # TODO: Implement boto3 secretsmanager get-secret-value
        logger.error("AWS KMS get_secret not fully implemented yet.")
        return None


class HashiCorpVaultProvider:
    """Stub for HashiCorp Vault integration. In production, this uses hvac."""
    def __init__(self, vault_addr: str, token: str):
        self.vault_addr = vault_addr
        self.token = token
        logger.info(f"Initialized HashiCorp Vault Provider at {vault_addr}")

    def get_public_key(self, key_id: str) -> Optional[str]:
        # TODO: Implement hvac client.secrets.kv.v2.read_secret_version
        logger.error("Vault get_public_key not fully implemented yet.")
        return None

    def get_secret(self, secret_id: str) -> Optional[str]:
        # TODO: Implement hvac client.secrets.kv.v2.read_secret_version
        logger.error("Vault get_secret not fully implemented yet.")
        return None


class KMSClient:
    """
    The main KMS Client used by the gateway. Caches keys in memory to prevent
    high latency calls to the external KMS on every single request.
    """
    def __init__(self, provider: KMSProvider, cache_ttl_seconds: int = 300):
        self.provider = provider
        self.cache_ttl = cache_ttl_seconds
        self._cache = {}

    def _get_cached(self, key: str) -> Optional[str]:
        if key in self._cache:
            val, expiry = self._cache[key]
            if time.time() < expiry:
                return val
            del self._cache[key]
        return None

    def _set_cached(self, key: str, value: str):
        self._cache[key] = (value, time.time() + self.cache_ttl)

    def resolve_public_key(self, key_id: str) -> Optional[str]:
        """Resolves an asymmetric public key (PEM)."""
        cached = self._get_cached(key_id)
        if cached:
            return cached
        
        val = self.provider.get_public_key(key_id)
        if val:
            self._set_cached(key_id, val)
        return val

    def resolve_secret(self, secret_id: str) -> Optional[str]:
        """Resolves a symmetric secret (e.g. for HS256)."""
        cached = self._get_cached(secret_id)
        if cached:
            return cached
        
        val = self.provider.get_secret(secret_id)
        if val:
            self._set_cached(secret_id, val)
        return val


def get_kms_client(provider_name: str = "local") -> KMSClient:
    """Factory to instantiate the configured KMS provider."""
    provider_name = provider_name.lower().strip()
    
    if provider_name == "aws":
        provider = AWSKMSProvider()
    elif provider_name == "vault":
        addr = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
        token = os.environ.get("VAULT_TOKEN", "")
        provider = HashiCorpVaultProvider(addr, token)
    else:
        provider = LocalMockKMS()
        
    return KMSClient(provider=provider)
