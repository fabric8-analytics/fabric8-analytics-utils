"""Utilities required for user token management."""
import tenacity
from tenacity import retry
from enum import Enum
import requests
import logging
from cryptography.fernet import Fernet
from .default_config import SNYK_API_TOKEN_VALIDATION_URL, ENCRYPTION_KEY_FOR_SNYK_TOKEN

logger = logging.getLogger(__name__)


@retry(reraise=True, stop=tenacity.stop_after_attempt(6),
       wait=tenacity.wait_exponential(multiplier=2, min=4))
def is_snyk_token_valid(snyk_api_token):
    """Validate Snyk API token."""
    try:
        response = requests.post(SNYK_API_TOKEN_VALIDATION_URL, json={'api': snyk_api_token})
        return response.status_code == 200
    except Exception as e:
        logger.exception("Encountered exception calling Snyk")
        raise e


def encrypt_api_token(snyk_api_token):
    """Encryption of Api Token."""
    cipher = Fernet(ENCRYPTION_KEY_FOR_SNYK_TOKEN.encode())
    return cipher.encrypt(snyk_api_token.encode())


def decrypt_api_token(snyk_api_token):
    """Decryption of Api Token."""
    cipher = Fernet(ENCRYPTION_KEY_FOR_SNYK_TOKEN.encode())
    return cipher.decrypt(snyk_api_token.encode())


class UserStatus(Enum):
    """Enumeration for maintaining user status."""

    REGISTERED = 1
    FREETIER = 2
    EXPIRED = 3
