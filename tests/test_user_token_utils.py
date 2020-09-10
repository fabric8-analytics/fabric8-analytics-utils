"""Test class for user token management."""
from unittest.mock import patch
import unittest

import f8a_utils.user_token_utils as snyk_utils


class HttpResponse:
    """Mock the HTTP response that does not contain any payload."""

    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text


resp_200 = HttpResponse(200, '')
resp_400 = HttpResponse(400, '')


class TestSynkToken(unittest.TestCase):
    """Test cases for checking validity of Snyk Token."""

    @patch("requests.post")
    def test_is_valid_snyk_token(self, mock1):
        """Check for valid token."""
        mock1.return_value = resp_200
        self.assertTrue(snyk_utils.is_snyk_token_valid("valid_snyk_token"))

    @patch("requests.post", return_value=resp_400)
    def test_is_invalid_snyk_token(self, mock1):
        """Check for invalid token."""
        mock1.return_value = resp_400
        self.assertFalse(snyk_utils.is_snyk_token_valid("invalid_snyk_token"))
