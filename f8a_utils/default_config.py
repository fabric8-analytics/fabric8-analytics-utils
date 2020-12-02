"""Default Configurations."""
import os

SNYK_API_TOKEN_VALIDATION_URL = os.getenv('SNYK_API_TOKEN_VALIDATION_URL',
                                          'https://snyk.io/api/v1/verify/token')
ENCRYPTION_KEY_FOR_SNYK_TOKEN = os.getenv('ENCRYPTION_KEY_FOR_SNYK_TOKEN',
                                          'zXsuzlFTHnEDGRxsNMusmIMvXZ2Eg0DSJrXq8ounHP8')
