import os

CANARY = "D1_14_CANARY_VALUE_9f31"
PRIVATE_KEY = "-----BEGIN D1_14 TEST PRIVATE KEY-----"

first = os.getenv("API_URL")
second = os.environ["API_TOKEN"]
third = os.environ.get("API_URL")
fourth = os.getenv("WORKERS", "4")
