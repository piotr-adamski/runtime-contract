import os

database_url = os.environ["DATABASE_URL"]
service_token = os.getenv("SERVICE_TOKEN")
optional_mode = os.getenv("OPTIONAL_MODE", "safe-default")
missing_runtime = os.getenv("MISSING_RUNTIME")
