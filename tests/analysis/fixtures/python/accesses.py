import os
import os as operating_system
from os import environ as env
from os import getenv as read_env

os.getenv("ONE")
operating_system.environ.get("TWO", default="fallback")
env["THREE"]
read_env("FOUR", None)
