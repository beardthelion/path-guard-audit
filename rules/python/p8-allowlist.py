# Fixture for rules/python/p8-allowlist.yaml.

import os

# ruleid: path-guard-audit-p8-python-env-killswitch
ALLOW_ANY_PATH = os.getenv("ALLOW_ANY_PATH")

# ok: path-guard-audit-p8-python-env-killswitch
DISABLE_TELEMETRY = os.getenv("DISABLE_TELEMETRY")

# ruleid: path-guard-audit-p8-python-env-killswitch
_UNSAFE_PATHS_ENV = "ALLOW_UNSAFE_PATHS"

# ok: path-guard-audit-p8-python-env-killswitch
_LOG_LEVEL_ENV = "LOG_LEVEL"

# ok: path-guard-audit-p8-python-env-killswitch
ALLOW_TELEMETRY = "1"


# ruleid: path-guard-audit-p8-python-default-off
allowed_paths = []

# ruleid: path-guard-audit-p8-python-default-off
permitted_roots = None

# ok: path-guard-audit-p8-python-default-off
max_upload_bytes = 1024
