"""Root pytest configuration.

Provides safe, non-secret defaults so modules that read settings at import time
(e.g. the Celery app) can be imported by unit tests. Integration runs override
these through real environment variables (see docs/TESTING.md).
"""

from __future__ import annotations

import os

_TEST_DEFAULTS = {
    "SENTINELX_ENVIRONMENT": "test",
    "SENTINELX_LOG_JSON": "true",
    "SENTINELX_SECRET_KEY": "test-only-secret-key-not-for-production-use-0000",
    # Port 1 is never listening: unit tests must not depend on real infrastructure.
    "SENTINELX_DATABASE_URL": "postgresql+asyncpg://sentinelx:sentinelx@127.0.0.1:1/sentinelx",
    "SENTINELX_REDIS_URL": "redis://127.0.0.1:1/0",
    "SENTINELX_ALLOWED_HOSTS": "testserver,localhost,127.0.0.1",
}

for _key, _value in _TEST_DEFAULTS.items():
    os.environ.setdefault(_key, _value)
