"""Shared test fixtures and configuration for proxy-api tests."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

_PROXY_ROOT = Path(__file__).resolve().parent.parent
_OSS_ROOT = _PROXY_ROOT.parent

if str(_PROXY_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROXY_ROOT))

os.environ.setdefault(
    "PROVIDERS_CONFIG_PATH",
    str(_OSS_ROOT / "config" / "providers.json"),
)
