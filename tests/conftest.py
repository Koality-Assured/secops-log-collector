"""Pytest fixtures and configuration for secops-log-collector test suite."""

import sys
from pathlib import Path

import pytest

# Ensure repository root is on sys.path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))


@pytest.fixture
def mock_sleep_recorder():
    """Captures sleep durations without pausing test execution."""
    sleeps = []

    def _mock_sleep(duration: float):
        sleeps.append(duration)

    _mock_sleep.sleeps = sleeps
    return _mock_sleep
