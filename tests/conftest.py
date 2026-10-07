from __future__ import annotations

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


@pytest.fixture
def fixtures_dir() -> str:
    return FIXTURES


@pytest.fixture
def basic_dir() -> str:
    return os.path.join(FIXTURES, "basic")


@pytest.fixture
def clean_dir() -> str:
    return os.path.join(FIXTURES, "clean")
