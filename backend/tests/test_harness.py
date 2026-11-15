"""
Verification of Backend Pytest test harness and modular monolith package imports.
"""
import pytest
import sys


def test_python_runtime_version():
    """Verify Python runtime meets minimum requirement (>= 3.11)."""
    assert sys.version_info.major == 3
    assert sys.version_info.minor >= 11


def test_backend_subsystem_packages():
    """Verify that all core modular monolith subsystems can be resolved."""
    import app
    import app.core
    import app.database
    import app.models
    import app.schemas
    import app.repositories
    import app.services
    import app.detection
    import app.intelligence
    import app.api.v1
    import app.workers

    assert app is not None
    assert app.core is not None
    assert app.detection is not None

