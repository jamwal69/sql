"""Test configuration and fixtures."""

import os
import tempfile
import pytest
from pathlib import Path

# Test configuration
TEST_DB_PATH = tempfile.mkdtemp()
TEST_REPORTS_PATH = tempfile.mkdtemp()

# Mock vulnerable targets for testing (DO NOT USE ON REAL SYSTEMS)
MOCK_VULNERABLE_RESPONSES = {
    "mysql_error": {
        "content": "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
        "status_code": 500
    },
    "postgresql_error": {
        "content": "ERROR: syntax error at or near \"'\" at character 1",
        "status_code": 500
    },
    "mssql_error": {
        "content": "Microsoft OLE DB Provider for ODBC Drivers error '80040e14'",
        "status_code": 500
    }
}

# Test payloads for validation
TEST_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' UNION SELECT NULL--",
    "1' AND SLEEP(5)--"
]


@pytest.fixture(scope="session")
def test_db_path():
    """Provide test database path."""
    return TEST_DB_PATH


@pytest.fixture(scope="session")
def test_reports_path():
    """Provide test reports path."""
    return TEST_REPORTS_PATH


@pytest.fixture
def cleanup_test_files():
    """Clean up test files after tests."""
    yield
    # Cleanup logic would go here
    pass