"""
SQLInjector - Advanced SQL Injection Testing Tool

A comprehensive penetration testing tool for discovering and exploiting SQL injection vulnerabilities.
Use only on systems you are authorized to test.

Author: AI Agent
License: MIT
"""

__version__ = "1.0.0"
__author__ = "AI Agent"
__license__ = "MIT"

from .core.scanner import SQLIScanner
from .core.injector import SQLInjector
from .core.session import SessionManager

__all__ = ['SQLIScanner', 'SQLInjector', 'SessionManager']