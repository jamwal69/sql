#!/usr/bin/env python3
"""
Main entry point for SQLInjector tool.
Can be used as: python -m sqlinjector or sqlinjector (if installed)
"""
import sys
import asyncio
from pathlib import Path

# Add the current directory to the Python path for development
sys.path.insert(0, str(Path(__file__).parent))

from cli import main

if __name__ == "__main__":
    asyncio.run(main())