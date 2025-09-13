#!/usr/bin/env python3
"""
Setup script for SQLInjector package.
"""
from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
README_PATH = Path(__file__).parent / "README.md"
if README_PATH.exists():
    long_description = README_PATH.read_text(encoding="utf-8")
else:
    long_description = "Advanced SQL injection testing tool for security professionals."

# Read requirements
REQUIREMENTS_PATH = Path(__file__).parent / "requirements.txt"
if REQUIREMENTS_PATH.exists():
    requirements = REQUIREMENTS_PATH.read_text().strip().split('\n')
    requirements = [r.strip() for r in requirements if r.strip() and not r.startswith('#')]
else:
    requirements = [
        "httpx>=0.25.0",
        "requests>=2.31.0",
        "lxml>=4.9.0",
        "beautifulsoup4>=4.12.0",
        "click>=8.1.0",
        "colorama>=0.4.6",
        "jinja2>=3.1.0",
        "PyYAML>=6.0"
    ]

setup(
    name="sqlinjector",
    version="1.0.0",
    author="AI Agent",
    author_email="contact@example.com",
    description="Advanced SQL injection testing tool for security professionals",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-repo/sqlinjector",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
            "black>=23.7.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0"
        ],
        "gui": [
            "tkinter"
        ],
        "pdf": [
            "weasyprint>=59.0"
        ]
    },
    entry_points={
        "console_scripts": [
            "sqlinjector=sqlinjector.sqlinjector:main",
        ],
    },
    include_package_data=True,
    package_data={
        "sqlinjector": [
            "payloads/*.json",
            "reports/templates/*.html",
        ],
    },
    keywords="sql injection security testing penetration",
    project_urls={
        "Bug Reports": "https://github.com/your-repo/sqlinjector/issues",
        "Source": "https://github.com/your-repo/sqlinjector",
        "Documentation": "https://github.com/your-repo/sqlinjector/wiki",
    },
)