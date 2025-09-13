# SQLInjector - Advanced SQL Injection Testing Tool

## ⚠️ LEGAL DISCLAIMER

**This tool is for authorized security testing only. Use only on systems you own or have explicit written permission to test. Unauthorized use may be illegal.**

## Overview

SQLInjector is a comprehensive SQL injection testing tool designed for penetration testers and security professionals. It provides automated detection, fingerprinting, and exploitation of SQL injection vulnerabilities with a focus on safety and reliability.

## Key Features

### 🔍 Detection Engine
- **Error-based detection**: Identifies SQL errors in responses
- **Boolean-based blind detection**: Tests logical conditions with multiple verification rounds
- **Time-based blind detection**: Uses database-specific delay functions
- **UNION-based detection**: Tests for UNION injection capabilities

### 🗄️ Database Fingerprinting
- **Multi-technique identification**: Error patterns, function tests, syntax analysis
- **Version detection**: Extracts database version information
- **Supports**: MySQL, PostgreSQL, MSSQL, Oracle, SQLite

### 🎯 Advanced Exploitation
- **UNION exploitation**: Automated column count detection and data extraction
- **Blind extraction**: Character-by-character data extraction
- **Information gathering**: Database structure enumeration
- **File operations**: Read/write capabilities (where supported)

### 🛡️ WAF Evasion
- **Tamper techniques**: URL encoding, hex encoding, case mixing, comment injection
- **Payload variations**: Multiple syntax patterns for each database type
- **Rate limiting**: Configurable delays to avoid detection

### 📊 Reporting
- **Multiple formats**: JSON, HTML, CSV reports
- **Executive summaries**: Risk assessment and recommendations
- **Session management**: Persistent storage and scan resumption

### 🔒 Safety Features
- **Safe mode**: Disables destructive operations by default
- **Authorization checks**: Interactive permission verification
- **Comprehensive logging**: Full audit trail of all actions

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Quick Install
```bash
# Clone the repository
git clone https://github.com/your-repo/sqlinjector.git
cd sqlinjector

# Install dependencies
pip install -r requirements.txt

# Make the tool executable
chmod +x sqlinjector.py
```

### Dependencies
```bash
pip install httpx requests lxml beautifulsoup4 click colorama jinja2 pyyaml
```

## Quick Start

### Basic Usage
```bash
# Test a single parameter
python sqlinjector.py -u "http://example.com/login.php?id=1" -p "id"

# Test POST data
python sqlinjector.py -u "http://example.com/search" -m POST --data "query=test"

# Test with custom headers
python sqlinjector.py -u "http://example.com/api" --headers "Authorization: Bearer token123"
```

### Advanced Usage
```bash
# Use through proxy (e.g., Burp Suite)
python sqlinjector.py -u "http://example.com/app" --proxy "http://127.0.0.1:8080"

# Apply tamper techniques
python sqlinjector.py -u "http://example.com/search?q=test" --tamper "url_encode,comment_split"

# Generate comprehensive reports
python sqlinjector.py -u "http://example.com/app" -o "./reports" --format "both"

# Resume a previous scan
python sqlinjector.py --resume "session_12345"
```

## Configuration Examples

### Testing JSON APIs
```bash
python sqlinjector.py \
  -u "http://api.example.com/users" \
  -m POST \
  --data '{"id": 1, "filter": "active"}' \
  --headers 'Content-Type: application/json' \
  --test-json
```

### Testing with Authentication
```bash
python sqlinjector.py \
  -u "http://example.com/admin/users" \
  --auth-type "bearer" \
  --auth-data "token=eyJhbGciOiJIUzI1NiIs..."
```

### Comprehensive Security Assessment
```bash
python sqlinjector.py \
  -u "http://example.com/app" \
  --test-get --test-post --test-headers --test-cookies \
  --tamper "url_encode,html_entity,comment_split" \
  --threads 3 \
  --delay 0.5 \
  -o "./security_report" \
  --format "both"
```

## Command Line Options

### Target Configuration
- `-u, --url`: Target URL (required)
- `-m, --method`: HTTP method (GET, POST, PUT, DELETE)
- `-p, --parameter`: Specific parameter to test
- `--data`: POST data (JSON or form-encoded)
- `--headers`: Custom headers
- `--cookies`: Cookies to send

### Authentication
- `--auth-type`: Authentication type (basic, bearer, form)
- `--auth-data`: Authentication credentials

### Test Configuration
- `--test-get`: Test GET parameters (default: true)
- `--test-post`: Test POST parameters (default: true)
- `--test-headers`: Test HTTP headers
- `--test-cookies`: Test cookies
- `--test-json`: Test JSON parameters (default: true)

### Detection Settings
- `--time-delay`: Time delay for time-based detection (default: 5s)
- `--boolean-rounds`: Number of boolean verification rounds (default: 3)

### Evasion and Performance
- `--tamper`: Tamper methods (comma-separated)
- `--proxy`: Proxy URL
- `--timeout`: Request timeout (default: 30s)
- `--delay`: Delay between requests (default: 0.1s)
- `--threads`: Number of concurrent threads (default: 1)

### Safety
- `--no-safe-mode`: Disable safe mode
- `--destructive`: Enable destructive tests (USE WITH CAUTION)
- `--force`: Skip authorization prompts

### Output
- `-o, --output`: Output directory for reports
- `--format`: Report format (json, html, both)
- `-v, --verbose`: Increase verbosity
- `--quiet`: Suppress non-essential output

## Programming Interface

### Python API Usage
```python
from sqlinjector import SQLInjector

# Quick scan
injector = SQLInjector("http://example.com/vulnerable.php?id=1")
results = injector.quick_scan()

# Check for vulnerabilities
vulnerabilities = injector.get_vulnerabilities()
for vuln in vulnerabilities:
    print(f"Vulnerable parameter: {vuln.injection_point.parameter}")
    print(f"Injection type: {vuln.injection_type.value}")

# Cleanup
injector.cleanup()
```

### Advanced Configuration
```python
from sqlinjector.core.scanner import SQLIScanner
from sqlinjector.core.base import ScanConfig

# Custom configuration
config = ScanConfig(
    target_url="http://example.com/api",
    method="POST",
    headers={"Authorization": "Bearer token"},
    safe_mode=True,
    time_delay=3
)

scanner = SQLIScanner(config)
results = scanner.scan()
```

## Report Examples

### Vulnerability Summary
- **Total Tests**: 24
- **Vulnerable Parameters**: 3
- **Risk Level**: HIGH
- **Database Types**: MySQL 8.0, PostgreSQL 13

### Detailed Findings
1. **Parameter**: `user_id` (GET)
   - **Type**: Error-based SQL injection
   - **Database**: MySQL 8.0.25
   - **Payload**: `' OR 1=1--`
   - **Impact**: Full database access

## Safety and Ethics

### Built-in Safety Features
- **Authorization verification**: Interactive prompts before testing
- **Safe mode**: Disables destructive operations by default
- **Rate limiting**: Prevents accidental DoS
- **Comprehensive logging**: Full audit trail

### Ethical Usage Guidelines
1. **Only test systems you own or have written permission to test**
2. **Respect rate limits and avoid disrupting services**
3. **Report vulnerabilities responsibly**
4. **Use findings only for legitimate security improvement**

### Legal Considerations
- Unauthorized testing may violate laws in your jurisdiction
- Always obtain proper authorization before testing
- Consider responsible disclosure for any findings
- Document your authorization and testing scope

## Troubleshooting

### Common Issues

#### No Vulnerabilities Found
- Verify the target is actually vulnerable
- Try different tamper techniques
- Check for WAF interference
- Increase verbosity to see detailed testing

#### Connection Errors
- Verify target URL is accessible
- Check proxy configuration
- Adjust timeout settings
- Verify authentication credentials

#### False Positives
- Enable safe mode to reduce noise
- Use multiple verification rounds
- Cross-verify with manual testing
- Check response analysis thresholds

### Debug Mode
```bash
# Maximum verbosity
python sqlinjector.py -u "http://example.com/test" -vvv

# Enable request/response logging
python sqlinjector.py -u "http://example.com/test" --debug
```

## Contributing

We welcome contributions! Please see our contributing guidelines:

### Development Setup
```bash
# Clone and setup development environment
git clone https://github.com/your-repo/sqlinjector.git
cd sqlinjector
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Code formatting
black sqlinjector/
flake8 sqlinjector/
```

### Testing
- Unit tests for all modules
- Integration tests with DVWA/WebGoat
- Performance benchmarks
- Security testing of the tool itself

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- sqlmap project for inspiration on payload techniques
- OWASP for SQL injection testing methodology
- Security community for feedback and contributions

## Support

- **Documentation**: [Wiki](https://github.com/your-repo/sqlinjector/wiki)
- **Issues**: [GitHub Issues](https://github.com/your-repo/sqlinjector/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-repo/sqlinjector/discussions)

---

**Remember: This tool is for authorized security testing only. Always ensure you have proper permission before testing any system.**