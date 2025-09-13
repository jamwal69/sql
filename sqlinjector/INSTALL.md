# SQLInjector Installation and Usage Guide

## Table of Contents
- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Advanced Configuration](#advanced-configuration)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [Safety Guidelines](#safety-guidelines)

## Installation

### Using pip (Recommended)

```bash
# Install from source
git clone https://github.com/your-repo/sqlinjector.git
cd sqlinjector
pip install -e .

# Or install from PyPI (when available)
pip install sqlinjector
```

### Manual Installation

```bash
# Clone repository
git clone https://github.com/your-repo/sqlinjector.git
cd sqlinjector

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies (optional)
pip install -e .[dev]
```

### Docker Installation

```bash
# Build image
docker build -t sqlinjector .

# Run container
docker run -it sqlinjector --help
```

## Basic Usage

### Quick Start

```bash
# Basic scan
sqlinjector -u "http://example.com/page.php?id=1"

# Scan with output file
sqlinjector -u "http://example.com/page.php?id=1" -o results.json

# Scan multiple parameters
sqlinjector -u "http://example.com/page.php" --data "id=1&name=test"
```

### Command Line Options

```bash
sqlinjector --help
```

Key options:
- `-u, --url`: Target URL
- `--data`: POST data
- `--cookies`: Cookies string
- `--headers`: Custom headers (JSON format)
- `--proxy`: HTTP proxy
- `--timeout`: Request timeout
- `--delay`: Delay between requests
- `-o, --output`: Output file
- `--format`: Output format (json/html/csv)
- `--safe-mode`: Enable safe mode
- `--resume`: Resume from session

## Advanced Configuration

### Configuration File

Create `config.yaml`:

```yaml
# HTTP Settings
http:
  timeout: 30
  delay: 1
  user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
  max_redirects: 5
  verify_ssl: true

# Detection Settings
detection:
  error_patterns: true
  boolean_logic: true
  time_based: true
  union_based: true
  time_delay: 5

# Payload Settings
payloads:
  max_payloads: 50
  tamper_techniques: ["space2comment", "randomcase", "charencode"]
  custom_payloads: []

# Safety Settings
safety:
  safe_mode: true
  max_requests: 1000
  whitelist_domains: ["example.com"]
  blacklist_patterns: ["DROP", "DELETE", "UPDATE"]

# Output Settings
output:
  format: "json"
  include_requests: false
  include_responses: false
  verbosity: "info"
```

Use configuration:
```bash
sqlinjector --config config.yaml -u "http://example.com/page.php?id=1"
```

### Environment Variables

```bash
export SQLINJECTOR_PROXY="http://localhost:8080"
export SQLINJECTOR_USER_AGENT="Custom User Agent"
export SQLINJECTOR_TIMEOUT="60"
export SQLINJECTOR_SAFE_MODE="true"
```

## Examples

### Basic Web Application Testing

```bash
# Test GET parameter
sqlinjector -u "http://testsite.com/products.php?id=1"

# Test POST data
sqlinjector -u "http://testsite.com/login.php" \
  --data "username=admin&password=test" \
  --method POST

# Test with cookies
sqlinjector -u "http://testsite.com/profile.php?id=1" \
  --cookies "session=abc123; user=admin"
```

### Advanced Testing Scenarios

```bash
# Test with custom headers
sqlinjector -u "http://api.example.com/users/1" \
  --headers '{"Authorization": "Bearer token123", "Content-Type": "application/json"}'

# Test through proxy (Burp Suite)
sqlinjector -u "http://example.com/page.php?id=1" \
  --proxy "http://127.0.0.1:8080"

# Test with specific techniques only
sqlinjector -u "http://example.com/page.php?id=1" \
  --techniques "error,boolean" \
  --dbms "mysql"

# Aggressive testing with tampering
sqlinjector -u "http://example.com/page.php?id=1" \
  --tamper "space2comment,randomcase,charencode" \
  --level 5 \
  --risk 3
```

### Session Management

```bash
# Save session for later resumption
sqlinjector -u "http://example.com/page.php?id=1" \
  --session-file "test_session.db"

# Resume previous session
sqlinjector --resume "test_session.db"

# List saved sessions
sqlinjector --list-sessions
```

### Output and Reporting

```bash
# Generate HTML report
sqlinjector -u "http://example.com/page.php?id=1" \
  --format html \
  --output report.html

# Generate detailed JSON output
sqlinjector -u "http://example.com/page.php?id=1" \
  --format json \
  --output results.json \
  --include-requests \
  --include-responses

# Generate CSV for analysis
sqlinjector -u "http://example.com/page.php?id=1" \
  --format csv \
  --output findings.csv
```

### Bulk Testing

```bash
# Test multiple URLs from file
sqlinjector --url-file urls.txt \
  --output-dir results/ \
  --threads 5

# Test with parameter discovery
sqlinjector -u "http://example.com/page.php" \
  --discover-params \
  --wordlist params.txt
```

## Troubleshooting

### Common Issues

#### Connection Problems
```bash
# Test with verbose output
sqlinjector -u "http://example.com/page.php?id=1" --verbose

# Test with longer timeout
sqlinjector -u "http://example.com/page.php?id=1" --timeout 60

# Disable SSL verification
sqlinjector -u "https://example.com/page.php?id=1" --no-verify-ssl
```

#### False Positives
```bash
# Use safe mode
sqlinjector -u "http://example.com/page.php?id=1" --safe-mode

# Reduce testing intensity
sqlinjector -u "http://example.com/page.php?id=1" --level 1 --risk 1

# Filter specific techniques
sqlinjector -u "http://example.com/page.php?id=1" --skip-techniques "time"
```

#### Performance Issues
```bash
# Reduce delay and threads
sqlinjector -u "http://example.com/page.php?id=1" --delay 0.5 --threads 10

# Limit payload count
sqlinjector -u "http://example.com/page.php?id=1" --max-payloads 20
```

### Debug Mode

```bash
# Enable debug logging
sqlinjector -u "http://example.com/page.php?id=1" --debug

# Save debug logs
sqlinjector -u "http://example.com/page.php?id=1" --log-file debug.log
```

### Memory and Performance

```bash
# Monitor resource usage
sqlinjector -u "http://example.com/page.php?id=1" --monitor-resources

# Limit memory usage
sqlinjector -u "http://example.com/page.php?id=1" --max-memory 1GB
```

## Safety Guidelines

### Legal and Ethical Use

⚠️ **IMPORTANT**: This tool is for authorized testing only!

1. **Authorization Required**: Only test systems you own or have explicit permission to test
2. **Responsible Disclosure**: Report findings responsibly to system owners
3. **Legal Compliance**: Ensure testing complies with local laws and regulations
4. **Documentation**: Keep records of authorization and testing scope

### Safe Testing Practices

```bash
# Always use safe mode for initial testing
sqlinjector -u "http://example.com/page.php?id=1" --safe-mode

# Limit request rate to avoid DoS
sqlinjector -u "http://example.com/page.php?id=1" --delay 2 --max-requests 100

# Use read-only techniques first
sqlinjector -u "http://example.com/page.php?id=1" --techniques "error,boolean"

# Test in isolated environment
sqlinjector -u "http://testlab.local/page.php?id=1"
```

### Data Protection

```bash
# Avoid extracting sensitive data
sqlinjector -u "http://example.com/page.php?id=1" --no-extract-data

# Limit data extraction
sqlinjector -u "http://example.com/page.php?id=1" --extract-limit 10

# Hash sensitive output
sqlinjector -u "http://example.com/page.php?id=1" --hash-sensitive
```

### Reporting Security

- Encrypt sensitive reports
- Use secure channels for communication
- Follow responsible disclosure timelines
- Provide clear reproduction steps
- Include risk ratings and impact assessments

## Getting Help

### Documentation
- [API Documentation](docs/api.md)
- [Payload Reference](docs/payloads.md)
- [Technique Guide](docs/techniques.md)

### Support
- GitHub Issues: [Report bugs](https://github.com/your-repo/sqlinjector/issues)
- Discussions: [Community support](https://github.com/your-repo/sqlinjector/discussions)
- Security: [Report security issues](security@example.com)

### Contributing
- [Contributing Guide](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Development Setup](docs/development.md)

---

**Remember**: Use this tool responsibly and only on systems you're authorized to test!