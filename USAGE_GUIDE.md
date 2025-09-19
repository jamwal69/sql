# SQLInjector Usage Guide

## Quick Start

### Installation
```bash
git clone https://github.com/jamwal69/sql.git
cd sql
pip install -r requirements.txt
```

### Basic Usage

#### Command Line Interface

**Test a GET parameter:**
```bash
python -m sqlinjector --url "http://example.com/page.php?id=1"
```

**Test POST parameters:**
```bash
python -m sqlinjector --url "http://example.com/login.php" --method POST --data "username=admin&password=test"
```

**Test with JSON data:**
```bash
python -m sqlinjector --url "http://example.com/api/user" --method POST --json '{"id": 1, "name": "test"}'
```

**Advanced testing:**
```bash
python -m sqlinjector --url "http://example.com/page.php?id=1" --all-techniques --output-dir reports/ --verbose
```

#### Python API

**Basic scan:**
```python
import asyncio
from sqlinjector import SQLInjector
from sqlinjector.core.base import ScanConfig

async def scan_example():
    config = ScanConfig(
        target_url="http://example.com/page.php?id=1",
        safe_mode=True
    )
    
    with SQLInjector(config) as injector:
        results = await injector.scan()
        
        summary = injector.get_scan_summary()
        print(f"Found {summary['vulnerable_count']} vulnerabilities")
        
        # Generate report
        if summary['vulnerable_count'] > 0:
            report_path = injector.generate_report("reports/", "html")
            print(f"Report saved to: {report_path}")

# Run the scan
asyncio.run(scan_example())
```

**Quick scan function:**
```python
from sqlinjector import SQLInjector

# Simple one-liner scan
results = SQLInjector.quick_scan("http://example.com/page.php?id=1")

# Check for vulnerabilities
vulnerable_results = [r for r in results if r.vulnerable]
if vulnerable_results:
    print(f"Found {len(vulnerable_results)} vulnerabilities!")
```

**Test specific parameter:**
```python
config = ScanConfig(target_url="http://example.com/page.php?id=1&sort=name")

with SQLInjector(config) as injector:
    # Test only the 'id' parameter
    results = injector.scan_parameter("id")
    print(f"Parameter 'id' results: {len(results)}")
```

## Configuration Options

### ScanConfig Parameters

```python
config = ScanConfig(
    # Required
    target_url="http://example.com/page.php",
    
    # HTTP Configuration
    method="GET",                    # GET, POST, PUT, DELETE, PATCH
    headers={"Custom": "Header"},    # Custom headers
    cookies={"session": "value"},    # Cookies
    data={"param": "value"},         # POST data
    
    # Authentication
    auth_type="basic",               # basic, bearer, form
    auth_data={"username": "user", "password": "pass"},
    
    # Network Configuration
    proxy_url="http://proxy:8080",   # HTTP proxy
    request_timeout=30,              # Request timeout in seconds
    delay_between_requests=0.1,      # Delay between requests
    max_retries=3,                   # Max retry attempts
    
    # Testing Configuration
    test_get_params=True,            # Test GET parameters
    test_post_params=True,           # Test POST parameters
    test_headers=False,              # Test HTTP headers
    test_cookies=False,              # Test cookies
    test_json=True,                  # Test JSON parameters
    
    # Detection Settings
    time_delay=5,                    # Time delay for time-based injection
    boolean_rounds=3,                # Rounds for boolean-based testing
    
    # Safety Settings
    safe_mode=True,                  # Exclude destructive payloads
    destructive_tests=False,         # Allow destructive tests
    
    # Tamper Settings
    tamper_methods=[]                # Tamper techniques to use
)
```

## CLI Options

### Target Configuration
- `--url, -u`: Target URL to test
- `--method, -m`: HTTP method (GET, POST, PUT, DELETE, PATCH)
- `--data, -d`: POST data (form-encoded)
- `--json, -j`: JSON data for requests
- `--headers, -H`: Custom headers
- `--cookies, -c`: Cookies

### Authentication
- `--auth-basic`: Basic authentication ("username:password")
- `--auth-bearer`: Bearer token authentication

### Testing Configuration
- `--parameter, -p`: Test specific parameter only
- `--all-techniques`: Use all available techniques
- `--techniques`: Specific techniques (error, boolean, time, union)
- `--safe-mode`: Enable safe mode (default)
- `--no-safe-mode`: Disable safe mode (⚠️ WARNING)
- `--timeout`: Request timeout in seconds
- `--delay`: Delay between requests
- `--time-delay`: Time delay for time-based detection

### Output Configuration
- `--output-dir, -o`: Output directory for reports
- `--output-format`: Report format (html, json, txt, all)
- `--verbose, -v`: Verbose output
- `--quiet, -q`: Quiet mode

### Advanced Options
- `--config`: Configuration file (YAML)
- `--session-dir`: Session directory for persistence
- `--proxy`: Proxy URL
- `--user-agent`: Custom User-Agent

## Examples

### Testing Scenarios

**1. Basic GET Parameter Testing**
```bash
python -m sqlinjector --url "http://example.com/product.php?id=1"
```

**2. POST Form Testing**
```bash
python -m sqlinjector --url "http://example.com/login.php" \
  --method POST \
  --data "username=admin&password=test"
```

**3. JSON API Testing**
```bash
python -m sqlinjector --url "http://example.com/api/user" \
  --method POST \
  --json '{"id": 1, "name": "test"}' \
  --headers "Content-Type: application/json"
```

**4. Authenticated Testing**
```bash
python -m sqlinjector --url "http://example.com/admin/users.php?id=1" \
  --auth-basic "admin:password" \
  --verbose
```

**5. Advanced Testing with All Techniques**
```bash
python -m sqlinjector --url "http://example.com/page.php?id=1" \
  --all-techniques \
  --output-dir reports/ \
  --output-format all \
  --verbose
```

**6. Specific Parameter Testing**
```bash
python -m sqlinjector --url "http://example.com/search.php?q=test&category=1" \
  --parameter "category" \
  --techniques error boolean
```

**7. Testing with Proxy**
```bash
python -m sqlinjector --url "http://example.com/page.php?id=1" \
  --proxy "http://127.0.0.1:8080" \
  --verbose
```

### Python API Examples

**1. Comprehensive Scan with Session**
```python
import asyncio
from sqlinjector import SQLInjector
from sqlinjector.core.base import ScanConfig
from sqlinjector.core.session import SessionManager

async def comprehensive_scan():
    config = ScanConfig(
        target_url="http://example.com/app.php",
        method="GET",
        safe_mode=True,
        test_get_params=True,
        test_post_params=True
    )
    
    # Create session manager for persistence
    session_manager = SessionManager(config, "./scan_sessions")
    
    with SQLInjector(config, session_manager) as injector:
        results = await injector.scan()
        
        # Get summary
        summary = injector.get_scan_summary()
        print(f"Scan completed:")
        print(f"  Target: {summary['target_url']}")
        print(f"  Tests: {summary['total_tests']}")
        print(f"  Vulnerabilities: {summary['vulnerable_count']}")
        
        # Generate reports
        if summary['vulnerable_count'] > 0:
            html_report = injector.generate_report("reports/", "html")
            print(f"  HTML Report: {html_report}")
            
            # Export session data
            injector.export_session_data("scan_data.json")
            print(f"  Session data exported to scan_data.json")

asyncio.run(comprehensive_scan())
```

**2. Custom Configuration from File**
```python
# config.yaml
target_url: "http://example.com/page.php?id=1"
method: "GET"
safe_mode: true
request_timeout: 30
delay_between_requests: 0.5
test_get_params: true
test_post_params: false

# Python code
from sqlinjector import SQLInjector

injector = SQLInjector.create_from_config_file("config.yaml")
results = asyncio.run(injector.scan())
```

**3. Vulnerability Analysis**
```python
import asyncio
from sqlinjector import SQLInjector
from sqlinjector.core.base import ScanConfig

async def analyze_vulnerabilities():
    config = ScanConfig(target_url="http://example.com/page.php?id=1")
    
    with SQLInjector(config) as injector:
        results = await injector.scan()
        
        # Analyze results
        for result in injector.get_vulnerable_results():
            print(f"\n🚨 Vulnerability Found:")
            print(f"  Parameter: {result.injection_point.parameter}")
            print(f"  Type: {result.injection_type.value}")
            print(f"  Payload: {result.payload}")
            print(f"  Confidence: High" if result.vulnerable else "Low")
            
            if result.db_type:
                print(f"  Database: {result.db_type.value}")
            
            if result.error_message:
                print(f"  Error: {result.error_message}")

asyncio.run(analyze_vulnerabilities())
```

## Safety and Legal Considerations

### ⚠️ Important Warnings

1. **Authorization Required**: Only use this tool on systems you own or have explicit written permission to test.

2. **Safe Mode**: Always use safe mode (`--safe-mode`) unless you specifically need destructive testing and understand the risks.

3. **Legal Compliance**: Ensure your testing complies with local laws and regulations.

4. **Responsible Disclosure**: If you find vulnerabilities, follow responsible disclosure practices.

### Safe Mode Features

- Excludes destructive payloads (DROP, DELETE, etc.)
- Limits request frequency
- Provides warnings for dangerous operations
- Includes authorization checks

### Best Practices

1. **Start with Safe Mode**: Always begin testing with safe mode enabled
2. **Use Test Environments**: Prefer testing on dedicated test environments
3. **Monitor Impact**: Watch for any negative impact on target systems
4. **Document Findings**: Keep detailed records of vulnerabilities found
5. **Report Responsibly**: Follow responsible disclosure guidelines

## Troubleshooting

### Common Issues

**1. Import Errors**
```bash
# Install required dependencies
pip install -r requirements.txt

# For AI features (optional)
pip install -r requirements-ai.txt

# For database connectors (optional)
pip install -r requirements-db.txt
```

**2. Network Issues**
```bash
# Test with increased timeout
python -m sqlinjector --url "http://example.com/page.php?id=1" --timeout 60

# Use proxy for debugging
python -m sqlinjector --url "http://example.com/page.php?id=1" --proxy "http://127.0.0.1:8080"
```

**3. Permission Issues**
```bash
# Check target is accessible
curl -I "http://example.com/page.php?id=1"

# Verify you have permission to test the target
```

**4. No Vulnerabilities Found**
- Verify the target actually has SQL injection vulnerabilities
- Try different techniques: `--all-techniques`
- Increase verbosity: `--verbose` or `--verbose --verbose`
- Check if WAF/security measures are blocking requests

### Getting Help

1. Check the verbose output: `--verbose`
2. Review the generated reports for detailed analysis
3. Check session data for debugging: `--session-dir`
4. Consult the source code for advanced usage

## Advanced Features

### Session Management
- Persistent storage of scan results
- Resume interrupted scans
- Export/import scan data

### Reporting
- HTML reports with detailed analysis
- JSON output for programmatic processing
- Text reports for quick review

### Extensibility
- Custom payload integration
- Tamper technique support
- Plugin architecture for advanced features

This tool represents a comprehensive approach to SQL injection testing with emphasis on safety, accuracy, and usability.