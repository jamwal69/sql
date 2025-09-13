# Quick Start Scripts

## Windows PowerShell Scripts

### setup.ps1 - Environment setup
```powershell
# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .

Write-Host "SQLInjector setup completed!" -ForegroundColor Green
Write-Host "Run: sqlinjector --help" -ForegroundColor Yellow
```

### test.ps1 - Run tests
```powershell
# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Run tests
pytest tests/ -v --cov=sqlinjector

Write-Host "Tests completed!" -ForegroundColor Green
```

### quick-scan.ps1 - Quick vulnerability scan
```powershell
param(
    [Parameter(Mandatory=$true)]
    [string]$Url,
    [string]$OutputFile = "results.json"
)

.\venv\Scripts\Activate.ps1

Write-Host "Starting SQL injection scan..." -ForegroundColor Yellow
sqlinjector -u $Url --safe-mode --format json --output $OutputFile

Write-Host "Scan completed! Results saved to $OutputFile" -ForegroundColor Green
```

## Linux/macOS Shell Scripts

### setup.sh - Environment setup
```bash
#!/bin/bash
set -e

echo "Setting up SQLInjector environment..."

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .

echo "SQLInjector setup completed!"
echo "Run: sqlinjector --help"
```

### test.sh - Run tests
```bash
#!/bin/bash
set -e

# Activate virtual environment
source venv/bin/activate

# Run tests
pytest tests/ -v --cov=sqlinjector

echo "Tests completed!"
```

### quick-scan.sh - Quick vulnerability scan
```bash
#!/bin/bash

if [ $# -eq 0 ]; then
    echo "Usage: $0 <URL> [output_file]"
    exit 1
fi

URL=$1
OUTPUT_FILE=${2:-"results.json"}

source venv/bin/activate

echo "Starting SQL injection scan..."
sqlinjector -u "$URL" --safe-mode --format json --output "$OUTPUT_FILE"

echo "Scan completed! Results saved to $OUTPUT_FILE"
```

## Docker Quick Start

### docker-run.sh - Run with Docker
```bash
#!/bin/bash

# Build image
docker build -t sqlinjector .

# Run container
docker run --rm -v $(pwd)/results:/app/results sqlinjector "$@"
```

### docker-compose-start.sh - Start full environment
```bash
#!/bin/bash

# Start all services
docker-compose up -d

echo "Services started:"
echo "- Target app: http://localhost:8080"
echo "- Report server: http://localhost:8090"

# Wait for services to be ready
sleep 10

# Run example scan
docker-compose exec sqlinjector sqlinjector \
    -u "http://target-app/vulnerabilities/sqli/?id=1&Submit=Submit" \
    --safe-mode \
    --format html \
    --output /app/results/example-scan.html

echo "Example scan completed!"
```

## Usage Examples

### Basic Scans
```bash
# Simple GET parameter test
sqlinjector -u "http://example.com/page.php?id=1"

# POST data test
sqlinjector -u "http://example.com/login.php" \
    --data "username=admin&password=test" \
    --method POST

# Test with authentication
sqlinjector -u "http://example.com/protected.php?id=1" \
    --cookies "session=abc123; auth=token"
```

### Advanced Scans
```bash
# Comprehensive scan with all techniques
sqlinjector -u "http://example.com/page.php?id=1" \
    --techniques "error,boolean,time,union" \
    --level 5 \
    --risk 3 \
    --tamper "space2comment,randomcase"

# Scan through proxy (Burp Suite)
sqlinjector -u "http://example.com/page.php?id=1" \
    --proxy "http://127.0.0.1:8080" \
    --headers '{"User-Agent": "Custom Agent"}'

# Batch testing from file
sqlinjector --url-file targets.txt \
    --output-dir batch_results/ \
    --threads 5
```

### Reporting and Analysis
```bash
# Generate detailed HTML report
sqlinjector -u "http://example.com/page.php?id=1" \
    --format html \
    --output detailed_report.html \
    --include-requests \
    --include-responses

# Export to CSV for analysis
sqlinjector -u "http://example.com/page.php?id=1" \
    --format csv \
    --output analysis.csv

# Resume previous session
sqlinjector --resume session_20231201_143022.db
```

## Troubleshooting Scripts

### check-deps.py - Verify dependencies
```python
#!/usr/bin/env python3
import importlib
import sys

required_modules = [
    'httpx', 'requests', 'lxml', 'bs4', 'click', 
    'colorama', 'jinja2', 'yaml'
]

print("Checking dependencies...")
missing = []

for module in required_modules:
    try:
        importlib.import_module(module)
        print(f"✓ {module}")
    except ImportError:
        print(f"✗ {module} - MISSING")
        missing.append(module)

if missing:
    print(f"\nMissing modules: {', '.join(missing)}")
    print("Run: pip install -r requirements.txt")
    sys.exit(1)
else:
    print("\n✓ All dependencies satisfied!")
```

### validate-config.py - Validate configuration
```python
#!/usr/bin/env python3
import sys
import yaml
from pathlib import Path

def validate_config(config_file):
    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
        
        # Validate required sections
        required_sections = ['http', 'detection', 'payloads', 'safety', 'output']
        for section in required_sections:
            if section not in config:
                print(f"✗ Missing section: {section}")
                return False
            else:
                print(f"✓ Section: {section}")
        
        print("✓ Configuration is valid!")
        return True
    
    except Exception as e:
        print(f"✗ Configuration error: {e}")
        return False

if __name__ == "__main__":
    config_file = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    
    if not Path(config_file).exists():
        print(f"✗ Config file not found: {config_file}")
        sys.exit(1)
    
    if validate_config(config_file):
        sys.exit(0)
    else:
        sys.exit(1)
```

## Performance Optimization

### optimize-scan.sh - Optimized scanning
```bash
#!/bin/bash

URL=$1
if [ -z "$URL" ]; then
    echo "Usage: $0 <URL>"
    exit 1
fi

echo "Running optimized SQL injection scan..."

# Start with lightweight detection
sqlinjector -u "$URL" \
    --techniques "error" \
    --level 1 \
    --risk 1 \
    --max-payloads 10 \
    --timeout 10 \
    --format json \
    --output quick_scan.json

# If vulnerabilities found, run detailed scan
if grep -q '"vulnerable": true' quick_scan.json 2>/dev/null; then
    echo "Vulnerabilities detected! Running detailed scan..."
    
    sqlinjector -u "$URL" \
        --techniques "error,boolean,time,union" \
        --level 3 \
        --risk 2 \
        --tamper "space2comment" \
        --format html \
        --output detailed_scan.html
        
    echo "Detailed scan completed: detailed_scan.html"
else
    echo "No obvious vulnerabilities detected."
fi
```

## Maintenance Scripts

### cleanup.sh - Clean temporary files
```bash
#!/bin/bash

echo "Cleaning up SQLInjector temporary files..."

# Remove session files older than 7 days
find . -name "session_*.db" -mtime +7 -delete

# Remove old log files
find . -name "*.log" -mtime +30 -delete

# Remove temporary reports
rm -f temp_*.html temp_*.json temp_*.csv

# Clean Python cache
find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find . -name "*.pyc" -delete

echo "Cleanup completed!"
```

### update.sh - Update tool and dependencies
```bash
#!/bin/bash

echo "Updating SQLInjector..."

# Activate virtual environment
source venv/bin/activate

# Update pip
pip install --upgrade pip

# Update dependencies
pip install --upgrade -r requirements.txt

# Reinstall package in development mode
pip install -e .

echo "Update completed!"
echo "Current version:"
sqlinjector --version
```

Save these scripts to a `scripts/` directory and make them executable with `chmod +x` on Linux/macOS.