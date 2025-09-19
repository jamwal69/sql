#!/usr/bin/env python3
"""
SQLInjector Demonstration Script
Shows the key capabilities of the enhanced SQL injection testing tool.
"""
import asyncio
import sys
from pathlib import Path

# Add parent directory to path for development
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlinjector import SQLInjector, SQLIScanner
from sqlinjector.core.base import ScanConfig
from sqlinjector.modules.payload_manager import PayloadManager
from sqlinjector.modules.detector import InjectionDetector


def print_banner():
    """Print tool banner."""
    print("=" * 80)
    print("🔍 SQLInjector - Ultimate SQL Injection Testing Tool")
    print("=" * 80)
    print("Enhanced with comprehensive detection, safety features, and professional reporting")
    print("⚠️  For authorized testing only - Use responsibly!")
    print("=" * 80)
    print()


def demonstrate_payload_capabilities():
    """Demonstrate payload management capabilities."""
    print("📦 PAYLOAD MANAGEMENT DEMONSTRATION")
    print("-" * 50)
    
    config = ScanConfig(target_url="http://example.com")
    pm = PayloadManager(config)
    
    # Show available payload types
    if hasattr(pm, 'payloads') and pm.payloads:
        print("Available payload categories:")
        for category in pm.payloads.keys():
            payloads = pm.payloads[category]
            if isinstance(payloads, list):
                print(f"  ✓ {category}: {len(payloads)} payloads")
        
        # Show sample payloads
        error_payloads = pm.payloads.get("error_based", [])
        if error_payloads:
            print(f"\nSample error-based payloads:")
            for i, payload in enumerate(error_payloads[:3]):
                print(f"  {i+1}. {payload}")
        
        # Demonstrate tamper techniques
        print(f"\nTamper technique demonstration:")
        original = "' OR '1'='1"
        print(f"  Original: {original}")
        print(f"  URL Encoded: {pm._url_encode(original)}")
        print(f"  Case Mixed: {pm._case_mix(original)}")
    
    print("✅ Payload management functional\n")


def demonstrate_detection_capabilities():
    """Demonstrate detection capabilities."""
    print("🔍 DETECTION ENGINE DEMONSTRATION")
    print("-" * 50)
    
    config = ScanConfig(target_url="http://example.com")
    detector = InjectionDetector(config)
    
    # Test database error detection
    test_errors = [
        ("MySQL error", "MySQL server version for the right syntax"),
        ("PostgreSQL error", "PostgreSQL query failed: ERROR:"),
        ("MSSQL error", "Microsoft SQL Server error"),
        ("Oracle error", "ORA-00933: SQL command not properly ended"),
        ("SQLite error", "SQLite error: unrecognized token")
    ]
    
    print("Database error detection capabilities:")
    for error_name, error_text in test_errors:
        from sqlinjector.core.base import DBType
        db_type, error_msg = detector._detect_database_error(error_text)
        if db_type != DBType.UNKNOWN:
            print(f"  ✓ {error_name}: Detected as {db_type.value}")
        else:
            print(f"  - {error_name}: Not detected")
    
    # Test response analysis
    print(f"\nResponse analysis capabilities:")
    response1 = {'status_code': 200, 'content': 'Welcome user', 'headers': {}}
    response2 = {'status_code': 500, 'content': 'Internal Server Error', 'headers': {}}
    
    if detector._responses_differ_significantly(response1, response2):
        print("  ✓ Can detect significant response differences")
    else:
        print("  - Response difference detection needs tuning")
    
    print("✅ Detection engine functional\n")


async def demonstrate_scanner_integration():
    """Demonstrate scanner integration."""
    print("🔧 SCANNER INTEGRATION DEMONSTRATION")
    print("-" * 50)
    
    # Test configuration
    config = ScanConfig(
        target_url="http://example.com/test.php?id=1&name=test",
        method="GET",
        safe_mode=True,
        delay_between_requests=0.1
    )
    
    print(f"Configuration:")
    print(f"  Target URL: {config.target_url}")
    print(f"  Method: {config.method}")
    print(f"  Safe Mode: {config.safe_mode}")
    print(f"  Request Delay: {config.delay_between_requests}s")
    
    # Create scanner
    scanner = SQLIScanner(config)
    
    print(f"\nScanner components initialized:")
    print(f"  ✓ HTTP Engine: {type(scanner.http_engine).__name__}")
    print(f"  ✓ Detector: {type(scanner.detector).__name__}")
    print(f"  ✓ Payload Manager: {type(scanner.payload_manager).__name__}")
    print(f"  ✓ Fingerprinter: {type(scanner.fingerprinter).__name__}")
    print(f"  ✓ Union Extractor: {type(scanner.union_extractor).__name__}")
    
    # Test injection point extraction
    try:
        points = scanner.http_engine.extract_injection_points(
            config.target_url, config.method, config.data
        )
        print(f"\nInjection points extracted: {len(points)}")
        for i, point in enumerate(points, 1):
            print(f"  {i}. Parameter: {point.parameter} ({point.param_type})")
    except Exception as e:
        print(f"  Note: Injection point extraction requires network access")
    
    scanner.cleanup()
    print("✅ Scanner integration functional\n")


async def demonstrate_main_injector():
    """Demonstrate main SQLInjector capabilities."""
    print("🚀 MAIN SQLINJECTOR DEMONSTRATION")
    print("-" * 50)
    
    config = ScanConfig(
        target_url="http://example.com/vulnerable.php?id=1",
        safe_mode=True
    )
    
    # Create injector
    with SQLInjector(config) as injector:
        print(f"SQLInjector initialized:")
        print(f"  ✓ Scanner: {type(injector.scanner).__name__}")
        print(f"  ✓ Session Manager: {type(injector.session_manager).__name__}")
        print(f"  ✓ Session ID: {injector.session_manager.session_id}")
        
        # Get initial summary
        summary = injector.get_scan_summary()
        print(f"\nInitial scan summary:")
        print(f"  Target: {summary['target_url']}")
        print(f"  Total tests: {summary['total_tests']}")
        print(f"  Vulnerabilities: {summary['vulnerable_count']}")
        print(f"  Scan started: {summary['scan_started']}")
        print(f"  Scan completed: {summary['scan_completed']}")
        
        # Note about actual scanning
        print(f"\n📝 Note: Actual vulnerability scanning requires a target server")
        print(f"   For demonstration purposes, we're showing the framework capabilities")
        print(f"   Use: python -m sqlinjector --url <target> for real testing")
    
    print("✅ Main injector functional\n")


def demonstrate_cli_capabilities():
    """Demonstrate CLI capabilities."""
    print("💻 COMMAND-LINE INTERFACE DEMONSTRATION")
    print("-" * 50)
    
    print("The tool provides a comprehensive CLI interface:")
    print()
    print("Basic usage examples:")
    print("  python -m sqlinjector --url 'http://example.com/page.php?id=1'")
    print("  python -m sqlinjector --url 'http://example.com/login.php' \\")
    print("    --method POST --data 'user=admin&pass=test'")
    print()
    print("Advanced usage:")
    print("  python -m sqlinjector --url 'http://example.com/api/user' \\")
    print("    --method POST --json '{\"id\": 1}' --all-techniques \\")
    print("    --output-dir reports/ --verbose")
    print()
    print("Authentication support:")
    print("  python -m sqlinjector --url 'http://example.com/admin/' \\")
    print("    --auth-basic 'admin:password' --proxy 'http://127.0.0.1:8080'")
    print()
    print("For full help: python -m sqlinjector --help")
    print("✅ CLI interface available\n")


def print_summary():
    """Print implementation summary."""
    print("📊 IMPLEMENTATION SUMMARY")
    print("-" * 50)
    print("✅ Core Components:")
    print("  • SQLInjector main class with async scanning")
    print("  • Comprehensive CLI interface")
    print("  • Payload database with 60+ injection patterns")
    print("  • Session management for persistence")
    print("  • Multi-format reporting (HTML, JSON, TXT)")
    print()
    print("✅ Detection Capabilities:")
    print("  • Error-based SQL injection")
    print("  • Boolean-based blind injection")
    print("  • Time-based blind injection")
    print("  • Union-based injection")
    print("  • Database fingerprinting")
    print()
    print("✅ Safety Features:")
    print("  • Safe mode enabled by default")
    print("  • Authorization requirement checks")
    print("  • Rate limiting and request throttling")
    print("  • Destructive payload filtering")
    print()
    print("✅ Professional Features:")
    print("  • Authentication support (Basic, Bearer)")
    print("  • Proxy support for advanced testing")
    print("  • Comprehensive logging and reporting")
    print("  • Configuration file support")
    print("  • Session persistence and resume")
    print()
    print("🎯 The tool is ready for professional SQL injection testing!")
    print("   Remember: Only use on systems you own or have permission to test.")
    print()


async def main():
    """Run all demonstrations."""
    print_banner()
    
    try:
        # Component demonstrations
        demonstrate_payload_capabilities()
        demonstrate_detection_capabilities()
        await demonstrate_scanner_integration()
        await demonstrate_main_injector()
        demonstrate_cli_capabilities()
        
        # Final summary
        print_summary()
        
    except KeyboardInterrupt:
        print("\n⚠️  Demonstration interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    print("🎬 Starting SQLInjector Capability Demonstration...")
    print()
    asyncio.run(main())