#!/usr/bin/env python3
"""
Command-line interface for SQLInjector.
Provides easy-to-use CLI for SQL injection testing.
"""
import argparse
import asyncio
import sys
import json
from pathlib import Path
from typing import Dict, Any

from sqlinjector import SQLInjector, SQLIScanner
from sqlinjector.core.base import ScanConfig
from sqlinjector.utils.logger import get_logger, setup_logging


def create_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="SQLInjector - Advanced SQL Injection Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic GET parameter testing
  sqlinjector --url "http://example.com/page.php?id=1"
  
  # POST parameter testing with data
  sqlinjector --url "http://example.com/login.php" --method POST --data "username=admin&password=test"
  
  # JSON parameter testing
  sqlinjector --url "http://example.com/api/user" --method POST --json '{"id": 1, "name": "test"}'
  
  # Advanced testing with multiple techniques
  sqlinjector --url "http://example.com/page.php?id=1" --all-techniques --output-dir reports/
  
  # Safe mode testing (default)
  sqlinjector --url "http://example.com/page.php?id=1" --safe-mode
  
  # Configuration file
  sqlinjector --config config.yaml

⚠️  WARNING: Use only on systems you own or have explicit permission to test!
        """)
    
    # Target configuration
    target_group = parser.add_argument_group('Target Configuration')
    target_group.add_argument(
        '--url', '-u',
        help='Target URL to test'
    )
    target_group.add_argument(
        '--method', '-m',
        choices=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
        default='GET',
        help='HTTP method (default: GET)'
    )
    target_group.add_argument(
        '--data', '-d',
        help='POST data (form-encoded parameters)'
    )
    target_group.add_argument(
        '--json', '-j',
        help='JSON data for POST requests'
    )
    target_group.add_argument(
        '--headers', '-H',
        action='append',
        help='Custom headers (format: "Header: Value")'
    )
    target_group.add_argument(
        '--cookies', '-c',
        help='Cookies (format: "name1=value1;name2=value2")'
    )
    
    # Authentication
    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument(
        '--auth-basic',
        help='Basic authentication (format: "username:password")'
    )
    auth_group.add_argument(
        '--auth-bearer',
        help='Bearer token authentication'
    )
    
    # Testing configuration
    test_group = parser.add_argument_group('Testing Configuration')
    test_group.add_argument(
        '--parameter', '-p',
        help='Test specific parameter only'
    )
    test_group.add_argument(
        '--all-techniques',
        action='store_true',
        help='Use all available testing techniques'
    )
    test_group.add_argument(
        '--techniques',
        nargs='+',
        choices=['error', 'boolean', 'time', 'union'],
        help='Specific techniques to use'
    )
    test_group.add_argument(
        '--safe-mode',
        action='store_true',
        default=True,
        help='Enable safe mode (default, excludes destructive payloads)'
    )
    test_group.add_argument(
        '--no-safe-mode',
        action='store_true',
        help='Disable safe mode (WARNING: May cause data loss!)'
    )
    test_group.add_argument(
        '--timeout',
        type=int,
        default=30,
        help='Request timeout in seconds (default: 30)'
    )
    test_group.add_argument(
        '--delay',
        type=float,
        default=0.1,
        help='Delay between requests in seconds (default: 0.1)'
    )
    test_group.add_argument(
        '--time-delay',
        type=int,
        default=5,
        help='Time delay for time-based detection (default: 5)'
    )
    
    # Output configuration
    output_group = parser.add_argument_group('Output Configuration')
    output_group.add_argument(
        '--output-dir', '-o',
        default='reports',
        help='Output directory for reports (default: reports)'
    )
    output_group.add_argument(
        '--output-format',
        choices=['html', 'json', 'txt', 'all'],
        default='html',
        help='Report format (default: html)'
    )
    output_group.add_argument(
        '--verbose', '-v',
        action='count',
        default=0,
        help='Verbose output (-v for INFO, -vv for DEBUG)'
    )
    output_group.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Quiet mode (minimal output)'
    )
    
    # Advanced options
    advanced_group = parser.add_argument_group('Advanced Options')
    advanced_group.add_argument(
        '--config',
        help='Configuration file (YAML format)'
    )
    advanced_group.add_argument(
        '--session-dir',
        help='Session directory for persistence'
    )
    advanced_group.add_argument(
        '--proxy',
        help='Proxy URL (format: "http://proxy:port")'
    )
    advanced_group.add_argument(
        '--user-agent',
        default='SQLInjector/1.0',
        help='Custom User-Agent header'
    )
    
    return parser


def parse_headers(headers_list) -> Dict[str, str]:
    """Parse headers from command-line format."""
    headers = {}
    if headers_list:
        for header in headers_list:
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
    return headers


def parse_cookies(cookies_str) -> Dict[str, str]:
    """Parse cookies from command-line format."""
    cookies = {}
    if cookies_str:
        for cookie in cookies_str.split(';'):
            if '=' in cookie:
                key, value = cookie.split('=', 1)
                cookies[key.strip()] = value.strip()
    return cookies


def parse_data(data_str) -> Dict[str, Any]:
    """Parse POST data from command-line format."""
    data = {}
    if data_str:
        for param in data_str.split('&'):
            if '=' in param:
                key, value = param.split('=', 1)
                data[key.strip()] = value.strip()
    return data


def setup_logging_from_args(args):
    """Setup logging based on command-line arguments."""
    if args.quiet:
        level = 'WARNING'
    elif args.verbose >= 2:
        level = 'DEBUG'
    elif args.verbose >= 1:
        level = 'INFO'
    else:
        level = 'WARNING'
    
    setup_logging(level)


def create_config_from_args(args) -> ScanConfig:
    """Create ScanConfig from command-line arguments."""
    
    # Parse additional data
    headers = parse_headers(getattr(args, 'headers', None))
    cookies = parse_cookies(getattr(args, 'cookies', None))
    
    # Handle User-Agent
    if args.user_agent:
        headers['User-Agent'] = args.user_agent
    
    # Parse POST data
    data = {}
    if args.data:
        data.update(parse_data(args.data))
    
    if args.json:
        import json as json_lib
        try:
            json_data = json_lib.loads(args.json)
            data.update(json_data)
            headers['Content-Type'] = 'application/json'
        except json_lib.JSONDecodeError as e:
            print(f"Error parsing JSON data: {e}")
            sys.exit(1)
    
    # Handle authentication
    auth_data = {}
    if args.auth_basic:
        auth_data = {'type': 'basic', 'credentials': args.auth_basic}
    elif args.auth_bearer:
        auth_data = {'type': 'bearer', 'token': args.auth_bearer}
        headers['Authorization'] = f'Bearer {args.auth_bearer}'
    
    # Create configuration
    config = ScanConfig(
        target_url=args.url,
        method=args.method,
        headers=headers,
        cookies=cookies,
        data=data,
        auth_data=auth_data,
        proxy_url=getattr(args, 'proxy', None),
        request_timeout=args.timeout,
        delay_between_requests=args.delay,
        time_delay=args.time_delay,
        safe_mode=not args.no_safe_mode if args.no_safe_mode else args.safe_mode
    )
    
    return config


async def run_scan(config: ScanConfig, args) -> Dict[str, Any]:
    """Run the SQL injection scan."""
    logger = get_logger("cli")
    
    # Create session manager if session directory specified
    session_manager = None
    if hasattr(args, 'session_dir') and args.session_dir:
        from sqlinjector.core.session import SessionManager
        session_manager = SessionManager(config, args.session_dir)
    
    # Create and run scanner
    with SQLInjector(config, session_manager) as injector:
        logger.info(f"Starting scan on {config.target_url}")
        
        if hasattr(args, 'parameter') and args.parameter:
            # Test specific parameter
            results = injector.scan_parameter(args.parameter)
        else:
            # Full scan
            results = await injector.scan()
        
        # Generate report
        if results:
            report_path = injector.generate_report(
                args.output_dir, 
                args.output_format
            )
            logger.info(f"Report generated: {report_path}")
        
        # Get summary
        summary = injector.get_scan_summary()
        
        return {
            'results': results,
            'summary': summary,
            'report_path': report_path if results else None
        }


def print_summary(scan_results: Dict[str, Any]):
    """Print scan summary to console."""
    summary = scan_results['summary']
    
    print("\n" + "="*60)
    print(f"SQL INJECTION SCAN RESULTS")
    print("="*60)
    print(f"Target URL: {summary['target_url']}")
    print(f"Total Tests: {summary['total_tests']}")
    print(f"Vulnerabilities Found: {summary['vulnerable_count']}")
    print(f"Vulnerable Parameters: {summary['vulnerable_points']}")
    
    if summary['injection_types']:
        print(f"\nInjection Types Found:")
        for injection_type, count in summary['injection_types'].items():
            print(f"  - {injection_type}: {count}")
    
    if summary['database_types']:
        print(f"\nDatabase Types Detected:")
        for db_type, count in summary['database_types'].items():
            print(f"  - {db_type}: {count}")
    
    if summary['vulnerable_count'] > 0:
        print(f"\n⚠️  VULNERABILITIES FOUND! Review the detailed report.")
        print(f"Average Confidence: {summary['average_confidence']:.2f}")
    else:
        print(f"\n✅ No SQL injection vulnerabilities detected.")
    
    if scan_results.get('report_path'):
        print(f"\nDetailed report: {scan_results['report_path']}")
    
    print("="*60)


async def main():
    """Main CLI function."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Check for required arguments
    if not args.url and not args.config:
        parser.error("Either --url or --config is required")
    
    # Setup logging
    setup_logging_from_args(args)
    
    try:
        # Load configuration
        if args.config:
            # Load from config file
            injector = SQLInjector.create_from_config_file(args.config)
            config = injector.config
        else:
            # Create from command-line arguments
            config = create_config_from_args(args)
        
        # Validate authorization (if not in safe mode)
        if not config.safe_mode:
            from sqlinjector.core.base import SecurityValidator
            SecurityValidator.validate_safe_mode(config)
        
        # Run scan
        scan_results = await run_scan(config, args)
        
        # Print summary
        if not args.quiet:
            print_summary(scan_results)
        
        # Exit with appropriate code
        if scan_results['summary']['vulnerable_count'] > 0:
            sys.exit(1)  # Vulnerabilities found
        else:
            sys.exit(0)  # No vulnerabilities
            
    except KeyboardInterrupt:
        print("\n⚠️  Scan interrupted by user")
        sys.exit(2)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(3)


if __name__ == "__main__":
    asyncio.run(main())