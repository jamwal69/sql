#!/usr/bin/env python3
"""
SQLInjector - Main CLI Entry Point

A comprehensive SQL injection testing tool for penetration testing.
Use only on systems you are authorized to test.
"""

import sys
import os
import argparse
import logging
from pathlib import Path

# Add the package to the path
sys.path.insert(0, str(Path(__file__).parent))

from sqlinjector.core.base import ScanConfig, SecurityValidator, SecurityError
from sqlinjector.core.scanner import SQLIScanner
from sqlinjector.utils.logger import setup_logging


def create_parser():
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="SQLInjector - Advanced SQL Injection Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sqlinjector.py -u "http://example.com/login.php" -p "username"
  python sqlinjector.py -u "http://example.com/api/user" -m POST --data '{"id": "1"}'
  python sqlinjector.py -u "http://example.com/search" -p "q" --tamper url_encode,hex_encode
  python sqlinjector.py -u "http://example.com/app" --crawl --scope "example.com"

WARNING: Use only on systems you are authorized to test!
        """
    )
    
    # Target configuration
    target_group = parser.add_argument_group('Target Configuration')
    target_group.add_argument('-u', '--url', required=True,
                            help='Target URL to test')
    target_group.add_argument('-m', '--method', default='GET',
                            choices=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
                            help='HTTP method to use (default: GET)')
    target_group.add_argument('-p', '--parameter',
                            help='Specific parameter to test')
    target_group.add_argument('--data',
                            help='POST data (JSON string or key=value pairs)')
    target_group.add_argument('--headers',
                            help='Custom headers (JSON string or key:value pairs)')
    target_group.add_argument('--cookies',
                            help='Cookies to send (JSON string or key=value pairs)')
    
    # Authentication
    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument('--auth-type',
                          choices=['basic', 'bearer', 'form'],
                          help='Authentication type')
    auth_group.add_argument('--auth-data',
                          help='Authentication data (username:password for basic, token for bearer)')
    
    # Proxy configuration
    proxy_group = parser.add_argument_group('Proxy Configuration')
    proxy_group.add_argument('--proxy',
                           help='Proxy URL (http://proxy:port)')
    
    # Test configuration
    test_group = parser.add_argument_group('Test Configuration')
    test_group.add_argument('--test-get', action='store_true', default=True,
                          help='Test GET parameters (default: True)')
    test_group.add_argument('--test-post', action='store_true', default=True,
                          help='Test POST parameters (default: True)')
    test_group.add_argument('--test-headers', action='store_true',
                          help='Test HTTP headers')
    test_group.add_argument('--test-cookies', action='store_true',
                          help='Test cookies')
    test_group.add_argument('--test-json', action='store_true', default=True,
                          help='Test JSON parameters (default: True)')
    
    # Timing and performance
    timing_group = parser.add_argument_group('Timing and Performance')
    timing_group.add_argument('--timeout', type=int, default=30,
                            help='Request timeout in seconds (default: 30)')
    timing_group.add_argument('--delay', type=float, default=0.1,
                            help='Delay between requests in seconds (default: 0.1)')
    timing_group.add_argument('--retries', type=int, default=3,
                            help='Maximum retries per request (default: 3)')
    timing_group.add_argument('--threads', type=int, default=1,
                            help='Number of concurrent threads (default: 1)')
    
    # Detection settings
    detection_group = parser.add_argument_group('Detection Settings')
    detection_group.add_argument('--time-delay', type=int, default=5,
                               help='Time delay for time-based detection (default: 5)')
    detection_group.add_argument('--boolean-rounds', type=int, default=3,
                               help='Number of boolean test rounds (default: 3)')
    
    # Tamper and evasion
    tamper_group = parser.add_argument_group('Tamper and Evasion')
    tamper_group.add_argument('--tamper',
                            help='Tamper methods (comma-separated): url_encode,hex_encode,html_entity,xml_entity,comment_split,case_mix,concat_split')
    
    # Safety and ethics
    safety_group = parser.add_argument_group('Safety and Ethics')
    safety_group.add_argument('--no-safe-mode', action='store_true',
                            help='Disable safe mode (allows potentially destructive tests)')
    safety_group.add_argument('--destructive', action='store_true',
                            help='Enable destructive tests (USE WITH EXTREME CAUTION)')
    safety_group.add_argument('--force', action='store_true',
                            help='Skip authorization prompt (not recommended)')
    
    # Output and reporting
    output_group = parser.add_argument_group('Output and Reporting')
    output_group.add_argument('-o', '--output',
                            help='Output directory for reports')
    output_group.add_argument('--format',
                            choices=['json', 'html', 'both'], default='both',
                            help='Report format (default: both)')
    output_group.add_argument('-v', '--verbose', action='count', default=0,
                            help='Increase verbosity (-v, -vv, -vvv)')
    output_group.add_argument('--quiet', action='store_true',
                            help='Suppress non-essential output')
    
    # Advanced features
    advanced_group = parser.add_argument_group('Advanced Features')
    advanced_group.add_argument('--crawl', action='store_true',
                              help='Crawl the target to find injection points')
    advanced_group.add_argument('--scope',
                              help='Scope for crawling (domain or URL pattern)')
    advanced_group.add_argument('--config',
                              help='Load configuration from file')
    advanced_group.add_argument('--resume',
                              help='Resume from saved session')
    
    return parser


def parse_data_string(data_str):
    """Parse data string into dictionary."""
    if not data_str:
        return {}
    
    # Try to parse as JSON first
    try:
        import json
        return json.loads(data_str)
    except json.JSONDecodeError:
        pass
    
    # Parse as key=value pairs
    result = {}
    for pair in data_str.split('&'):
        if '=' in pair:
            key, value = pair.split('=', 1)
            result[key] = value
    return result


def parse_headers_string(headers_str):
    """Parse headers string into dictionary."""
    if not headers_str:
        return {}
    
    # Try to parse as JSON first
    try:
        import json
        return json.loads(headers_str)
    except json.JSONDecodeError:
        pass
    
    # Parse as key:value pairs
    result = {}
    for pair in headers_str.split(','):
        if ':' in pair:
            key, value = pair.split(':', 1)
            result[key.strip()] = value.strip()
    return result


def parse_tamper_methods(tamper_str):
    """Parse tamper methods string into list."""
    if not tamper_str:
        return []
    
    from sqlinjector.core.base import TamperType
    
    methods = []
    for method in tamper_str.split(','):
        method = method.strip().upper()
        try:
            methods.append(TamperType[method])
        except KeyError:
            print(f"Warning: Unknown tamper method '{method}'")
    
    return methods


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Set up logging
    log_level = max(1, 3 - args.verbose) * 10  # 30, 20, 10 for -v, -vv, -vvv
    if args.quiet:
        log_level = logging.WARNING
    
    setup_logging(level=log_level)
    logger = logging.getLogger("sqlinjector.main")
    
    try:
        # Security check
        if not args.force:
            if not SecurityValidator.check_authorization(args.url):
                return 1
        
        # Parse configuration
        config = ScanConfig(
            target_url=args.url,
            method=args.method,
            headers=parse_headers_string(args.headers),
            cookies=parse_data_string(args.cookies),
            data=parse_data_string(args.data),
            proxy_url=args.proxy,
            test_get_params=args.test_get,
            test_post_params=args.test_post,
            test_headers=args.test_headers,
            test_cookies=args.test_cookies,
            test_json=args.test_json,
            request_timeout=args.timeout,
            delay_between_requests=args.delay,
            max_retries=args.retries,
            time_delay=args.time_delay,
            boolean_rounds=args.boolean_rounds,
            tamper_methods=parse_tamper_methods(args.tamper),
            safe_mode=not args.no_safe_mode,
            destructive_tests=args.destructive
        )
        
        # Validate safety settings
        SecurityValidator.validate_safe_mode(config)
        
        # Create and run scanner
        scanner = SQLIScanner(config)
        
        if args.parameter:
            # Test specific parameter
            results = scanner.test_parameter(args.parameter)
        elif args.crawl:
            # Crawl and test
            results = scanner.crawl_and_test(scope=args.scope)
        else:
            # Standard scan
            results = scanner.scan()
        
        # Generate reports
        if args.output:
            scanner.generate_reports(args.output, format=args.format)
        
        # Print summary
        vulnerable_count = sum(1 for r in results if r.vulnerable)
        print(f"\nScan completed. Found {vulnerable_count} potential vulnerabilities out of {len(results)} tests.")
        
        return 0 if vulnerable_count == 0 else 2
        
    except SecurityError as e:
        logger.error(f"Security validation failed: {e}")
        return 1
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.verbose > 2:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())