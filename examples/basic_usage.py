#!/usr/bin/env python3
"""
Example: Basic SQL injection testing
This example shows how to use SQLInjector for basic vulnerability testing.
"""
import asyncio
import sys
from pathlib import Path

# Add parent directory to path for development
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlinjector import SQLInjector
from sqlinjector.core.base import ScanConfig


async def basic_get_scan():
    """Example: Testing GET parameters for SQL injection."""
    print("=== Basic GET Parameter Testing ===")
    
    # Configure the scan
    config = ScanConfig(
        target_url="http://testphp.vulnweb.com/listproducts.php?cat=1",
        method="GET",
        safe_mode=True,
        request_timeout=10,
        delay_between_requests=0.5
    )
    
    # Create scanner and run scan
    with SQLInjector(config) as injector:
        try:
            results = await injector.scan()
            
            # Print results
            summary = injector.get_scan_summary()
            print(f"Scanned: {summary['target_url']}")
            print(f"Total tests: {summary['total_tests']}")
            print(f"Vulnerabilities found: {summary['vulnerable_count']}")
            
            # Show vulnerable results
            if summary['vulnerable_count'] > 0:
                print("\n🚨 Vulnerabilities found:")
                for result in injector.get_vulnerable_results():
                    print(f"  - Parameter: {result.injection_point.parameter}")
                    print(f"    Type: {result.injection_type.value if result.injection_type else 'Unknown'}")
                    print(f"    Payload: {result.payload}")
                    if result.db_type:
                        print(f"    Database: {result.db_type.value}")
                    print()
            else:
                print("✅ No vulnerabilities detected")
                
        except Exception as e:
            print(f"❌ Scan failed: {e}")


async def basic_post_scan():
    """Example: Testing POST parameters for SQL injection."""
    print("\n=== Basic POST Parameter Testing ===")
    
    # Configure the scan for POST request
    config = ScanConfig(
        target_url="http://testphp.vulnweb.com/userinfo.php",
        method="POST",
        data={"uname": "test", "pass": "test"},
        safe_mode=True
    )
    
    with SQLInjector(config) as injector:
        try:
            results = await injector.scan()
            
            summary = injector.get_scan_summary()
            print(f"Scanned: {summary['target_url']} (POST)")
            print(f"Total tests: {summary['total_tests']}")
            print(f"Vulnerabilities found: {summary['vulnerable_count']}")
            
        except Exception as e:
            print(f"❌ Scan failed: {e}")


def parameter_only_test():
    """Example: Testing a specific parameter only."""
    print("\n=== Specific Parameter Testing ===")
    
    config = ScanConfig(
        target_url="http://testphp.vulnweb.com/listproducts.php?cat=1&sort=name",
        method="GET",
        safe_mode=True
    )
    
    with SQLInjector(config) as injector:
        try:
            # Test only the 'cat' parameter
            results = injector.scan_parameter("cat")
            
            print(f"Tested parameter: cat")
            print(f"Results: {len(results)}")
            
            vulnerable_results = [r for r in results if r.vulnerable]
            if vulnerable_results:
                print(f"🚨 Parameter 'cat' is vulnerable!")
                for result in vulnerable_results:
                    print(f"  - Type: {result.injection_type.value if result.injection_type else 'Unknown'}")
                    print(f"  - Payload: {result.payload}")
            else:
                print("✅ Parameter 'cat' appears safe")
                
        except Exception as e:
            print(f"❌ Test failed: {e}")


async def main():
    """Run all examples."""
    print("SQLInjector Basic Examples")
    print("=" * 50)
    print("⚠️  These examples use public test sites")
    print("⚠️  Only use on systems you own or have permission to test!")
    print()
    
    # Note: These examples use a public test site
    # In practice, you would use your own test environment
    
    try:
        # Basic GET scan
        await basic_get_scan()
        
        # Basic POST scan  
        await basic_post_scan()
        
        # Parameter-specific test
        parameter_only_test()
        
    except KeyboardInterrupt:
        print("\n⚠️  Examples interrupted by user")


if __name__ == "__main__":
    asyncio.run(main())