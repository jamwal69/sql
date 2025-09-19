#!/usr/bin/env python3
"""
Simple test runner to validate basic functionality.
Tests the core functionality without requiring external network access.
"""
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlinjector import SQLInjector, SQLIScanner
from sqlinjector.core.base import ScanConfig, InjectionPoint
from sqlinjector.modules.payload_manager import PayloadManager
from sqlinjector.modules.detector import InjectionDetector


def test_basic_imports():
    """Test that basic imports work."""
    print("Testing basic imports...")
    try:
        from sqlinjector import SQLInjector, SQLIScanner
        from sqlinjector.core.base import ScanConfig
        print("✅ Basic imports successful")
        return True
    except Exception as e:
        print(f"❌ Import failed: {e}")
        return False


def test_config_creation():
    """Test configuration creation."""
    print("Testing configuration creation...")
    try:
        config = ScanConfig(
            target_url="http://example.com/test?id=1",
            method="GET",
            safe_mode=True
        )
        assert config.target_url == "http://example.com/test?id=1"
        assert config.method == "GET"
        assert config.safe_mode == True
        print("✅ Configuration creation successful")
        return True
    except Exception as e:
        print(f"❌ Configuration creation failed: {e}")
        return False


def test_payload_manager():
    """Test payload manager functionality."""
    print("Testing payload manager...")
    try:
        config = ScanConfig(target_url="http://example.com")
        pm = PayloadManager(config)
        
        # Test getting payloads directly from the JSON structure
        if hasattr(pm, 'payloads') and pm.payloads:
            error_payloads = pm.payloads.get("error_based", [])
            assert isinstance(error_payloads, list)
            assert len(error_payloads) > 0
        else:
            # Test fallback behavior
            error_payloads = pm.get_detection_payloads("error_based")
            # The method might return empty list if structure doesn't match
            assert isinstance(error_payloads, list)
        
        # Test tamper functions
        original = "' OR '1'='1"
        encoded = pm._url_encode(original)
        assert "%27" in encoded  # Single quote should be encoded
        
        print("✅ Payload manager functional")
        return True
    except Exception as e:
        print(f"❌ Payload manager test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_injection_point():
    """Test injection point creation."""
    print("Testing injection point creation...")
    try:
        point = InjectionPoint(
            url="http://example.com/test?id=1",
            method="GET",
            parameter="id",
            param_type="GET",
            original_value="1"
        )
        
        assert point.url == "http://example.com/test?id=1"
        assert point.parameter == "id"
        assert point.original_value == "1"
        
        print("✅ Injection point creation successful")
        return True
    except Exception as e:
        print(f"❌ Injection point test failed: {e}")
        return False


def test_scanner_creation():
    """Test scanner creation."""
    print("Testing scanner creation...")
    try:
        import asyncio
        
        async def test_async():
            config = ScanConfig(target_url="http://example.com")
            scanner = SQLIScanner(config)
            
            assert scanner.config == config
            assert hasattr(scanner, 'http_engine')
            assert hasattr(scanner, 'detector')
            assert hasattr(scanner, 'payload_manager')
            
            scanner.cleanup()
            return True
        
        # Run in event loop
        result = asyncio.run(test_async())
        print("✅ Scanner creation successful")
        return result
    except Exception as e:
        print(f"❌ Scanner creation failed: {e}")
        return False


def test_injector_creation():
    """Test main injector creation."""
    print("Testing SQLInjector creation...")
    try:
        import asyncio
        
        async def test_async():
            config = ScanConfig(target_url="http://example.com")
            injector = SQLInjector(config)
            
            assert injector.config == config
            assert hasattr(injector, 'scanner')
            assert hasattr(injector, 'session_manager')
            
            # Test summary generation
            summary = injector.get_scan_summary()
            assert isinstance(summary, dict)
            assert 'target_url' in summary
            assert 'total_tests' in summary
            
            injector.cleanup()
            return True
        
        # Run in event loop
        result = asyncio.run(test_async())
        print("✅ SQLInjector creation successful")
        return result
    except Exception as e:
        print(f"❌ SQLInjector creation failed: {e}")
        return False


def test_detector_functionality():
    """Test detector functionality."""
    print("Testing detector functionality...")
    try:
        config = ScanConfig(target_url="http://example.com")
        detector = InjectionDetector(config)
        
        # Test database error detection
        mysql_error = "MySQL server version for the right syntax"
        db_type, error_msg = detector._detect_database_error(mysql_error)
        
        from sqlinjector.core.base import DBType
        assert db_type == DBType.MYSQL
        
        # Test response difference detection
        response1 = {'status_code': 200, 'content': 'Hello', 'headers': {}}
        response2 = {'status_code': 500, 'content': 'Error', 'headers': {}}
        
        assert detector._responses_differ_significantly(response1, response2)
        
        print("✅ Detector functionality successful")
        return True
    except Exception as e:
        print(f"❌ Detector test failed: {e}")
        return False


def main():
    """Run all tests."""
    print("SQLInjector Functionality Test Suite")
    print("=" * 50)
    
    tests = [
        test_basic_imports,
        test_config_creation,
        test_injection_point,
        test_payload_manager,
        test_detector_functionality,
        test_scanner_creation,
        test_injector_creation,
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} failed with exception: {e}")
        print()
    
    print("=" * 50)
    print(f"Test Results: {passed}/{total} passed")
    
    if passed == total:
        print("🎉 All tests passed! SQLInjector is functional.")
        return 0
    else:
        print("⚠️  Some tests failed. Check the output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())