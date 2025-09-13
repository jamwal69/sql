"""
Test suite for SQLInjector.
Basic unit tests for core functionality.
"""
import pytest
import time
from unittest.mock import Mock, patch

from sqlinjector.core.base import ScanConfig, InjectionPoint, TestResult, DBType, InjectionType
from sqlinjector.modules.http_engine import HTTPEngine
from sqlinjector.modules.detector import InjectionDetector
from sqlinjector.modules.payload_manager import PayloadManager


class TestScanConfig:
    """Test ScanConfig functionality."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = ScanConfig(target_url="http://example.com")
        
        assert config.target_url == "http://example.com"
        assert config.method == "GET"
        assert config.safe_mode == True
        assert config.request_timeout == 30
        assert config.delay_between_requests == 0.1
    
    def test_custom_config(self):
        """Test custom configuration."""
        config = ScanConfig(
            target_url="http://example.com",
            method="POST",
            safe_mode=False,
            request_timeout=60
        )
        
        assert config.method == "POST"
        assert config.safe_mode == False
        assert config.request_timeout == 60


class TestInjectionPoint:
    """Test InjectionPoint functionality."""
    
    def test_injection_point_creation(self):
        """Test injection point creation."""
        point = InjectionPoint(
            url="http://example.com/test",
            method="GET",
            parameter="id",
            param_type="GET",
            original_value="1"
        )
        
        assert point.url == "http://example.com/test"
        assert point.parameter == "id"
        assert point.param_type == "GET"
        assert point.original_value == "1"


class TestHTTPEngine:
    """Test HTTP engine functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = ScanConfig(target_url="http://example.com")
        self.engine = HTTPEngine(self.config)
    
    def test_engine_initialization(self):
        """Test HTTP engine initialization."""
        assert self.engine.config == self.config
        assert hasattr(self.engine, 'session')
    
    def test_extract_injection_points_get(self):
        """Test extraction of GET parameter injection points."""
        url = "http://example.com/test?id=1&name=test"
        points = self.engine.extract_injection_points(url, "GET")
        
        assert len(points) >= 2
        param_names = [p.parameter for p in points]
        assert "id" in param_names
        assert "name" in param_names
    
    def test_extract_injection_points_post(self):
        """Test extraction of POST parameter injection points."""
        url = "http://example.com/test"
        data = {"username": "admin", "password": "test"}
        points = self.engine.extract_injection_points(url, "POST", data)
        
        param_names = [p.parameter for p in points]
        assert "username" in param_names
        assert "password" in param_names
    
    def test_build_request_with_payload(self):
        """Test building request with payload."""
        point = InjectionPoint(
            url="http://example.com/test?id=1",
            method="GET",
            parameter="id",
            param_type="GET",
            original_value="1"
        )
        
        request_params = self.engine.build_request_with_payload(point, "1' OR '1'='1")
        
        assert "1' OR '1'='1" in request_params['url']
    
    def teardown_method(self):
        """Clean up after tests."""
        self.engine.close()


class TestPayloadManager:
    """Test payload manager functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = ScanConfig(target_url="http://example.com")
        self.payload_manager = PayloadManager(self.config)
    
    def test_get_detection_payloads(self):
        """Test getting detection payloads."""
        error_payloads = self.payload_manager.get_detection_payloads("error_based")
        assert isinstance(error_payloads, list)
        assert len(error_payloads) > 0
        assert "'" in error_payloads[0]
    
    def test_generate_time_payloads(self):
        """Test generating time-based payloads."""
        payloads = self.payload_manager.generate_time_payloads(DBType.MYSQL, delay=5)
        assert isinstance(payloads, list)
        assert len(payloads) > 0
        assert any("SLEEP(5)" in p for p in payloads)
    
    def test_url_encode_tamper(self):
        """Test URL encoding tamper."""
        original = "' OR '1'='1"
        encoded = self.payload_manager._url_encode(original)
        assert "%27" in encoded  # Single quote encoded
        assert "%20" in encoded  # Space encoded
    
    def test_case_mix_tamper(self):
        """Test case mixing tamper."""
        original = "UNION SELECT"
        mixed = self.payload_manager._case_mix(original)
        assert mixed != original
        assert mixed.upper() == original.upper()


class TestDetector:
    """Test injection detector functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = ScanConfig(target_url="http://example.com")
        self.detector = InjectionDetector(self.config)
    
    @patch('sqlinjector.modules.detector.HTTPEngine')
    def test_detect_database_error(self, mock_http):
        """Test database error detection."""
        content = "MySQL server version for the right syntax to use"
        db_type, error_msg = self.detector._detect_database_error(content)
        
        assert db_type == DBType.MYSQL
        assert error_msg is not None
    
    def test_responses_differ_significantly(self):
        """Test response difference detection."""
        response1 = {
            'status_code': 200,
            'content': 'Hello World',
            'headers': {}
        }
        
        response2 = {
            'status_code': 500,
            'content': 'Internal Server Error',
            'headers': {}
        }
        
        assert self.detector._responses_differ_significantly(response1, response2)
    
    def test_responses_similar(self):
        """Test similar response detection."""
        response1 = {
            'status_code': 200,
            'content': 'Hello World',
            'headers': {}
        }
        
        response2 = {
            'status_code': 200,
            'content': 'Hello World!',  # Slight difference
            'headers': {}
        }
        
        assert not self.detector._responses_differ_significantly(response1, response2)


class TestIntegration:
    """Integration tests."""
    
    def setup_method(self):
        """Set up integration test fixtures."""
        self.config = ScanConfig(
            target_url="http://httpbin.org/get",
            method="GET",
            safe_mode=True
        )
    
    @pytest.mark.integration
    def test_basic_scan_flow(self):
        """Test basic scanning flow (requires internet connection)."""
        from sqlinjector.core.scanner import SQLIScanner
        
        scanner = SQLIScanner(self.config)
        
        # Extract injection points
        engine = scanner.http_engine
        points = engine.extract_injection_points(
            "http://httpbin.org/get?test=1",
            "GET"
        )
        
        assert len(points) > 0
        
        # Test with a safe payload (won't be vulnerable but tests the flow)
        if points:
            detector = scanner.detector
            # Mock the baseline response to avoid actual HTTP calls in unit test
            with patch.object(detector, '_get_baseline_response') as mock_baseline:
                mock_baseline.return_value = {
                    'status_code': 200,
                    'content': 'test response',
                    'response_time': 0.5,
                    'headers': {}
                }
                
                # This will test the detection logic without making real requests
                # since we're mocking the baseline
                result = detector.detect_injection(points[0])
                assert isinstance(result, TestResult)
                assert not result.vulnerable  # Should not be vulnerable with safe payload
        
        scanner.cleanup()


class TestSecurityFeatures:
    """Test security and safety features."""
    
    def test_safe_mode_blocking(self):
        """Test that safe mode blocks destructive payloads."""
        config = ScanConfig(target_url="http://example.com", safe_mode=True)
        payload_manager = PayloadManager(config)
        
        # Safe mode should not include destructive payloads
        error_payloads = payload_manager.get_detection_payloads("error_based")
        
        # Check that DROP TABLE payloads are not included (they should be filtered out)
        destructive_payloads = [p for p in error_payloads if "DROP TABLE" in p.upper()]
        assert len(destructive_payloads) == 0
    
    def test_authorization_check(self):
        """Test authorization checking."""
        from sqlinjector.core.base import SecurityValidator
        
        # This would normally be interactive, but we can test the structure
        assert hasattr(SecurityValidator, 'check_authorization')
        assert callable(SecurityValidator.check_authorization)


# Test fixtures and helpers
@pytest.fixture
def sample_config():
    """Sample configuration for tests."""
    return ScanConfig(
        target_url="http://example.com/test",
        method="GET",
        safe_mode=True,
        request_timeout=10
    )


@pytest.fixture
def sample_injection_point():
    """Sample injection point for tests."""
    return InjectionPoint(
        url="http://example.com/test?id=1",
        method="GET",
        parameter="id",
        param_type="GET",
        original_value="1"
    )


if __name__ == "__main__":
    # Run tests with: python -m pytest tests/test_sqlinjector.py -v
    pytest.main([__file__, "-v"])