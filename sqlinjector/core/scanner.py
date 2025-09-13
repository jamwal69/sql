"""
Main SQL injection scanner module.
Orchestrates detection, fingerprinting, and exploitation.
"""
from typing import List, Optional, Dict, Any
import time

from ..core.base import BaseModule, ScanConfig, TestResult, InjectionPoint, InjectionType
from ..modules.http_engine import HTTPEngine
from ..modules.detector import InjectionDetector
from ..modules.fingerprinter import DatabaseFingerprinter
from ..modules.payload_manager import PayloadManager
from ..modules.union_extractor import UnionExtractor
from ..utils.logger import get_logger


class SQLIScanner(BaseModule):
    """
    Main SQL injection scanner that coordinates all testing modules.
    """
    
    def __init__(self, config: ScanConfig):
        super().__init__(config)
        self.logger = get_logger("scanner")
        
        # Initialize modules
        self.http_engine = HTTPEngine(config)
        self.detector = InjectionDetector(config)
        self.fingerprinter = DatabaseFingerprinter(config)
        self.payload_manager = PayloadManager(config)
        self.union_extractor = UnionExtractor(config)
        
        self.results = []
        self.vulnerable_points = []
    
    def scan(self) -> List[TestResult]:
        """
        Perform a comprehensive SQL injection scan.
        
        Returns:
            List of test results
        """
        self.logger.info(f"Starting SQL injection scan on {self.config.target_url}")
        
        # Extract injection points
        injection_points = self.http_engine.extract_injection_points(
            self.config.target_url,
            self.config.method,
            self.config.data
        )
        
        if not injection_points:
            self.logger.warning("No injection points found")
            return []
        
        self.logger.info(f"Found {len(injection_points)} injection points to test")
        
        # Test each injection point
        for injection_point in injection_points:
            self.logger.info(f"Testing {injection_point.parameter} ({injection_point.param_type})")
            
            # Basic detection
            result = self.detector.detect_injection(injection_point)
            self.results.append(result)
            
            if result.vulnerable:
                self.logger.info(f"VULNERABLE: {injection_point.parameter} - {result.injection_type.value}")
                self.vulnerable_points.append(injection_point)
                
                # Advanced testing for vulnerable points
                self._advanced_testing(injection_point, result)
            
            # Rate limiting
            time.sleep(self.config.delay_between_requests)
        
        self.logger.info(f"Scan completed. Found {len(self.vulnerable_points)} vulnerable parameters")
        return self.results
    
    def test_parameter(self, parameter: str) -> List[TestResult]:
        """
        Test a specific parameter.
        
        Args:
            parameter: Parameter name to test
            
        Returns:
            List of test results for the parameter
        """
        injection_points = self.http_engine.extract_injection_points(
            self.config.target_url,
            self.config.method,
            self.config.data
        )
        
        # Filter to specific parameter
        target_points = [ip for ip in injection_points if ip.parameter == parameter]
        
        if not target_points:
            self.logger.warning(f"Parameter '{parameter}' not found")
            return []
        
        results = []
        for injection_point in target_points:
            result = self.detector.detect_injection(injection_point)
            results.append(result)
            
            if result.vulnerable:
                self.vulnerable_points.append(injection_point)
                self._advanced_testing(injection_point, result)
        
        return results
    
    def crawl_and_test(self, scope: Optional[str] = None) -> List[TestResult]:
        """
        Crawl the target and test discovered endpoints.
        
        Args:
            scope: Crawling scope (domain or URL pattern)
            
        Returns:
            List of test results
        """
        self.logger.info("Crawling functionality not implemented in this version")
        # For now, fall back to standard scan
        return self.scan()
    
    def _advanced_testing(self, injection_point: InjectionPoint, detection_result: TestResult):
        """
        Perform advanced testing on confirmed vulnerable points.
        
        Args:
            injection_point: Vulnerable injection point
            detection_result: Initial detection result
        """
        self.logger.info(f"Performing advanced testing on {injection_point.parameter}")
        
        # Database fingerprinting
        if detection_result.db_type is None:
            fingerprint = self.fingerprinter.fingerprint_database(injection_point)
            detection_result.db_type = fingerprint.db_type
            if fingerprint.version:
                detection_result.error_message = f"{detection_result.error_message}; DB Version: {fingerprint.version}"
        
        # UNION-based exploitation if applicable
        if detection_result.injection_type in [InjectionType.UNION, InjectionType.ERROR]:
            self._test_union_exploitation(injection_point, detection_result)
    
    def _test_union_exploitation(self, injection_point: InjectionPoint, detection_result: TestResult):
        """
        Test UNION-based data extraction.
        
        Args:
            injection_point: Injection point
            detection_result: Detection result
        """
        self.logger.info("Testing UNION-based exploitation")
        
        try:
            # Detect column count
            column_count = self.union_extractor.detect_column_count(injection_point)
            
            if column_count > 0:
                self.logger.info(f"Detected {column_count} columns")
                
                # Find injectable columns
                injectable_columns = self.union_extractor.find_injectable_columns(
                    injection_point, column_count
                )
                
                if injectable_columns:
                    self.logger.info(f"Found injectable columns: {injectable_columns}")
                    
                    # Extract basic information
                    if detection_result.db_type:
                        self._extract_database_info(injection_point, column_count, 
                                                  injectable_columns, detection_result.db_type)
                
        except Exception as e:
            self.logger.error(f"UNION exploitation failed: {e}")
    
    def _extract_database_info(self, injection_point: InjectionPoint, column_count: int,
                             injectable_columns: List[int], db_type):
        """
        Extract basic database information.
        
        Args:
            injection_point: Injection point
            column_count: Number of columns
            injectable_columns: List of injectable column positions
            db_type: Database type
        """
        if not injectable_columns:
            return
        
        injectable_col = injectable_columns[0]  # Use first injectable column
        
        # Get information extraction payloads
        info_payloads = self.payload_manager.get_exploitation_payloads(db_type, "information_extraction")
        
        extracted_info = {}
        
        # Extract version
        if "version" in info_payloads:
            version_data = self.union_extractor.extract_data(
                injection_point, column_count, injectable_col, info_payloads["version"]
            )
            if version_data:
                extracted_info["version"] = version_data
                self.logger.info(f"Database version: {version_data}")
        
        # Extract current database
        if "database" in info_payloads:
            db_data = self.union_extractor.extract_data(
                injection_point, column_count, injectable_col, info_payloads["database"]
            )
            if db_data:
                extracted_info["database"] = db_data
                self.logger.info(f"Current database: {db_data}")
        
        # Extract current user
        if "user" in info_payloads:
            user_data = self.union_extractor.extract_data(
                injection_point, column_count, injectable_col, info_payloads["user"]
            )
            if user_data:
                extracted_info["user"] = user_data
                self.logger.info(f"Current user: {user_data}")
        
        # Store extracted information
        self._store_extracted_info(injection_point, extracted_info)
    
    def _store_extracted_info(self, injection_point: InjectionPoint, info: Dict[str, str]):
        """Store extracted information for reporting."""
        # Add to results or store in session database
        # This would integrate with the session storage system
        pass
    
    def generate_reports(self, output_dir: str, format: str = "both"):
        """
        Generate scan reports.
        
        Args:
            output_dir: Output directory for reports
            format: Report format (json, html, both)
        """
        from ..reports.generator import ReportGenerator
        
        report_generator = ReportGenerator(self.config)
        report_generator.generate_reports(self.results, output_dir, format)
    
    def get_scan_summary(self) -> Dict[str, Any]:
        """
        Get a summary of scan results.
        
        Returns:
            Dictionary containing scan summary
        """
        total_tests = len(self.results)
        vulnerable_count = len(self.vulnerable_points)
        
        injection_types = {}
        db_types = {}
        
        for result in self.results:
            if result.vulnerable:
                if result.injection_type:
                    injection_types[result.injection_type.value] = injection_types.get(result.injection_type.value, 0) + 1
                if result.db_type:
                    db_types[result.db_type.value] = db_types.get(result.db_type.value, 0) + 1
        
        return {
            "total_tests": total_tests,
            "vulnerable_count": vulnerable_count,
            "injection_types": injection_types,
            "database_types": db_types,
            "scan_config": {
                "target_url": self.config.target_url,
                "method": self.config.method,
                "safe_mode": self.config.safe_mode
            }
        }
    
    def cleanup(self):
        """Clean up resources."""
        if self.http_engine:
            self.http_engine.close()


class SQLInjector:
    """
    High-level interface for SQL injection testing.
    Simplified API for common use cases.
    """
    
    def __init__(self, target_url: str, **kwargs):
        """
        Initialize SQLInjector.
        
        Args:
            target_url: Target URL to test
            **kwargs: Additional configuration options
        """
        self.config = ScanConfig(target_url=target_url, **kwargs)
        self.scanner = SQLIScanner(self.config)
    
    def quick_scan(self) -> List[TestResult]:
        """Perform a quick SQL injection scan."""
        return self.scanner.scan()
    
    def test_parameter(self, parameter: str) -> List[TestResult]:
        """Test a specific parameter."""
        return self.scanner.test_parameter(parameter)
    
    def get_vulnerabilities(self) -> List[TestResult]:
        """Get only vulnerable results."""
        return [result for result in self.scanner.results if result.vulnerable]
    
    def cleanup(self):
        """Clean up resources."""
        self.scanner.cleanup()