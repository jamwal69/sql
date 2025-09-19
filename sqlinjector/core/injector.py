"""
Main SQL injection testing class that coordinates all modules.
Provides high-level interface for comprehensive SQL injection testing.
"""
import asyncio
import time
from typing import List, Dict, Any, Optional
from pathlib import Path

from .base import BaseModule, ScanConfig, TestResult, InjectionPoint
from .scanner import SQLIScanner
from .session import SessionManager
from ..modules.http_engine import HTTPEngine
from ..modules.detector import InjectionDetector
from ..modules.payload_manager import PayloadManager
from ..modules.fingerprinter import DatabaseFingerprinter
from ..modules.union_extractor import UnionExtractor
# Optional reporting module (may require additional dependencies)
try:
    from ..modules.reporting import AdvancedReportingEngine
    REPORTING_AVAILABLE = True
except ImportError:
    AdvancedReportingEngine = None
    REPORTING_AVAILABLE = False
from ..utils.logger import get_logger


class SQLInjector(BaseModule):
    """
    Main SQL injection testing class that provides a high-level interface
    for comprehensive SQL injection vulnerability assessment.
    """
    
    def __init__(self, config: ScanConfig, session_manager: Optional[SessionManager] = None):
        """
        Initialize SQLInjector.
        
        Args:
            config: Scan configuration
            session_manager: Optional session manager for persistence
        """
        super().__init__(config)
        self.logger = get_logger("sql_injector")
        
        # Initialize core modules
        self.scanner = SQLIScanner(config)
        self.session_manager = session_manager or SessionManager(config)
        
        # Initialize optional modules
        self.reporting_engine = None
        if REPORTING_AVAILABLE:
            try:
                self.reporting_engine = AdvancedReportingEngine(config)
            except Exception as e:
                self.logger.warning(f"Could not initialize reporting engine: {e}")
                self.reporting_engine = None
        
        # Results storage
        self.scan_results: List[TestResult] = []
        self.vulnerable_points: List[InjectionPoint] = []
        
        # Scan state
        self.scan_started = False
        self.scan_completed = False
        
        self.logger.info("SQLInjector initialized")
    
    async def scan(self, target_url: Optional[str] = None) -> List[TestResult]:
        """
        Perform a comprehensive SQL injection scan.
        
        Args:
            target_url: Override target URL from config
            
        Returns:
            List of test results
        """
        try:
            # Update target if provided
            if target_url:
                self.config.target_url = target_url
            
            self.logger.info(f"Starting comprehensive SQL injection scan on {self.config.target_url}")
            self.scan_started = True
            
            # Run the core scanner
            results = self.scanner.scan()
            self.scan_results.extend(results)
            
            # Store results in session
            for result in results:
                if result.vulnerable:
                    self.vulnerable_points.append(result.injection_point)
                
                # Store in session if available
                if self.session_manager:
                    point_id = self.session_manager.store_injection_point(result.injection_point)
                    self.session_manager.store_test_result(result, point_id)
            
            self.scan_completed = True
            
            # Finish session
            if self.session_manager:
                self.session_manager.finish_session()
            
            self.logger.info(f"Scan completed. Found {len(self.vulnerable_points)} vulnerable points")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            raise
    
    def scan_parameter(self, parameter: str) -> List[TestResult]:
        """
        Scan a specific parameter for SQL injection vulnerabilities.
        
        Args:
            parameter: Parameter name to test
            
        Returns:
            List of test results for the parameter
        """
        self.logger.info(f"Testing specific parameter: {parameter}")
        
        try:
            results = self.scanner.test_parameter(parameter)
            self.scan_results.extend(results)
            
            # Update vulnerable points
            for result in results:
                if result.vulnerable:
                    self.vulnerable_points.append(result.injection_point)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Parameter scan failed: {e}")
            raise
    
    def get_vulnerable_results(self) -> List[TestResult]:
        """
        Get only the vulnerable test results.
        
        Returns:
            List of vulnerable test results
        """
        return [result for result in self.scan_results if result.vulnerable]
    
    def get_scan_summary(self) -> Dict[str, Any]:
        """
        Get a comprehensive scan summary.
        
        Returns:
            Dictionary containing scan statistics and summary
        """
        vulnerable_results = self.get_vulnerable_results()
        
        # Count by injection type
        injection_types = {}
        for result in vulnerable_results:
            if result.injection_type:
                injection_types[result.injection_type.value] = injection_types.get(
                    result.injection_type.value, 0) + 1
        
        # Count by database type
        db_types = {}
        for result in vulnerable_results:
            if result.db_type:
                db_types[result.db_type.value] = db_types.get(
                    result.db_type.value, 0) + 1
        
        # Confidence scores
        confidence_scores = [
            self.scanner.detector._get_confidence_score(result) 
            for result in vulnerable_results
        ]
        avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0
        
        summary = {
            'target_url': self.config.target_url,
            'scan_started': self.scan_started,
            'scan_completed': self.scan_completed,
            'total_tests': len(self.scan_results),
            'vulnerable_count': len(vulnerable_results),
            'vulnerable_points': len(self.vulnerable_points),
            'injection_types': injection_types,
            'database_types': db_types,
            'average_confidence': avg_confidence,
            'session_id': self.session_manager.session_id if self.session_manager else None
        }
        
        return summary
    
    def generate_report(self, output_dir: str = "reports", format: str = "html") -> str:
        """
        Generate a comprehensive vulnerability report.
        
        Args:
            output_dir: Directory to save the report
            format: Report format (html, json, txt)
            
        Returns:
            Path to the generated report
        """
        self.logger.info(f"Generating {format} report in {output_dir}")
        
        # Initialize reporting engine if not already done
        if not self.reporting_engine and REPORTING_AVAILABLE:
            try:
                self.reporting_engine = AdvancedReportingEngine(self.config)
            except Exception as e:
                self.logger.warning(f"Could not initialize reporting engine: {e}")
                # Fall back to basic report generation
                return self.scanner.generate_reports(output_dir, format)
        
        # Use scanner's report generation
        return self.scanner.generate_reports(output_dir, format)
    
    def export_session_data(self, output_file: str) -> None:
        """
        Export session data to file.
        
        Args:
            output_file: Output file path
        """
        if not self.session_manager:
            raise ValueError("No session manager available for data export")
        
        import json
        
        # Get session statistics and results
        stats = self.session_manager.get_scan_statistics()
        results = self.session_manager.get_session_results()
        
        # Convert results to serializable format
        serializable_results = []
        for result in results:
            result_dict = {
                'injection_point': {
                    'url': result.injection_point.url,
                    'method': result.injection_point.method,
                    'parameter': result.injection_point.parameter,
                    'param_type': result.injection_point.param_type,
                    'original_value': result.injection_point.original_value,
                    'location': result.injection_point.location
                },
                'payload': result.payload,
                'vulnerable': result.vulnerable,
                'injection_type': result.injection_type.value if result.injection_type else None,
                'db_type': result.db_type.value if result.db_type else None,
                'response_status': result.response_status,
                'response_time': result.response_time,
                'error_message': result.error_message,
                'timestamp': result.timestamp
            }
            serializable_results.append(result_dict)
        
        export_data = {
            'session_statistics': stats,
            'test_results': serializable_results,
            'scan_summary': self.get_scan_summary()
        }
        
        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        self.logger.info(f"Session data exported to {output_file}")
    
    def cleanup(self):
        """Clean up resources."""
        self.logger.info("Cleaning up SQLInjector resources")
        
        if self.scanner:
            self.scanner.cleanup()
        
        if self.session_manager:
            self.session_manager.close()
        
        self.logger.info("Cleanup completed")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.cleanup()
    
    @classmethod
    def quick_scan(cls, target_url: str, **kwargs) -> List[TestResult]:
        """
        Perform a quick scan with minimal configuration.
        
        Args:
            target_url: Target URL to scan
            **kwargs: Additional configuration options
            
        Returns:
            List of test results
        """
        config = ScanConfig(target_url=target_url, **kwargs)
        
        with cls(config) as injector:
            return asyncio.run(injector.scan())
    
    @classmethod
    def create_from_config_file(cls, config_file: str) -> 'SQLInjector':
        """
        Create SQLInjector instance from configuration file.
        
        Args:
            config_file: Path to configuration file
            
        Returns:
            SQLInjector instance
        """
        import yaml
        
        with open(config_file, 'r') as f:
            config_data = yaml.safe_load(f)
        
        config = ScanConfig(**config_data)
        return cls(config)


# Convenience functions for common use cases
async def quick_scan(target_url: str, method: str = "GET", **kwargs) -> List[TestResult]:
    """
    Quick scan function for immediate testing.
    
    Args:
        target_url: Target URL
        method: HTTP method
        **kwargs: Additional scan options
        
    Returns:
        List of test results
    """
    config = ScanConfig(target_url=target_url, method=method, **kwargs)
    
    with SQLInjector(config) as injector:
        return await injector.scan()


def scan_url(target_url: str, **kwargs) -> Dict[str, Any]:
    """
    Synchronous scan function with summary results.
    
    Args:
        target_url: Target URL
        **kwargs: Additional scan options
        
    Returns:
        Scan summary with results
    """
    results = SQLInjector.quick_scan(target_url, **kwargs)
    
    vulnerable_count = sum(1 for r in results if r.vulnerable)
    
    return {
        'target_url': target_url,
        'total_tests': len(results),
        'vulnerable_count': vulnerable_count,
        'results': results,
        'vulnerable': vulnerable_count > 0
    }