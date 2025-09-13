"""
Base classes and configurations for the SQL injection testing tool.
"""
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Any
import time


class DBType(Enum):
    """Supported database types."""
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    UNKNOWN = "unknown"


class InjectionType(Enum):
    """Types of SQL injection vulnerabilities."""
    UNION = "union"
    BOOLEAN = "boolean"
    TIME = "time"
    ERROR = "error"
    STACKED = "stacked"
    OOB = "out_of_band"


class TamperType(Enum):
    """Available tamper/encoding methods."""
    URL_ENCODE = "url_encode"
    HEX_ENCODE = "hex_encode"
    HTML_ENTITY = "html_entity"
    XML_ENTITY = "xml_entity"
    COMMENT_SPLIT = "comment_split"
    CASE_MIX = "case_mix"
    CONCAT_SPLIT = "concat_split"


@dataclass
class InjectionPoint:
    """Represents a potential SQL injection point."""
    url: str
    method: str
    parameter: str
    param_type: str  # GET, POST, HEADER, COOKIE, JSON
    original_value: str
    location: Optional[str] = None  # For JSON: path like "user.name"


@dataclass
class TestResult:
    """Result of a single injection test."""
    injection_point: InjectionPoint
    payload: str
    tamper_used: List[str]
    response_status: int
    response_length: int
    response_time: float
    response_body: str
    response_headers: Dict[str, str]
    vulnerable: bool
    injection_type: Optional[InjectionType]
    db_type: Optional[DBType]
    error_message: Optional[str]
    timestamp: float = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()


@dataclass
class ScanConfig:
    """Configuration for SQL injection scans."""
    # Target configuration
    target_url: str
    method: str = "GET"
    headers: Dict[str, str] = None
    cookies: Dict[str, str] = None
    data: Dict[str, Any] = None
    
    # Authentication
    auth_type: Optional[str] = None  # basic, bearer, form
    auth_data: Dict[str, str] = None
    
    # Proxy configuration
    proxy_url: Optional[str] = None
    
    # Scan configuration
    test_get_params: bool = True
    test_post_params: bool = True
    test_headers: bool = False
    test_cookies: bool = False
    test_json: bool = True
    
    # Timing and throttling
    request_timeout: int = 30
    delay_between_requests: float = 0.1
    max_retries: int = 3
    
    # Detection settings
    time_delay: int = 5  # For time-based detection
    boolean_rounds: int = 3  # Number of true/false rounds
    
    # Tamper settings
    tamper_methods: List[TamperType] = None
    
    # Safety settings
    safe_mode: bool = True
    destructive_tests: bool = False
    
    def __post_init__(self):
        if self.headers is None:
            self.headers = {}
        if self.cookies is None:
            self.cookies = {}
        if self.data is None:
            self.data = {}
        if self.auth_data is None:
            self.auth_data = {}
        if self.tamper_methods is None:
            self.tamper_methods = []


class BaseModule:
    """Base class for all modules."""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.logger = self._setup_logger()
    
    def _setup_logger(self) -> logging.Logger:
        """Set up module-specific logger."""
        logger = logging.getLogger(f"sqlinjector.{self.__class__.__name__}")
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger


class SecurityValidator:
    """Validates that the tool is being used ethically and safely."""
    
    @staticmethod
    def check_authorization(target_url: str) -> bool:
        """
        Interactive check for authorization.
        In a real implementation, you might want to make this more sophisticated.
        """
        print("\n" + "="*60)
        print("SECURITY WARNING")
        print("="*60)
        print(f"You are about to test: {target_url}")
        print("\nThis tool should ONLY be used on systems you are authorized to test.")
        print("Unauthorized testing may be illegal and unethical.")
        print("="*60)
        
        while True:
            response = input("\nDo you have explicit authorization to test this target? (yes/no): ")
            if response.lower() in ['yes', 'y']:
                return True
            elif response.lower() in ['no', 'n']:
                print("Testing aborted. Only test systems you are authorized to test.")
                return False
            else:
                print("Please answer 'yes' or 'no'")
    
    @staticmethod
    def validate_safe_mode(config: ScanConfig) -> None:
        """Validate safe mode configuration."""
        if not config.safe_mode and config.destructive_tests:
            print("\nWARNING: Safe mode is disabled and destructive tests are enabled!")
            print("This may cause data loss or system damage.")
            response = input("Are you sure you want to continue? (yes/no): ")
            if response.lower() not in ['yes', 'y']:
                raise SecurityError("Testing aborted for safety reasons.")


class SecurityError(Exception):
    """Raised when security validation fails."""
    pass


# Error patterns for different database types
DB_ERROR_PATTERNS = {
    DBType.MYSQL: [
        r"MySQL server version",
        r"mysql_fetch_array\(\)",
        r"mysql_fetch_assoc\(\)",
        r"mysql_fetch_row\(\)",
        r"mysql_num_rows\(\)",
        r"You have an error in your SQL syntax",
        r"Warning.*mysql_.*",
        r"MySQLSyntaxErrorException",
        r"com.mysql.jdbc.exceptions"
    ],
    DBType.POSTGRESQL: [
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_.*",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError",
        r"org.postgresql.util.PSQLException",
        r"ERROR:\s+syntax error at or near"
    ],
    DBType.MSSQL: [
        r"Microsoft.*ODBC.*SQL Server",
        r"Warning.*mssql_.*",
        r"Microsoft OLE DB Provider for ODBC Drivers.*error",
        r"Microsoft OLE DB Provider for SQL Server.*error",
        r"Syntax error.*in query.*Incorrect syntax near",
        r"System.Data.SqlClient.SqlException",
        r"Microsoft SQL Native Client error"
    ],
    DBType.ORACLE: [
        r"Microsoft.*ODBC.*Oracle",
        r"Warning.*oci_.*",
        r"Warning.*ora_.*",
        r"Oracle error",
        r"Oracle.*Driver",
        r"ORA-[0-9]{4,5}",
        r"java.sql.SQLException.*oracle"
    ],
    DBType.SQLITE: [
        r"SQLite/JDBCDriver",
        r"SQLite.Exception",
        r"System.Data.SQLite.SQLiteException",
        r"Warning.*sqlite_.*",
        r"sqlite3.OperationalError"
    ]
}