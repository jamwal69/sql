"""
Session management and persistent storage for SQL injection testing.
Handles result storage, session persistence, and scan resumption.
"""
import sqlite3
import json
import time
import uuid
from typing import List, Dict, Any, Optional
from pathlib import Path
from dataclasses import asdict

from ..core.base import BaseModule, ScanConfig, TestResult, InjectionPoint
from ..utils.logger import get_logger


class SessionManager(BaseModule):
    """
    Manages scan sessions and persistent storage using SQLite.
    """
    
    def __init__(self, config: ScanConfig, session_dir: Optional[str] = None):
        super().__init__(config)
        self.logger = get_logger("session_manager")
        
        # Set up session directory
        if session_dir:
            self.session_dir = Path(session_dir)
        else:
            self.session_dir = Path.home() / ".sqlinjector" / "sessions"
        
        self.session_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate session ID
        self.session_id = str(uuid.uuid4())
        self.session_file = self.session_dir / f"session_{self.session_id}.db"
        
        # Initialize database
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database for session storage."""
        self.conn = sqlite3.connect(str(self.session_file))
        self.conn.row_factory = sqlite3.Row  # Enable column access by name
        
        # Create tables
        self._create_tables()
        
        # Store session metadata
        self._store_session_metadata()
    
    def _create_tables(self):
        """Create database tables for session storage."""
        cursor = self.conn.cursor()
        
        # Sessions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                target_url TEXT NOT NULL,
                method TEXT NOT NULL,
                start_time REAL NOT NULL,
                end_time REAL,
                config_json TEXT NOT NULL,
                status TEXT DEFAULT 'running'
            )
        """)
        
        # Injection points table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS injection_points (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                url TEXT NOT NULL,
                method TEXT NOT NULL,
                parameter TEXT NOT NULL,
                param_type TEXT NOT NULL,
                original_value TEXT NOT NULL,
                location TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions (id)
            )
        """)
        
        # Test results table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS test_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                injection_point_id INTEGER NOT NULL,
                payload TEXT NOT NULL,
                tamper_used TEXT,
                response_status INTEGER NOT NULL,
                response_length INTEGER NOT NULL,
                response_time REAL NOT NULL,
                response_body TEXT,
                response_headers TEXT,
                vulnerable BOOLEAN NOT NULL,
                injection_type TEXT,
                db_type TEXT,
                error_message TEXT,
                timestamp REAL NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions (id),
                FOREIGN KEY (injection_point_id) REFERENCES injection_points (id)
            )
        """)
        
        # Extracted data table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS extracted_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                injection_point_id INTEGER NOT NULL,
                data_type TEXT NOT NULL,
                data_value TEXT NOT NULL,
                extraction_method TEXT NOT NULL,
                timestamp REAL NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions (id),
                FOREIGN KEY (injection_point_id) REFERENCES injection_points (id)
            )
        """)
        
        # Scan progress table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_progress (
                session_id TEXT PRIMARY KEY,
                current_injection_point INTEGER,
                total_injection_points INTEGER,
                completed_tests INTEGER,
                total_tests INTEGER,
                last_update REAL NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions (id)
            )
        """)
        
        self.conn.commit()
    
    def _store_session_metadata(self):
        """Store session metadata."""
        cursor = self.conn.cursor()
        
        cursor.execute("""
            INSERT INTO sessions (id, target_url, method, start_time, config_json)
            VALUES (?, ?, ?, ?, ?)
        """, (
            self.session_id,
            self.config.target_url,
            self.config.method,
            time.time(),
            json.dumps(asdict(self.config), default=str)
        ))
        
        self.conn.commit()
        self.logger.info(f"Created session {self.session_id}")
    
    def store_injection_point(self, injection_point: InjectionPoint) -> int:
        """
        Store an injection point in the database.
        
        Args:
            injection_point: Injection point to store
            
        Returns:
            Database ID of the stored injection point
        """
        cursor = self.conn.cursor()
        
        cursor.execute("""
            INSERT INTO injection_points 
            (session_id, url, method, parameter, param_type, original_value, location)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            self.session_id,
            injection_point.url,
            injection_point.method,
            injection_point.parameter,
            injection_point.param_type,
            injection_point.original_value,
            injection_point.location
        ))
        
        self.conn.commit()
        return cursor.lastrowid
    
    def store_test_result(self, test_result: TestResult, injection_point_id: int):
        """
        Store a test result in the database.
        
        Args:
            test_result: Test result to store
            injection_point_id: Database ID of the injection point
        """
        cursor = self.conn.cursor()
        
        cursor.execute("""
            INSERT INTO test_results 
            (session_id, injection_point_id, payload, tamper_used, response_status,
             response_length, response_time, response_body, response_headers,
             vulnerable, injection_type, db_type, error_message, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            self.session_id,
            injection_point_id,
            test_result.payload,
            json.dumps(test_result.tamper_used),
            test_result.response_status,
            test_result.response_length,
            test_result.response_time,
            test_result.response_body,
            json.dumps(test_result.response_headers),
            test_result.vulnerable,
            test_result.injection_type.value if test_result.injection_type else None,
            test_result.db_type.value if test_result.db_type else None,
            test_result.error_message,
            test_result.timestamp
        ))
        
        self.conn.commit()
    
    def store_extracted_data(self, injection_point_id: int, data_type: str, 
                           data_value: str, extraction_method: str):
        """
        Store extracted data.
        
        Args:
            injection_point_id: Database ID of the injection point
            data_type: Type of data (version, tables, columns, etc.)
            data_value: The extracted data
            extraction_method: Method used for extraction
        """
        cursor = self.conn.cursor()
        
        cursor.execute("""
            INSERT INTO extracted_data 
            (session_id, injection_point_id, data_type, data_value, extraction_method, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            self.session_id,
            injection_point_id,
            data_type,
            data_value,
            extraction_method,
            time.time()
        ))
        
        self.conn.commit()
    
    def update_scan_progress(self, current_point: int, total_points: int, 
                           completed_tests: int, total_tests: int):
        """
        Update scan progress.
        
        Args:
            current_point: Current injection point being tested
            total_points: Total number of injection points
            completed_tests: Number of completed tests
            total_tests: Total number of tests
        """
        cursor = self.conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO scan_progress 
            (session_id, current_injection_point, total_injection_points,
             completed_tests, total_tests, last_update)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            self.session_id,
            current_point,
            total_points,
            completed_tests,
            total_tests,
            time.time()
        ))
        
        self.conn.commit()
    
    def get_session_results(self) -> List[TestResult]:
        """
        Get all test results for the current session.
        
        Returns:
            List of test results
        """
        cursor = self.conn.cursor()
        
        cursor.execute("""
            SELECT tr.*, ip.url, ip.method, ip.parameter, ip.param_type, 
                   ip.original_value, ip.location
            FROM test_results tr
            JOIN injection_points ip ON tr.injection_point_id = ip.id
            WHERE tr.session_id = ?
            ORDER BY tr.timestamp
        """, (self.session_id,))
        
        results = []
        for row in cursor.fetchall():
            # Reconstruct injection point
            injection_point = InjectionPoint(
                url=row['url'],
                method=row['method'],
                parameter=row['parameter'],
                param_type=row['param_type'],
                original_value=row['original_value'],
                location=row['location']
            )
            
            # Reconstruct test result
            from ..core.base import InjectionType, DBType
            
            injection_type = None
            if row['injection_type']:
                injection_type = InjectionType(row['injection_type'])
            
            db_type = None
            if row['db_type']:
                db_type = DBType(row['db_type'])
            
            test_result = TestResult(
                injection_point=injection_point,
                payload=row['payload'],
                tamper_used=json.loads(row['tamper_used'] or '[]'),
                response_status=row['response_status'],
                response_length=row['response_length'],
                response_time=row['response_time'],
                response_body=row['response_body'],
                response_headers=json.loads(row['response_headers'] or '{}'),
                vulnerable=bool(row['vulnerable']),
                injection_type=injection_type,
                db_type=db_type,
                error_message=row['error_message'],
                timestamp=row['timestamp']
            )
            
            results.append(test_result)
        
        return results
    
    def get_vulnerable_results(self) -> List[TestResult]:
        """Get only vulnerable test results."""
        results = self.get_session_results()
        return [result for result in results if result.vulnerable]
    
    def get_scan_statistics(self) -> Dict[str, Any]:
        """
        Get scan statistics for the current session.
        
        Returns:
            Dictionary containing scan statistics
        """
        cursor = self.conn.cursor()
        
        # Get basic counts
        cursor.execute("""
            SELECT 
                COUNT(*) as total_tests,
                SUM(CASE WHEN vulnerable = 1 THEN 1 ELSE 0 END) as vulnerable_count
            FROM test_results 
            WHERE session_id = ?
        """, (self.session_id,))
        
        basic_stats = cursor.fetchone()
        
        # Get injection type distribution
        cursor.execute("""
            SELECT injection_type, COUNT(*) as count
            FROM test_results 
            WHERE session_id = ? AND vulnerable = 1 AND injection_type IS NOT NULL
            GROUP BY injection_type
        """, (self.session_id,))
        
        injection_types = {row['injection_type']: row['count'] for row in cursor.fetchall()}
        
        # Get database type distribution
        cursor.execute("""
            SELECT db_type, COUNT(*) as count
            FROM test_results 
            WHERE session_id = ? AND vulnerable = 1 AND db_type IS NOT NULL
            GROUP BY db_type
        """, (self.session_id,))
        
        db_types = {row['db_type']: row['count'] for row in cursor.fetchall()}
        
        # Get session metadata
        cursor.execute("""
            SELECT start_time, end_time, target_url
            FROM sessions 
            WHERE id = ?
        """, (self.session_id,))
        
        session_info = cursor.fetchone()
        
        return {
            'session_id': self.session_id,
            'target_url': session_info['target_url'],
            'start_time': session_info['start_time'],
            'end_time': session_info['end_time'],
            'total_tests': basic_stats['total_tests'],
            'vulnerable_count': basic_stats['vulnerable_count'],
            'injection_types': injection_types,
            'database_types': db_types
        }
    
    def finish_session(self):
        """Mark the session as finished."""
        cursor = self.conn.cursor()
        
        cursor.execute("""
            UPDATE sessions 
            SET end_time = ?, status = 'completed'
            WHERE id = ?
        """, (time.time(), self.session_id))
        
        self.conn.commit()
        self.logger.info(f"Finished session {self.session_id}")
    
    def close(self):
        """Close the database connection."""
        if hasattr(self, 'conn'):
            self.conn.close()
    
    @classmethod
    def list_sessions(cls, session_dir: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List all available sessions.
        
        Args:
            session_dir: Directory containing session files
            
        Returns:
            List of session information
        """
        if session_dir:
            sessions_path = Path(session_dir)
        else:
            sessions_path = Path.home() / ".sqlinjector" / "sessions"
        
        if not sessions_path.exists():
            return []
        
        sessions = []
        for db_file in sessions_path.glob("session_*.db"):
            try:
                conn = sqlite3.connect(str(db_file))
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT id, target_url, method, start_time, end_time, status
                    FROM sessions
                    ORDER BY start_time DESC
                """)
                
                for row in cursor.fetchall():
                    sessions.append({
                        'session_id': row['id'],
                        'target_url': row['target_url'],
                        'method': row['method'],
                        'start_time': row['start_time'],
                        'end_time': row['end_time'],
                        'status': row['status'],
                        'file_path': str(db_file)
                    })
                
                conn.close()
                
            except sqlite3.Error:
                # Skip corrupted database files
                continue
        
        return sorted(sessions, key=lambda x: x['start_time'], reverse=True)
    
    @classmethod
    def load_session(cls, session_id: str, session_dir: Optional[str] = None) -> Optional['SessionManager']:
        """
        Load an existing session.
        
        Args:
            session_id: Session ID to load
            session_dir: Directory containing session files
            
        Returns:
            SessionManager instance or None if not found
        """
        sessions = cls.list_sessions(session_dir)
        
        for session in sessions:
            if session['session_id'] == session_id:
                # Create a dummy config (would need to load from session data)
                config = ScanConfig(target_url=session['target_url'])
                
                # Create session manager with existing session
                manager = cls(config, session_dir)
                manager.session_id = session_id
                manager.session_file = Path(session['file_path'])
                
                # Connect to existing database
                manager.conn = sqlite3.connect(str(manager.session_file))
                manager.conn.row_factory = sqlite3.Row
                
                return manager
        
        return None