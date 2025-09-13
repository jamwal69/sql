"""
HTTP client engine for SQL injection testing.
Provides comprehensive HTTP request capabilities with authentication, proxies, and session management.
"""
import asyncio
import time
from typing import Dict, Any, Optional, Union, List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import json
import re

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False
    import requests

from ..core.base import BaseModule, ScanConfig, TestResult, InjectionPoint
from ..utils.logger import get_logger


class HTTPEngine(BaseModule):
    """
    Advanced HTTP client for SQL injection testing.
    Supports sync/async operations, authentication, proxies, and session management.
    """
    
    def __init__(self, config: ScanConfig):
        super().__init__(config)
        self.logger = get_logger("http_engine")
        self.session = None
        self.async_session = None
        self._setup_session()
    
    def _setup_session(self):
        """Set up HTTP session with configuration."""
        if HTTPX_AVAILABLE:
            # Use httpx for modern async support
            self._setup_httpx_session()
        else:
            # Fallback to requests
            self._setup_requests_session()
    
    def _setup_httpx_session(self):
        """Set up httpx session."""
        client_config = {
            'timeout': httpx.Timeout(self.config.request_timeout),
            'follow_redirects': True,
            'verify': False  # Allow self-signed certificates for testing
        }
        
        # Proxy configuration
        if self.config.proxy_url:
            client_config['proxies'] = self.config.proxy_url
        
        # Headers
        headers = {
            'User-Agent': 'SQLInjector/1.0 (Security Testing Tool)',
            **self.config.headers
        }
        client_config['headers'] = headers
        
        self.session = httpx.Client(**client_config)
        self.async_session = httpx.AsyncClient(**client_config)
    
    def _setup_requests_session(self):
        """Set up requests session as fallback."""
        self.session = requests.Session()
        
        # Headers
        self.session.headers.update({
            'User-Agent': 'SQLInjector/1.0 (Security Testing Tool)',
            **self.config.headers
        })
        
        # Proxy configuration
        if self.config.proxy_url:
            self.session.proxies = {
                'http': self.config.proxy_url,
                'https': self.config.proxy_url
            }
        
        # Disable SSL warnings for testing
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.session.verify = False
    
    def make_request(self, url: str, method: str = "GET", data: Dict[str, Any] = None, 
                    headers: Dict[str, str] = None, cookies: Dict[str, str] = None,
                    timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        Make a synchronous HTTP request.
        
        Args:
            url: Target URL
            method: HTTP method
            data: Request data
            headers: Additional headers
            cookies: Cookies to send
            timeout: Request timeout
            
        Returns:
            Dictionary containing response data
        """
        start_time = time.time()
        
        try:
            request_config = {
                'timeout': timeout or self.config.request_timeout
            }
            
            # Merge headers
            if headers:
                request_config['headers'] = {**self.config.headers, **headers}
            
            # Merge cookies
            if cookies:
                request_config['cookies'] = {**self.config.cookies, **cookies}
            
            # Handle authentication
            if self.config.auth_type:
                self._add_authentication(request_config)
            
            # Make request
            if HTTPX_AVAILABLE:
                response = self.session.request(method, url, **request_config, **self._prepare_data(data, method))
            else:
                response = self.session.request(method, url, **request_config, **self._prepare_data(data, method))
            
            end_time = time.time()
            
            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.text,
                'content_bytes': response.content,
                'response_time': end_time - start_time,
                'url': str(response.url) if hasattr(response, 'url') else url,
                'request': {
                    'method': method,
                    'url': url,
                    'headers': request_config.get('headers', {}),
                    'data': data
                }
            }
            
        except Exception as e:
            end_time = time.time()
            self.logger.error(f"Request failed: {e}")
            return {
                'status_code': 0,
                'headers': {},
                'content': '',
                'content_bytes': b'',
                'response_time': end_time - start_time,
                'url': url,
                'error': str(e),
                'request': {
                    'method': method,
                    'url': url,
                    'headers': headers or {},
                    'data': data
                }
            }
    
    async def make_async_request(self, url: str, method: str = "GET", data: Dict[str, Any] = None,
                               headers: Dict[str, str] = None, cookies: Dict[str, str] = None,
                               timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        Make an asynchronous HTTP request.
        
        Args:
            url: Target URL
            method: HTTP method
            data: Request data
            headers: Additional headers
            cookies: Cookies to send
            timeout: Request timeout
            
        Returns:
            Dictionary containing response data
        """
        if not HTTPX_AVAILABLE or not self.async_session:
            # Fall back to sync request
            return self.make_request(url, method, data, headers, cookies, timeout)
        
        start_time = time.time()
        
        try:
            request_config = {
                'timeout': timeout or self.config.request_timeout
            }
            
            # Merge headers
            if headers:
                request_config['headers'] = {**self.config.headers, **headers}
            
            # Merge cookies
            if cookies:
                request_config['cookies'] = {**self.config.cookies, **cookies}
            
            # Handle authentication
            if self.config.auth_type:
                self._add_authentication(request_config)
            
            # Make async request
            response = await self.async_session.request(method, url, **request_config, **self._prepare_data(data, method))
            
            end_time = time.time()
            
            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.text,
                'content_bytes': response.content,
                'response_time': end_time - start_time,
                'url': str(response.url),
                'request': {
                    'method': method,
                    'url': url,
                    'headers': request_config.get('headers', {}),
                    'data': data
                }
            }
            
        except Exception as e:
            end_time = time.time()
            self.logger.error(f"Async request failed: {e}")
            return {
                'status_code': 0,
                'headers': {},
                'content': '',
                'content_bytes': b'',
                'response_time': end_time - start_time,
                'url': url,
                'error': str(e),
                'request': {
                    'method': method,
                    'url': url,
                    'headers': headers or {},
                    'data': data
                }
            }
    
    def _prepare_data(self, data: Dict[str, Any], method: str) -> Dict[str, Any]:
        """Prepare data for the request based on method and content type."""
        if not data:
            return {}
        
        if method.upper() in ['GET', 'DELETE']:
            # For GET/DELETE, add to params
            return {'params': data}
        else:
            # For POST/PUT/PATCH, determine if JSON or form data
            if isinstance(data, dict) and self._is_json_data(data):
                return {'json': data}
            else:
                return {'data': data}
    
    def _is_json_data(self, data: Dict[str, Any]) -> bool:
        """Determine if data should be sent as JSON."""
        # Check if any values are complex types (dict, list)
        for value in data.values():
            if isinstance(value, (dict, list)):
                return True
        
        # Check content-type header
        content_type = self.config.headers.get('Content-Type', '').lower()
        return 'application/json' in content_type
    
    def _add_authentication(self, request_config: Dict[str, Any]):
        """Add authentication to request configuration."""
        if self.config.auth_type == 'basic':
            if ':' in self.config.auth_data.get('credentials', ''):
                username, password = self.config.auth_data['credentials'].split(':', 1)
                if HTTPX_AVAILABLE:
                    request_config['auth'] = (username, password)
                else:
                    from requests.auth import HTTPBasicAuth
                    request_config['auth'] = HTTPBasicAuth(username, password)
        
        elif self.config.auth_type == 'bearer':
            token = self.config.auth_data.get('token', '')
            if 'headers' not in request_config:
                request_config['headers'] = {}
            request_config['headers']['Authorization'] = f'Bearer {token}'
        
        elif self.config.auth_type == 'form':
            # Form-based authentication would require a login flow
            # This is a placeholder for more complex auth scenarios
            pass
    
    def extract_injection_points(self, url: str, method: str = "GET", 
                                data: Dict[str, Any] = None) -> List[InjectionPoint]:
        """
        Extract potential injection points from a URL and data.
        
        Args:
            url: Target URL
            method: HTTP method
            data: Request data
            
        Returns:
            List of injection points
        """
        injection_points = []
        
        # Parse URL
        parsed_url = urlparse(url)
        
        # GET parameters
        if self.config.test_get_params and parsed_url.query:
            query_params = parse_qs(parsed_url.query, keep_blank_values=True)
            for param, values in query_params.items():
                for i, value in enumerate(values):
                    injection_points.append(InjectionPoint(
                        url=url,
                        method="GET",
                        parameter=param,
                        param_type="GET",
                        original_value=value,
                        location=f"query[{param}][{i}]" if len(values) > 1 else f"query[{param}]"
                    ))
        
        # POST/form parameters
        if self.config.test_post_params and data and method.upper() != "GET":
            if isinstance(data, dict):
                for param, value in data.items():
                    if isinstance(value, (str, int, float)):
                        injection_points.append(InjectionPoint(
                            url=url,
                            method=method,
                            parameter=param,
                            param_type="POST",
                            original_value=str(value),
                            location=f"body[{param}]"
                        ))
                    elif isinstance(value, dict) and self.config.test_json:
                        # Handle nested JSON
                        self._extract_json_points(injection_points, url, method, value, param)
        
        # Headers
        if self.config.test_headers:
            testable_headers = ['User-Agent', 'Referer', 'X-Forwarded-For', 'X-Real-IP']
            for header in testable_headers:
                injection_points.append(InjectionPoint(
                    url=url,
                    method=method,
                    parameter=header,
                    param_type="HEADER",
                    original_value=self.config.headers.get(header, ''),
                    location=f"header[{header}]"
                ))
        
        # Cookies
        if self.config.test_cookies:
            for cookie, value in self.config.cookies.items():
                injection_points.append(InjectionPoint(
                    url=url,
                    method=method,
                    parameter=cookie,
                    param_type="COOKIE",
                    original_value=str(value),
                    location=f"cookie[{cookie}]"
                ))
        
        return injection_points
    
    def _extract_json_points(self, injection_points: List[InjectionPoint], url: str, 
                           method: str, data: Dict[str, Any], path: str = ""):
        """Recursively extract injection points from JSON data."""
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key
            
            if isinstance(value, (str, int, float)):
                injection_points.append(InjectionPoint(
                    url=url,
                    method=method,
                    parameter=key,
                    param_type="JSON",
                    original_value=str(value),
                    location=current_path
                ))
            elif isinstance(value, dict):
                self._extract_json_points(injection_points, url, method, value, current_path)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, (str, int, float)):
                        injection_points.append(InjectionPoint(
                            url=url,
                            method=method,
                            parameter=f"{key}[{i}]",
                            param_type="JSON",
                            original_value=str(item),
                            location=f"{current_path}[{i}]"
                        ))
    
    def build_request_with_payload(self, injection_point: InjectionPoint, 
                                 payload: str) -> Dict[str, Any]:
        """
        Build a request with the payload injected at the specified injection point.
        
        Args:
            injection_point: The injection point to test
            payload: The payload to inject
            
        Returns:
            Dictionary with request parameters
        """
        url = injection_point.url
        method = injection_point.method
        data = {}
        headers = dict(self.config.headers)
        cookies = dict(self.config.cookies)
        
        if injection_point.param_type == "GET":
            # Modify URL parameters
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query, keep_blank_values=True)
            
            # Update the specific parameter
            if injection_point.parameter in query_params:
                query_params[injection_point.parameter][0] = payload
            else:
                query_params[injection_point.parameter] = [payload]
            
            # Rebuild URL
            new_query = urlencode(query_params, doseq=True)
            url = urlunparse((
                parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                parsed_url.params, new_query, parsed_url.fragment
            ))
        
        elif injection_point.param_type == "POST":
            # Modify POST data
            if hasattr(self, '_original_data'):
                data = dict(self._original_data)
            data[injection_point.parameter] = payload
        
        elif injection_point.param_type == "JSON":
            # Modify JSON data
            if hasattr(self, '_original_data'):
                data = self._deep_copy_with_payload(self._original_data, 
                                                  injection_point.location, payload)
        
        elif injection_point.param_type == "HEADER":
            # Modify headers
            headers[injection_point.parameter] = payload
        
        elif injection_point.param_type == "COOKIE":
            # Modify cookies
            cookies[injection_point.parameter] = payload
        
        return {
            'url': url,
            'method': method,
            'data': data if data else None,
            'headers': headers,
            'cookies': cookies
        }
    
    def _deep_copy_with_payload(self, data: Dict[str, Any], path: str, payload: str) -> Dict[str, Any]:
        """Deep copy data structure and inject payload at specified path."""
        import copy
        result = copy.deepcopy(data)
        
        # Navigate to the target location
        parts = path.split('.')
        current = result
        
        for i, part in enumerate(parts[:-1]):
            if '[' in part and ']' in part:
                # Handle array notation like "key[0]"
                key, index = part.split('[')
                index = int(index.rstrip(']'))
                current = current[key][index]
            else:
                current = current[part]
        
        # Set the payload at the target location
        final_part = parts[-1]
        if '[' in final_part and ']' in final_part:
            key, index = final_part.split('[')
            index = int(index.rstrip(']'))
            current[key][index] = payload
        else:
            current[final_part] = payload
        
        return result
    
    def close(self):
        """Clean up sessions."""
        if self.session:
            if HTTPX_AVAILABLE:
                self.session.close()
            else:
                self.session.close()
        
        if self.async_session:
            asyncio.create_task(self.async_session.aclose())


class RequestThrottler:
    """Manages request throttling and rate limiting."""
    
    def __init__(self, delay: float = 0.1):
        self.delay = delay
        self.last_request_time = 0
    
    def wait(self):
        """Wait if necessary to maintain rate limit."""
        if self.delay > 0:
            current_time = time.time()
            time_since_last = current_time - self.last_request_time
            if time_since_last < self.delay:
                time.sleep(self.delay - time_since_last)
            self.last_request_time = time.time()


class RetryHandler:
    """Handles request retries with exponential backoff."""
    
    def __init__(self, max_retries: int = 3, base_delay: float = 1.0):
        self.max_retries = max_retries
        self.base_delay = base_delay
    
    def should_retry(self, attempt: int, response: Dict[str, Any]) -> bool:
        """Determine if a request should be retried."""
        if attempt >= self.max_retries:
            return False
        
        # Retry on connection errors
        if 'error' in response:
            return True
        
        # Retry on server errors (5xx)
        if response.get('status_code', 0) >= 500:
            return True
        
        return False
    
    def get_delay(self, attempt: int) -> float:
        """Get delay for retry attempt with exponential backoff."""
        return self.base_delay * (2 ** attempt)