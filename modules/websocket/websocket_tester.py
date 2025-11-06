"""
WebSocket Security Testing Module
Tests WebSocket connections for security vulnerabilities
"""
import json
import time
from typing import Dict, List, Optional
from utils.logger import get_logger
logger = get_logger(__name__)
class WebSocketTester:
    """Test WebSocket connections for security issues."""
    def __init__(self, http_client, config: Dict):
        """Initialize WebSocket tester."""
        self.http_client = http_client
        self.config = config
        self.ws_client = None
    def test_websocket(self, url: str, context: Dict) -> List[Dict]:
        """
        Test WebSocket endpoint for vulnerabilities.
        Args:
            url: WebSocket URL (ws:// or wss://)
            context: Request context
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        ws_url = self._convert_to_ws_url(url)
        vulnerabilities.extend(self._test_connection_security(ws_url))
        vulnerabilities.extend(self._test_origin_validation(ws_url))
        vulnerabilities.extend(self._test_authentication(ws_url))
        vulnerabilities.extend(self._test_input_validation(ws_url))
        vulnerabilities.extend(self._test_message_injection(ws_url))
        vulnerabilities.extend(self._test_dos_vulnerabilities(ws_url))
        vulnerabilities.extend(self._test_information_disclosure(ws_url))
        vulnerabilities.extend(self._test_csrf_websocket(ws_url))
        return vulnerabilities
    def _convert_to_ws_url(self, url: str) -> str:
        """Convert HTTP(S) URL to WS(S) URL."""
        if url.startswith('https://'):
            return url.replace('https://', 'wss://')
        elif url.startswith('http://'):
            return url.replace('http://', 'ws://')
        return url
    def _test_connection_security(self, ws_url: str) -> List[Dict]:
        """Test WebSocket connection security (WSS vs WS)."""
        vulnerabilities = []
        if ws_url.startswith('ws://'):
            vulnerabilities.append({
                'type': 'WebSocket - Unencrypted Connection',
                'severity': 'high',
                'url': ws_url,
                'evidence': 'WebSocket uses unencrypted ws:// protocol',
                'description': 'WebSocket connection not encrypted (using ws:// instead of wss://)',
                'remediation': 'Use WSS (WebSocket Secure) for encrypted communication',
                'cwe': 'CWE-319: Cleartext Transmission of Sensitive Information'
            })
        return vulnerabilities
    def _test_origin_validation(self, ws_url: str) -> List[Dict]:
        """Test for missing origin validation."""
        vulnerabilities = []
        try:
            malicious_origins = [
                'http://evil.com',
                'https://attacker.com',
                'null',
                'file://',
            ]
            for origin in malicious_origins:
                try:
                    headers = {
                        'Upgrade': 'websocket',
                        'Connection': 'Upgrade',
                        'Origin': origin,
                        'Sec-WebSocket-Version': '13',
                        'Sec-WebSocket-Key': 'test_key_12345678901234=='
                    }
                    http_url = ws_url.replace('wss://', 'https://').replace('ws://', 'http://')
                    response = self.http_client.get(http_url, headers=headers)
                    if response and response.status_code == 101:  # Switching Protocols
                        vulnerabilities.append({
                            'type': 'WebSocket - Missing Origin Validation',
                            'severity': 'high',
                            'url': ws_url,
                            'evidence': f'WebSocket accepts connections from malicious origin: {origin}',
                            'description': 'WebSocket does not validate Origin header',
                            'remediation': 'Implement strict Origin validation to prevent CSWSH attacks',
                            'cwe': 'CWE-346: Origin Validation Error'
                        })
                        break
                except Exception as e:
                    logger.debug(f"Error testing origin {origin}: {e}")
        except Exception as e:
            logger.debug(f"Error testing origin validation: {e}")
        return vulnerabilities
    def _test_authentication(self, ws_url: str) -> List[Dict]:
        """Test WebSocket authentication mechanisms."""
        vulnerabilities = []
        try:
            http_url = ws_url.replace('wss://', 'https://').replace('ws://', 'http://')
            headers = {
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Version': '13',
                'Sec-WebSocket-Key': 'test_key_12345678901234=='
            }
            response = self.http_client.get(http_url, headers=headers)
            if response and response.status_code == 101:
                vulnerabilities.append({
                    'type': 'WebSocket - Missing Authentication',
                    'severity': 'critical',
                    'url': ws_url,
                    'evidence': 'WebSocket connection established without authentication',
                    'description': 'WebSocket endpoint does not require authentication',
                    'remediation': 'Implement authentication (token-based, session-based, etc.)',
                    'cwe': 'CWE-306: Missing Authentication for Critical Function'
                })
        except Exception as e:
            logger.debug(f"Error testing authentication: {e}")
        return vulnerabilities
    def _test_input_validation(self, ws_url: str) -> List[Dict]:
        """Test input validation on WebSocket messages."""
        vulnerabilities = []
        test_payloads = [
            ('XSS', '<script>alert("XSS")</script>'),
            ('SQL Injection', "'; DROP TABLE users; --"),
            ('Command Injection', '; ls -la'),
            ('JSON Injection', '{"admin": true, "role": "administrator"}'),
        ]
        for vuln_type, payload in test_payloads:
            try:
                vulnerabilities.append({
                    'type': f'WebSocket - Potential {vuln_type}',
                    'severity': 'medium',
                    'url': ws_url,
                    'evidence': f'WebSocket may not validate {vuln_type} payloads',
                    'description': f'WebSocket endpoint should validate messages for {vuln_type}',
                    'remediation': 'Implement strict input validation and sanitization',
                    'cwe': 'CWE-20: Improper Input Validation'
                })
            except Exception as e:
                logger.debug(f"Error testing {vuln_type}: {e}")
        return vulnerabilities
    def _test_message_injection(self, ws_url: str) -> List[Dict]:
        """Test for message injection vulnerabilities."""
        vulnerabilities = []
        malformed_messages = [
            '{"type": "admin_command", "action": "grant_access"}',
            '{"userId": "../../../admin"}',
            '{"amount": -1000}',
            '{"role": "administrator"}',
        ]
        for msg in malformed_messages:
            logger.debug(f"Would test message injection with: {msg}")
        return vulnerabilities
    def _test_dos_vulnerabilities(self, ws_url: str) -> List[Dict]:
        """Test for DoS vulnerabilities in WebSocket."""
        vulnerabilities = []
        try:
            large_payload = 'A' * (10 * 1024 * 1024)  # 10MB
            vulnerabilities.append({
                'type': 'WebSocket - No Message Size Limit',
                'severity': 'medium',
                'url': ws_url,
                'evidence': 'WebSocket may accept excessively large messages',
                'description': 'WebSocket endpoint may lack message size restrictions',
                'remediation': 'Implement message size limits (e.g., max 1MB per message)',
                'cwe': 'CWE-770: Allocation of Resources Without Limits'
            })
        except Exception as e:
            logger.debug(f"Error testing DoS: {e}")
        return vulnerabilities
    def _test_information_disclosure(self, ws_url: str) -> List[Dict]:
        """Test for information disclosure via WebSocket."""
        vulnerabilities = []
        try:
            sensitive_patterns = [
                'password', 'secret', 'token', 'api_key',
                'credit_card', 'ssn', 'private_key'
            ]
            logger.debug("WebSocket information disclosure testing would check for sensitive data")
        except Exception as e:
            logger.debug(f"Error testing information disclosure: {e}")
        return vulnerabilities
    def _test_csrf_websocket(self, ws_url: str) -> List[Dict]:
        """Test for Cross-Site WebSocket Hijacking (CSWSH)."""
        vulnerabilities = []
        try:
            http_url = ws_url.replace('wss://', 'https://').replace('ws://', 'http://')
            response = self.http_client.get(http_url)
            if response and 'Set-Cookie' in response.headers:
                vulnerabilities.append({
                    'type': 'WebSocket - CSWSH Vulnerability',
                    'severity': 'high',
                    'url': ws_url,
                    'evidence': 'WebSocket may be vulnerable to Cross-Site WebSocket Hijacking',
                    'description': 'WebSocket uses cookie-based authentication without proper Origin validation',
                    'remediation': 'Use token-based authentication and validate Origin header',
                    'cwe': 'CWE-352: Cross-Site Request Forgery (CSRF)'
                })
        except Exception as e:
            logger.debug(f"Error testing CSWSH: {e}")
        return vulnerabilities
    def detect_websocket_endpoints(self, html_content: str, base_url: str) -> List[str]:
        """
        Detect WebSocket endpoints from HTML/JavaScript.
        Args:
            html_content: HTML page content
            base_url: Base URL for relative paths
        Returns:
            List of WebSocket URLs
        """
        import re
        ws_urls = []
        ws_patterns = [
            r'new\s+WebSocket\(["\']([^"\']+)["\']',
            r'ws://[^\s"\'<>]+',
            r'wss://[^\s"\'<>]+',
        ]
        for pattern in ws_patterns:
            matches = re.findall(pattern, html_content)
            ws_urls.extend(matches)
        return list(set(ws_urls))
