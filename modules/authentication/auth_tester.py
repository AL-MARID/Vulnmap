"""
Authentication Testing Module
Comprehensive authentication and session management testing
"""
from typing import Dict, List
import re
from utils.logger import get_logger
logger = get_logger(__name__)
class AuthenticationTester:
    """Test authentication mechanisms and session management."""
    def __init__(self, http_client, config: Dict):
        """Initialize authentication tester."""
        self.http_client = http_client
        self.config = config
    def test_authentication(self, url: str, context: Dict) -> List[Dict]:
        """
        Test authentication mechanisms.
        Args:
            url: Target URL
            context: Request context
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        vulnerabilities.extend(self._test_weak_passwords(url, context))
        vulnerabilities.extend(self._test_brute_force_protection(url, context))
        vulnerabilities.extend(self._test_credential_stuffing(url, context))
        vulnerabilities.extend(self._test_session_fixation(url, context))
        vulnerabilities.extend(self._test_session_timeout(url, context))
        vulnerabilities.extend(self._test_jwt_security(url, context))
        vulnerabilities.extend(self._test_password_reset(url, context))
        vulnerabilities.extend(self._test_oauth_security(url, context))
        vulnerabilities.extend(self._test_mfa_bypass(url, context))
        return vulnerabilities
    def _test_weak_passwords(self, url: str, context: Dict) -> List[Dict]:
        """Test for weak password acceptance."""
        vulnerabilities = []
        if 'register' in url.lower() or 'signup' in url.lower() or 'password' in url.lower():
            weak_passwords = [
                '123456',
                'password',
                'admin',
                '12345678',
                'qwerty',
                'abc123',
                'password123',
                '1234',
                'admin123'
            ]
            for weak_pass in weak_passwords:
                try:
                    response = self.http_client.post(
                        url,
                        data={
                            'username': 'testuser',
                            'password': weak_pass,
                            'email': 'test@example.com'
                        }
                    )
                    if response and response.status_code in [200, 201, 302]:
                        if 'success' in response.text.lower() or 'welcome' in response.text.lower():
                            vulnerabilities.append({
                                'type': 'Authentication - Weak Password Accepted',
                                'severity': 'high',
                                'url': url,
                                'evidence': f'Weak password accepted: {weak_pass}',
                                'description': 'Application accepts commonly used weak passwords',
                                'remediation': 'Implement strong password policy (min 8 chars, mixed case, numbers, symbols)',
                                'cwe': 'CWE-521: Weak Password Requirements'
                            })
                            break
                except Exception as e:
                    logger.debug(f"Error testing weak passwords: {e}")
        return vulnerabilities
    def _test_brute_force_protection(self, url: str, context: Dict) -> List[Dict]:
        """Test for brute force attack protection."""
        vulnerabilities = []
        if 'login' in url.lower() or 'signin' in url.lower():
            try:
                failed_attempts = 0
                for i in range(20):
                    response = self.http_client.post(
                        url,
                        data={
                            'username': 'admin',
                            'password': f'wrongpass{i}'
                        }
                    )
                    if response:
                        if response.status_code != 429:  # Not rate limited
                            failed_attempts += 1
                        else:
                            break
                if failed_attempts >= 15:
                    vulnerabilities.append({
                        'type': 'Authentication - No Brute Force Protection',
                        'severity': 'high',
                        'url': url,
                        'evidence': f'{failed_attempts} failed login attempts without blocking',
                        'description': 'Application lacks brute force protection',
                        'remediation': 'Implement account lockout after 5 failed attempts, CAPTCHA, rate limiting',
                        'cwe': 'CWE-307: Improper Restriction of Excessive Authentication Attempts'
                    })
            except Exception as e:
                logger.debug(f"Error testing brute force protection: {e}")
        return vulnerabilities
    def _test_credential_stuffing(self, url: str, context: Dict) -> List[Dict]:
        """Test for credential stuffing protection."""
        vulnerabilities = []
        if 'login' in url.lower():
            common_creds = [
                ('admin', 'admin'),
                ('administrator', 'administrator'),
                ('root', 'root'),
                ('test', 'test'),
                ('guest', 'guest')
            ]
            for username, password in common_creds:
                try:
                    response = self.http_client.post(
                        url,
                        data={'username': username, 'password': password}
                    )
                    if response and response.status_code == 200:
                        if 'dashboard' in response.text.lower() or 'welcome' in response.text.lower():
                            vulnerabilities.append({
                                'type': 'Authentication - Default Credentials',
                                'severity': 'critical',
                                'url': url,
                                'evidence': f'Default credentials work: {username}:{password}',
                                'description': 'Application has default credentials enabled',
                                'remediation': 'Remove or force change of default credentials',
                                'cwe': 'CWE-798: Use of Hard-coded Credentials'
                            })
                            break
                except Exception as e:
                    logger.debug(f"Error testing credential stuffing: {e}")
        return vulnerabilities
    def _test_session_fixation(self, url: str, context: Dict) -> List[Dict]:
        """Test for session fixation vulnerabilities."""
        vulnerabilities = []
        if 'login' in url.lower():
            try:
                response1 = self.http_client.get(url)
                if response1 and 'Set-Cookie' in response1.headers:
                    initial_cookie = response1.headers['Set-Cookie']
                    session_id_match = re.search(r'(session|PHPSESSID|JSESSIONID)=([^;]+)', initial_cookie)
                    if session_id_match:
                        initial_session_id = session_id_match.group(2)
                        response2 = self.http_client.post(
                            url,
                            data={'username': 'testuser', 'password': 'testpass'},
                            headers={'Cookie': f'{session_id_match.group(1)}={initial_session_id}'}
                        )
                        if response2 and 'Set-Cookie' in response2.headers:
                            new_cookie = response2.headers['Set-Cookie']
                            new_session_match = re.search(r'(session|PHPSESSID|JSESSIONID)=([^;]+)', new_cookie)
                            if new_session_match:
                                new_session_id = new_session_match.group(2)
                                if initial_session_id == new_session_id:
                                    vulnerabilities.append({
                                        'type': 'Authentication - Session Fixation',
                                        'severity': 'high',
                                        'url': url,
                                        'evidence': 'Session ID not regenerated after login',
                                        'description': 'Application vulnerable to session fixation attacks',
                                        'remediation': 'Regenerate session ID upon authentication',
                                        'cwe': 'CWE-384: Session Fixation'
                                    })
            except Exception as e:
                logger.debug(f"Error testing session fixation: {e}")
        return vulnerabilities
    def _test_session_timeout(self, url: str, context: Dict) -> List[Dict]:
        """Test for proper session timeout."""
        vulnerabilities = []
        try:
            response = self.http_client.get(url)
            if response and 'Set-Cookie' in response.headers:
                cookie_header = response.headers['Set-Cookie']
                if 'Max-Age' not in cookie_header and 'Expires' not in cookie_header:
                    vulnerabilities.append({
                        'type': 'Authentication - No Session Timeout',
                        'severity': 'medium',
                        'url': url,
                        'evidence': 'Session cookie lacks expiration',
                        'description': 'Session cookies have no expiration time',
                        'remediation': 'Set appropriate Max-Age (e.g., 30 minutes for sensitive apps)',
                        'cwe': 'CWE-613: Insufficient Session Expiration'
                    })
                max_age_match = re.search(r'Max-Age=(\d+)', cookie_header)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age > 86400:  # More than 24 hours
                        vulnerabilities.append({
                            'type': 'Authentication - Excessive Session Timeout',
                            'severity': 'medium',
                            'url': url,
                            'evidence': f'Session timeout: {max_age} seconds ({max_age//3600} hours)',
                            'description': 'Session timeout is excessively long',
                            'remediation': 'Reduce session timeout to 30 minutes for sensitive applications',
                            'cwe': 'CWE-613: Insufficient Session Expiration'
                        })
        except Exception as e:
            logger.debug(f"Error testing session timeout: {e}")
        return vulnerabilities
    def _test_jwt_security(self, url: str, context: Dict) -> List[Dict]:
        """Test JWT token security."""
        vulnerabilities = []
        try:
            response = self.http_client.get(url)
            if response:
                auth_header = response.headers.get('Authorization', '')
                jwt_pattern = r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'
                jwt_match = re.search(jwt_pattern, response.text + auth_header)
                if jwt_match:
                    jwt_token = jwt_match.group(0)
                    try:
                        import base64
                        parts = jwt_token.split('.')
                        header = base64.b64decode(parts[0] + '==').decode()
                        modified_header = header.replace('"alg":"HS256"', '"alg":"none"')
                        modified_header = header.replace('"alg":"RS256"', '"alg":"none"')
                        modified_token = base64.b64encode(modified_header.encode()).decode().rstrip('=') + '.' + parts[1] + '.'
                        test_response = self.http_client.get(
                            url,
                            headers={'Authorization': f'Bearer {modified_token}'}
                        )
                        if test_response and test_response.status_code == 200:
                            vulnerabilities.append({
                                'type': 'Authentication - JWT None Algorithm',
                                'severity': 'critical',
                                'url': url,
                                'evidence': 'JWT accepts "none" algorithm',
                                'description': 'JWT implementation accepts unsigned tokens',
                                'remediation': 'Reject tokens with "none" algorithm',
                                'cwe': 'CWE-347: Improper Verification of Cryptographic Signature'
                            })
                    except Exception:
                        pass
        except Exception as e:
            logger.debug(f"Error testing JWT security: {e}")
        return vulnerabilities
    def _test_password_reset(self, url: str, context: Dict) -> List[Dict]:
        """Test password reset functionality."""
        vulnerabilities = []
        if 'reset' in url.lower() or 'forgot' in url.lower():
            try:
                response = self.http_client.post(
                    url,
                    data={'email': 'test@example.com'}
                )
                if response and response.status_code == 200:
                    token_patterns = [
                        r'token=([0-9]{6})',  # 6-digit numeric
                        r'token=([0-9]{4})',  # 4-digit numeric
                        r'token=([a-f0-9]{8})',  # Short hash
                    ]
                    for pattern in token_patterns:
                        if re.search(pattern, response.text):
                            vulnerabilities.append({
                                'type': 'Authentication - Weak Password Reset Token',
                                'severity': 'high',
                                'url': url,
                                'evidence': 'Password reset token appears predictable or short',
                                'description': 'Password reset tokens may be guessable',
                                'remediation': 'Use cryptographically secure random tokens (min 32 chars)',
                                'cwe': 'CWE-640: Weak Password Recovery Mechanism'
                            })
                            break
            except Exception as e:
                logger.debug(f"Error testing password reset: {e}")
        return vulnerabilities
    def _test_oauth_security(self, url: str, context: Dict) -> List[Dict]:
        """Test OAuth implementation security."""
        vulnerabilities = []
        if 'oauth' in url.lower() or 'authorize' in url.lower():
            try:
                if 'state=' not in url:
                    vulnerabilities.append({
                        'type': 'Authentication - Missing OAuth State',
                        'severity': 'high',
                        'url': url,
                        'evidence': 'OAuth flow missing state parameter',
                        'description': 'OAuth implementation lacks CSRF protection',
                        'remediation': 'Include and validate state parameter in OAuth flow',
                        'cwe': 'CWE-352: Cross-Site Request Forgery'
                    })
                if 'redirect_uri=' in url:
                    test_urls = [
                        url.replace('redirect_uri=', 'redirect_uri=https://evil.com'),
                        url + '&redirect_uri=https://evil.com'
                    ]
                    for test_url in test_urls:
                        response = self.http_client.get(test_url)
                        if response and 'evil.com' in response.url:
                            vulnerabilities.append({
                                'type': 'Authentication - OAuth Open Redirect',
                                'severity': 'high',
                                'url': url,
                                'evidence': 'OAuth accepts arbitrary redirect_uri',
                                'description': 'OAuth redirect_uri not properly validated',
                                'remediation': 'Whitelist allowed redirect URIs',
                                'cwe': 'CWE-601: URL Redirection to Untrusted Site'
                            })
                            break
            except Exception as e:
                logger.debug(f"Error testing OAuth security: {e}")
        return vulnerabilities
    def _test_mfa_bypass(self, url: str, context: Dict) -> List[Dict]:
        """Test for MFA bypass vulnerabilities."""
        vulnerabilities = []
        if 'mfa' in url.lower() or '2fa' in url.lower() or 'verify' in url.lower():
            try:
                response = self.http_client.post(
                    url,
                    data={'code': '000000'}
                )
                if response and response.status_code == 200:
                    if 'success' in response.text.lower() or 'dashboard' in response.text.lower():
                        vulnerabilities.append({
                            'type': 'Authentication - MFA Bypass',
                            'severity': 'critical',
                            'url': url,
                            'evidence': 'Invalid MFA code accepted',
                            'description': 'MFA implementation has bypass vulnerability',
                            'remediation': 'Properly validate MFA codes server-side',
                            'cwe': 'CWE-287: Improper Authentication'
                        })
            except Exception as e:
                logger.debug(f"Error testing MFA bypass: {e}")
        return vulnerabilities
