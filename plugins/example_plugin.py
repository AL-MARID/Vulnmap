"""
Example Custom Plugin
Demonstrates how to create a custom vulnerability scanner plugin
"""
import re
from typing import Dict, List
from core.plugin_manager import PluginBase
class ExamplePlugin(PluginBase):
    """Example plugin that checks for custom security headers."""
    name = "Example Security Header Checker"
    version = "1.0.0"
    author = "AL-MARID"
    description = "Checks for custom security headers (example plugin)"
    def scan(self, url: str, context: Dict) -> List[Dict]:
        """
        Scan for missing custom security headers.
        Args:
            url: Target URL
            context: Context containing response data
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        try:
            response = context.get('response')
            if not response:
                return vulnerabilities
            headers = response.headers
            custom_headers = {
                'X-Custom-Security': 'Custom security header missing',
                'X-Rate-Limit': 'Rate limiting header missing',
                'X-API-Version': 'API version header missing',
            }
            for header, description in custom_headers.items():
                if header not in headers:
                    vulnerabilities.append({
                        'type': 'Missing Custom Header',
                        'severity': 'info',
                        'url': url,
                        'evidence': f'Missing header: {header}',
                        'description': description,
                        'remediation': f'Add {header} header to responses',
                        'plugin': self.name
                    })
        except Exception as e:
            pass
        return vulnerabilities
