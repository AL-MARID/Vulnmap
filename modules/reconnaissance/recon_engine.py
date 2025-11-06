"""
Reconnaissance Engine
Gathers intelligence about target
"""
import socket
import dns.resolver
from typing import Dict, List
from urllib.parse import urlparse
from utils.logger import get_logger
from modules.reconnaissance.osint_enhanced import EnhancedOSINT
logger = get_logger(__name__)
class ReconEngine:
    """Reconnaissance and intelligence gathering."""
    def __init__(self, config: Dict, http_client):
        """Initialize reconnaissance engine."""
        self.config = config
        self.http_client = http_client
        self.recon_config = config.get('reconnaissance', {})
        self.enabled_modules = self.recon_config.get('enabled_modules', [])
        self.osint_enhanced = EnhancedOSINT(http_client, config)
    def run(self, target_url: str) -> Dict:
        """
        Run reconnaissance on target.
        Args:
            target_url: Target URL
        Returns:
            Reconnaissance results
        """
        results = {
            'target': target_url,
            'domain': self._extract_domain(target_url)
        }
        if 'dns_records' in self.enabled_modules:
            results['dns_records'] = self._get_dns_records(results['domain'])
        if 'whois_lookup' in self.enabled_modules:
            results['whois'] = self._whois_lookup(results['domain'])
        if 'technology_detection' in self.enabled_modules:
            results['technologies'] = self._detect_technologies(target_url)
        if 'ssl_certificate_info' in self.enabled_modules:
            results['ssl_info'] = self._get_ssl_info(results['domain'])
        if 'subdomain_enumeration' in self.enabled_modules:
            results['subdomains'] = self._enumerate_subdomains(results['domain'])
        if 'osint_gathering' in self.enabled_modules:
            logger.info(f"Running OSINT intelligence gathering on {results['domain']}")
            osint_results = self.osint_enhanced.gather_intelligence(results['domain'])
            results['osint'] = osint_results
            results['osint']['emails'] = osint_results.get('email_addresses', [])
            results['osint']['subdomains'] = osint_results.get('certificate_transparency', [])
            results['osint']['technologies'] = osint_results.get('technology_intelligence', {})
            results['osint']['breaches'] = osint_results.get('data_breaches', [])
            results['osint']['github_leaks'] = osint_results.get('exposed_files', [])
            results['osint']['social_media'] = osint_results.get('social_media', {})
            results['osint']['cloud_resources'] = osint_results.get('cloud_resources', {})
        if 'dns_records' not in results and results.get('domain'):
            results['dns'] = self._get_dns_records(results['domain'])
        return results
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        parsed = urlparse(url)
        return parsed.netloc
    def _get_dns_records(self, domain: str) -> Dict:
        """Get DNS records for domain."""
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except Exception as e:
                logger.debug(f"No {record_type} records for {domain}: {e}")
                records[record_type] = []
        return records
    def _whois_lookup(self, domain: str) -> Dict:
        """Perform WHOIS lookup."""
        return {
            'status': 'Not implemented',
            'registrar': 'N/A',
            'creation_date': 'N/A',
            'expiration_date': 'N/A'
        }
    def _detect_technologies(self, url: str) -> List[str]:
        """Detect technologies used by target."""
        technologies = []
        try:
            response = self.http_client.get(url)
            if response:
                from utils.parser import ResponseParser
                parser = ResponseParser(response)
                technologies = parser.detect_technologies()
        except Exception as e:
            logger.debug(f"Error detecting technologies: {e}")
        return technologies
    def _get_ssl_info(self, domain: str) -> Dict:
        """Get SSL certificate information."""
        return {
            'status': 'Not implemented',
            'issuer': 'N/A',
            'valid_from': 'N/A',
            'valid_until': 'N/A'
        }
    def _enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains."""
        subdomains = []
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'dev', 'test',
            'staging', 'api', 'blog', 'shop', 'portal'
        ]
        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            try:
                socket.gethostbyname(full_domain)
                subdomains.append(full_domain)
                logger.debug(f"Found subdomain: {full_domain}")
            except socket.gaierror:
                pass
        return subdomains
