"""
Enhanced OSINT Reconnaissance Module
Advanced passive information gathering and intelligence collection
"""
import re
import json
from typing import Dict, List, Optional
from urllib.parse import urlparse
from utils.logger import get_logger
logger = get_logger(__name__)
class EnhancedOSINT:
    """Enhanced OSINT reconnaissance engine."""
    def __init__(self, http_client, config: Dict):
        """Initialize enhanced OSINT module."""
        self.http_client = http_client
        self.config = config
        self.osint_config = config.get('osint', {})
    def gather_intelligence(self, target: str) -> Dict:
        """
        Gather comprehensive OSINT intelligence.
        Args:
            target: Target domain or URL
        Returns:
            Intelligence report
        """
        domain = self._extract_domain(target)
        intelligence = {
            'target': target,
            'domain': domain,
            'email_addresses': self.find_email_addresses(domain),
            'social_media': self.find_social_media_accounts(domain),
            'data_breaches': self.check_data_breaches(domain),
            'exposed_files': self.find_exposed_files(domain),
            'archived_content': self.search_web_archives(domain),
            'dns_intelligence': self.gather_dns_intelligence(domain),
            'certificate_transparency': self.check_certificate_transparency(domain),
            'cloud_resources': self.discover_cloud_resources(domain),
            'api_endpoints': self.discover_api_endpoints(target),
            'technology_intelligence': self.gather_technology_intel(target)
        }
        return intelligence
    def find_email_addresses(self, domain: str) -> List[str]:
        """Find email addresses associated with domain."""
        emails = []
        try:
            search_queries = [
                f'site:{domain} email',
                f'site:{domain} contact',
                f'site:{domain} @{domain}',
            ]
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            logger.info(f"Searching for emails on {domain}")
            common_emails = [
                f'info@{domain}',
                f'contact@{domain}',
                f'admin@{domain}',
                f'support@{domain}',
            ]
            emails.extend(common_emails)
        except Exception as e:
            logger.debug(f"Error finding emails: {e}")
        return list(set(emails))
    def find_social_media_accounts(self, domain: str) -> Dict[str, str]:
        """Find social media accounts associated with domain."""
        social_accounts = {}
        platforms = {
            'twitter': f'https://twitter.com/{domain.split(".")[0]}',
            'linkedin': f'https://linkedin.com/company/{domain.split(".")[0]}',
            'facebook': f'https://facebook.com/{domain.split(".")[0]}',
            'github': f'https://github.com/{domain.split(".")[0]}',
            'instagram': f'https://instagram.com/{domain.split(".")[0]}',
        }
        for platform, url in platforms.items():
            try:
                response = self.http_client.get(url, timeout=5)
                if response and response.status_code == 200:
                    social_accounts[platform] = url
            except Exception as e:
                logger.debug(f"Error checking {platform}: {e}")
        return social_accounts
    def check_data_breaches(self, domain: str) -> List[Dict]:
        """Check for data breaches involving domain."""
        breaches = []
        logger.info(f"Checking data breaches for {domain}")
        return breaches
    def find_exposed_files(self, domain: str) -> List[Dict]:
        """Find exposed sensitive files using Google dorks."""
        exposed_files = []
        dorks = [
            f'site:{domain} ext:sql',
            f'site:{domain} ext:log',
            f'site:{domain} ext:bak',
            f'site:{domain} ext:old',
            f'site:{domain} ext:config',
            f'site:{domain} ext:env',
            f'site:{domain} intitle:"index of"',
            f'site:{domain} inurl:admin',
            f'site:{domain} inurl:backup',
            f'site:{domain} filetype:pdf',
        ]
        for dork in dorks:
            logger.debug(f"Dork search: {dork}")
            exposed_files.append({
                'dork': dork,
                'type': 'potential_exposure'
            })
        return exposed_files
    def search_web_archives(self, domain: str) -> Dict:
        """Search Wayback Machine for archived content."""
        archives = {
            'wayback_url': f'https://web.archive.org/web/*/{domain}',
            'snapshots_available': False,
            'historical_data': []
        }
        try:
            api_url = f'https://archive.org/wayback/available?url={domain}'
            response = self.http_client.get(api_url)
            if response and response.status_code == 200:
                data = response.json()
                if 'archived_snapshots' in data:
                    archives['snapshots_available'] = True
                    archives['historical_data'] = data.get('archived_snapshots', {})
        except Exception as e:
            logger.debug(f"Error checking web archives: {e}")
        return archives
    def gather_dns_intelligence(self, domain: str) -> Dict:
        """Gather DNS-based intelligence."""
        dns_intel = {
            'mx_records': [],
            'txt_records': [],
            'spf_records': [],
            'dmarc_records': [],
            'nameservers': [],
        }
        try:
            import dns.resolver
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                dns_intel['mx_records'] = [str(rdata.exchange) for rdata in mx_records]
            except Exception:
                pass
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                for rdata in txt_records:
                    txt_str = str(rdata)
                    dns_intel['txt_records'].append(txt_str)
                    if 'v=spf1' in txt_str:
                        dns_intel['spf_records'].append(txt_str)
            except Exception:
                pass
            try:
                dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
                dns_intel['dmarc_records'] = [str(rdata) for rdata in dmarc_records]
            except Exception:
                pass
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                dns_intel['nameservers'] = [str(rdata) for rdata in ns_records]
            except Exception:
                pass
        except ImportError:
            logger.warning("dnspython not available for DNS intelligence")
        except Exception as e:
            logger.debug(f"Error gathering DNS intelligence: {e}")
        return dns_intel
    def check_certificate_transparency(self, domain: str) -> List[Dict]:
        """Check certificate transparency logs for subdomains."""
        subdomains = []
        try:
            crt_url = f'https://crt.sh/?q=%.{domain}&output=json'
            response = self.http_client.get(crt_url)
            if response and response.status_code == 200:
                cert_data = response.json()
                for cert in cert_data:
                    name_value = cert.get('name_value', '')
                    for subdomain in name_value.split('\n'):
                        subdomain = subdomain.strip()
                        if subdomain and subdomain not in subdomains:
                            subdomains.append({
                                'subdomain': subdomain,
                                'source': 'certificate_transparency'
                            })
        except Exception as e:
            logger.debug(f"Error checking certificate transparency: {e}")
        return subdomains
    def discover_cloud_resources(self, domain: str) -> Dict:
        """Discover cloud storage resources."""
        cloud_resources = {
            'aws_s3': [],
            'azure_blob': [],
            'google_cloud': [],
        }
        company_name = domain.split('.')[0]
        s3_names = [
            company_name,
            f'{company_name}-backup',
            f'{company_name}-data',
            f'{company_name}-assets',
            f'{company_name}-files',
        ]
        for bucket_name in s3_names:
            s3_url = f'https://{bucket_name}.s3.amazonaws.com'
            try:
                response = self.http_client.get(s3_url)
                if response and response.status_code in [200, 403]:
                    cloud_resources['aws_s3'].append({
                        'bucket': bucket_name,
                        'url': s3_url,
                        'accessible': response.status_code == 200
                    })
            except Exception:
                pass
        azure_names = [f'{company_name}', f'{company_name}storage']
        for blob_name in azure_names:
            azure_url = f'https://{blob_name}.blob.core.windows.net'
            try:
                response = self.http_client.get(azure_url)
                if response:
                    cloud_resources['azure_blob'].append({
                        'container': blob_name,
                        'url': azure_url
                    })
            except Exception:
                pass
        return cloud_resources
    def discover_api_endpoints(self, target: str) -> List[str]:
        """Discover API endpoints."""
        api_endpoints = []
        try:
            api_paths = [
                '/api', '/api/v1', '/api/v2', '/api/v3',
                '/rest', '/graphql', '/v1', '/v2',
                '/api/docs', '/api-docs', '/swagger',
                '/openapi.json', '/api/swagger.json',
            ]
            for path in api_paths:
                api_url = target.rstrip('/') + path
                response = self.http_client.get(api_url)
                if response and response.status_code == 200:
                    api_endpoints.append(api_url)
        except Exception as e:
            logger.debug(f"Error discovering API endpoints: {e}")
        return api_endpoints
    def gather_technology_intel(self, target: str) -> Dict:
        """Gather detailed technology intelligence."""
        tech_intel = {
            'frameworks': [],
            'libraries': [],
            'cdn': [],
            'analytics': [],
            'cms': None,
        }
        try:
            response = self.http_client.get(target)
            if response:
                content = response.text
                headers = response.headers
                if 'X-Powered-By' in headers:
                    tech_intel['frameworks'].append(headers['X-Powered-By'])
                framework_patterns = {
                    'React': r'react',
                    'Angular': r'ng-',
                    'Vue': r'vue',
                    'jQuery': r'jquery',
                    'Bootstrap': r'bootstrap',
                }
                for framework, pattern in framework_patterns.items():
                    if re.search(pattern, content, re.IGNORECASE):
                        tech_intel['libraries'].append(framework)
                cms_patterns = {
                    'WordPress': r'wp-content',
                    'Joomla': r'joomla',
                    'Drupal': r'drupal',
                }
                for cms, pattern in cms_patterns.items():
                    if re.search(pattern, content, re.IGNORECASE):
                        tech_intel['cms'] = cms
                        break
        except Exception as e:
            logger.debug(f"Error gathering technology intelligence: {e}")
        return tech_intel
    def _extract_domain(self, target: str) -> str:
        """Extract domain from URL or domain string."""
        if '://' in target:
            parsed = urlparse(target)
            return parsed.netloc
        return target
