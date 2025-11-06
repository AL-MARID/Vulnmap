"""
Parser utilities for URLs and responses
"""
import re
from typing import List, Set
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from utils.logger import get_logger
logger = get_logger(__name__)
class URLParser:
    """Parse and manipulate URLs."""
    @staticmethod
    def normalize(url: str) -> str:
        """Normalize URL."""
        parsed = urlparse(url)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized.rstrip('/')
    @staticmethod
    def is_valid(url: str) -> bool:
        """Check if URL is valid."""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    @staticmethod
    def get_domain(url: str) -> str:
        """Extract domain from URL."""
        parsed = urlparse(url)
        return parsed.netloc
    @staticmethod
    def is_same_domain(url1: str, url2: str) -> bool:
        """Check if two URLs are from the same domain."""
        return URLParser.get_domain(url1) == URLParser.get_domain(url2)
class ResponseParser:
    """Parse HTTP responses."""
    def __init__(self, response):
        """Initialize parser with response."""
        self.response = response
        self.soup = None
        if response and response.text:
            try:
                self.soup = BeautifulSoup(response.text, 'lxml')
            except Exception as e:
                logger.debug(f"Error parsing response: {e}")
    def extract_links(self, base_url: str) -> List[str]:
        """Extract all links from response."""
        if not self.soup:
            return []
        links = set()
        for tag in self.soup.find_all('a', href=True):
            href = tag['href']
            absolute_url = urljoin(base_url, href)
            if URLParser.is_valid(absolute_url):
                links.add(URLParser.normalize(absolute_url))
        for tag in self.soup.find_all('form', action=True):
            action = tag['action']
            absolute_url = urljoin(base_url, action)
            if URLParser.is_valid(absolute_url):
                links.add(URLParser.normalize(absolute_url))
        for tag in self.soup.find_all('script', src=True):
            src = tag['src']
            absolute_url = urljoin(base_url, src)
            if URLParser.is_valid(absolute_url):
                links.add(URLParser.normalize(absolute_url))
        return list(links)
    def extract_forms(self) -> List[dict]:
        """Extract forms from response."""
        if not self.soup:
            return []
        forms = []
        for form in self.soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                }
                form_data['inputs'].append(input_data)
            forms.append(form_data)
        return forms
    def extract_comments(self) -> List[str]:
        """Extract HTML comments."""
        if not self.soup:
            return []
        comments = []
        for comment in self.soup.find_all(text=lambda text: isinstance(text, str)):
            if '<!--' in str(comment):
                comments.append(str(comment))
        return comments
    def extract_scripts(self) -> List[str]:
        """Extract JavaScript code."""
        if not self.soup:
            return []
        scripts = []
        for script in self.soup.find_all('script'):
            if script.string:
                scripts.append(script.string)
        return scripts
    def extract_emails(self) -> Set[str]:
        """Extract email addresses."""
        if not self.response or not self.response.text:
            return set()
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, self.response.text)
        return set(emails)
    def extract_headers(self) -> dict:
        """Extract response headers."""
        if not self.response:
            return {}
        return dict(self.response.headers)
    def detect_technologies(self) -> List[str]:
        """Detect technologies used."""
        technologies = []
        if not self.response:
            return technologies
        headers = self.response.headers
        content = self.response.text.lower()
        server = headers.get('Server', '')
        if 'apache' in server.lower():
            technologies.append('Apache')
        elif 'nginx' in server.lower():
            technologies.append('Nginx')
        elif 'iis' in server.lower():
            technologies.append('IIS')
        if 'x-powered-by' in headers:
            technologies.append(headers['x-powered-by'])
        if 'wp-content' in content or 'wordpress' in content:
            technologies.append('WordPress')
        if 'joomla' in content:
            technologies.append('Joomla')
        if 'drupal' in content:
            technologies.append('Drupal')
        if 'react' in content:
            technologies.append('React')
        if 'angular' in content:
            technologies.append('Angular')
        if 'vue' in content:
            technologies.append('Vue.js')
        return technologies
