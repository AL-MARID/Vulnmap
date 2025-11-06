"""
HTTP Client for making requests
"""
import requests
from typing import Dict, Optional
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from utils.logger import get_logger
logger = get_logger(__name__)
class HTTPClient:
    """HTTP client with retry logic and configuration."""
    def __init__(
        self,
        proxy: Optional[str] = None,
        custom_headers: Optional[Dict] = None,
        cookies: Optional[Dict] = None,
        config: Optional[Dict] = None
    ):
        """Initialize HTTP client."""
        self.config = config or {}
        scanner_config = self.config.get('scanner', {})
        self.timeout = scanner_config.get('timeout', 10)
        self.verify_ssl = scanner_config.get('verify_ssl', True)
        self.max_retries = scanner_config.get('max_retries', 3)
        self.user_agent = scanner_config.get('user_agent', 'Vulnmap/1.0')
        self.session = requests.Session()
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        if custom_headers:
            self.session.headers.update(custom_headers)
        if cookies:
            self.session.cookies.update(cookies)
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
    def get(
        self,
        url: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        allow_redirects: bool = True,
        **kwargs
    ) -> Optional[requests.Response]:
        """Make GET request."""
        try:
            response = self.session.get(
                url,
                params=params,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=allow_redirects,
                **kwargs
            )
            return response
        except requests.exceptions.RequestException as e:
            logger.debug(f"GET request failed for {url}: {e}")
            return None
    def post(
        self,
        url: str,
        data: Optional[Dict] = None,
        json: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        **kwargs
    ) -> Optional[requests.Response]:
        """Make POST request."""
        try:
            response = self.session.post(
                url,
                data=data,
                json=json,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                **kwargs
            )
            return response
        except requests.exceptions.RequestException as e:
            logger.debug(f"POST request failed for {url}: {e}")
            return None
    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make HEAD request."""
        try:
            response = self.session.head(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                **kwargs
            )
            return response
        except requests.exceptions.RequestException as e:
            logger.debug(f"HEAD request failed for {url}: {e}")
            return None
    def options(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make OPTIONS request."""
        try:
            response = self.session.options(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                **kwargs
            )
            return response
        except requests.exceptions.RequestException as e:
            logger.debug(f"OPTIONS request failed for {url}: {e}")
            return None
