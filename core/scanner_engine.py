"""
Vulnmap Scanner Engine
Orchestrates the entire scanning process
"""
import time
import threading
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.console import Console
from core.vulnerability_scanner import VulnerabilityScanner
from core.ai_payload_generator import AIPayloadGenerator
from core.plugin_manager import PluginManager
from modules.reconnaissance.recon_engine import ReconEngine
from utils.http_client import HTTPClient
from utils.parser import URLParser, ResponseParser
from utils.notification_manager import NotificationManager
from utils.logger import get_logger
console = Console()
logger = get_logger(__name__)
class ScannerEngine:
    """Main scanner engine that orchestrates the penetration testing process."""
    def __init__(
        self,
        target_url: str,
        config: Dict,
        ai_manager,
        depth: int = 2,
        threads: int = 5,
        proxy: Optional[str] = None,
        custom_headers: Optional[Dict] = None,
        cookies: Optional[Dict] = None,
        verbose: bool = False
    ):
        """Initialize the scanner engine."""
        self.target_url = target_url
        self.config = config
        self.ai_manager = ai_manager
        self.depth = depth
        self.threads = threads
        self.verbose = verbose
        self.http_client = HTTPClient(
            proxy=proxy,
            custom_headers=custom_headers,
            cookies=cookies,
            config=config
        )
        self.vulnerability_scanner = VulnerabilityScanner(
            config=config,
            http_client=self.http_client
        )
        self.ai_payload_generator = AIPayloadGenerator(
            ai_manager=ai_manager,
            config=config
        )
        self.recon_engine = ReconEngine(
            config=config,
            http_client=self.http_client
        )
        self.plugin_manager = PluginManager(
            http_client=self.http_client,
            config=config
        )
        if config.get('plugin_manager', {}).get('enabled', False):
            self.plugin_manager.load_plugins()
        self.notification_manager = NotificationManager(config)
        self.visited_urls: Set[str] = set()
        self.urls_to_scan: List[str] = [target_url]
        self.vulnerabilities: List[Dict] = []
        self.scan_results: Dict = {}
        self.lock = threading.Lock()
        self.start_time = None
        self.end_time = None
    def crawl(self, url: str, current_depth: int = 0) -> List[str]:
        """Crawl a URL and extract links."""
        if current_depth >= self.depth or url in self.visited_urls:
            return []
        with self.lock:
            self.visited_urls.add(url)
        try:
            response = self.http_client.get(url)
            if not response:
                return []
            parser = ResponseParser(response)
            links = parser.extract_links(base_url=url)
            parsed_target = urlparse(self.target_url)
            same_domain_links = []
            for link in links:
                parsed_link = urlparse(link)
                if parsed_link.netloc == parsed_target.netloc:
                    if link not in self.visited_urls:
                        same_domain_links.append(link)
            return same_domain_links
        except Exception as e:
            logger.error(f"Error crawling {url}: {e}")
            return []
    def crawl_recursive(self) -> Set[str]:
        """Recursively crawl the target website."""
        console.print("[bold blue]🕷️  Starting web crawler...[/bold blue]")
        all_urls = set([self.target_url])
        queue = [(self.target_url, 0)]
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task(
                f"[cyan]Crawling (depth: {self.depth})...",
                total=None
            )
            while queue:
                url, depth = queue.pop(0)
                if depth >= self.depth:
                    continue
                new_links = self.crawl(url, depth)
                for link in new_links:
                    if link not in all_urls:
                        all_urls.add(link)
                        queue.append((link, depth + 1))
                progress.update(
                    task,
                    description=f"[cyan]Crawling... Found {len(all_urls)} URLs"
                )
        console.print(f"[green]✓[/green] Crawling complete. Found {len(all_urls)} URLs\n")
        return all_urls
    def scan_url(self, url: str, recon_data: Optional[Dict] = None) -> List[Dict]:
        """Scan a single URL for vulnerabilities."""
        vulnerabilities = []
        try:
            response = self.http_client.get(url)
            if not response:
                return vulnerabilities
            context = {
                'url': url,
                'response': response,
                'headers': dict(response.headers)
            }
            if recon_data and 'osint' in recon_data:
                context['osint_data'] = recon_data['osint']
            payloads = self.ai_payload_generator.generate_payloads(context)
            scan_results = self.vulnerability_scanner.scan(
                url=url,
                payloads=payloads,
                context=context
            )
            vulnerabilities.extend(scan_results)
            if self.config.get('plugin_manager', {}).get('enabled', False):
                plugin_results = self.plugin_manager.scan_with_plugins(url, context)
                vulnerabilities.extend(plugin_results)
            for vuln in vulnerabilities:
                if vuln.get('severity', '').lower() == 'critical':
                    try:
                        self.notification_manager.send_critical_vulnerability(vuln, self.target_url)
                    except Exception as e:
                        logger.debug(f"Error sending critical vulnerability alert: {e}")
        except Exception as e:
            logger.error(f"Error scanning {url}: {e}")
        return vulnerabilities
    def scan_all_urls(self, urls: Set[str], recon_data: Optional[Dict] = None):
        """Scan all discovered URLs for vulnerabilities."""
        console.print("[bold blue]🔍 Starting vulnerability scanning...[/bold blue]")
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task(
                "[cyan]Scanning for vulnerabilities...",
                total=len(urls)
            )
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_url = {
                    executor.submit(self.scan_url, url, recon_data): url
                    for url in urls
                }
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        vulns = future.result()
                        with self.lock:
                            self.vulnerabilities.extend(vulns)
                        progress.advance(task)
                        progress.update(
                            task,
                            description=f"[cyan]Scanning... {len(self.vulnerabilities)} vulnerabilities found"
                        )
                    except Exception as e:
                        logger.error(f"Error processing {url}: {e}")
                        progress.advance(task)
        console.print(f"[green]✓[/green] Vulnerability scanning complete. Found {len(self.vulnerabilities)} issues\n")
    def run_reconnaissance(self) -> Dict:
        """Run reconnaissance modules."""
        console.print("[bold blue]🔎 Running reconnaissance...[/bold blue]")
        recon_results = self.recon_engine.run(self.target_url)
        console.print("[green]✓[/green] Reconnaissance complete\n")
        return recon_results
    def scan(
        self,
        enable_recon: bool = False,
        full_scan: bool = False,
        quick_scan: bool = False
    ) -> Dict:
        """
        Execute the complete scanning process.
        Args:
            enable_recon: Enable reconnaissance phase
            full_scan: Enable all vulnerability tests
            quick_scan: Run only basic tests
        Returns:
            Dictionary containing scan results
        """
        self.start_time = datetime.now()
        results = {
            'target': self.target_url,
            'start_time': self.start_time.isoformat(),
            'config': {
                'depth': self.depth,
                'threads': self.threads,
                'recon_enabled': enable_recon,
                'scan_mode': 'full' if full_scan else 'quick' if quick_scan else 'standard'
            }
        }
        recon_data = None
        if enable_recon:
            recon_data = self.run_reconnaissance()
            results['reconnaissance'] = recon_data
        discovered_urls = self.crawl_recursive()
        results['urls_crawled'] = len(discovered_urls)
        results['discovered_urls'] = list(discovered_urls)
        if quick_scan:
            self.scan_all_urls({self.target_url}, recon_data)
        else:
            self.scan_all_urls(discovered_urls, recon_data)
        results['vulnerabilities'] = self.vulnerabilities
        results['severity_summary'] = self._calculate_severity_summary()
        self.end_time = datetime.now()
        results['end_time'] = self.end_time.isoformat()
        results['duration'] = str(self.end_time - self.start_time)
        try:
            self.notification_manager.send_scan_complete(results)
        except Exception as e:
            logger.error(f"Error sending notification: {e}")
        return results
    def _calculate_severity_summary(self) -> Dict[str, int]:
        """Calculate vulnerability severity summary."""
        summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            if severity in summary:
                summary[severity] += 1
        return summary
