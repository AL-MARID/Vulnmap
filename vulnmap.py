"""
Vulnmap - Advanced AI-Driven Penetration Testing Tool
Main Entry Point
"""
import sys
import argparse
import json
import os # Import os for clear_screen
from pathlib import Path
from typing import Optional, Dict
from rich.console import Console
from rich.panel import Panel
from rich import print as rprint
from core.scanner_engine import ScannerEngine
from core.report_generator import ReportGenerator
from utils.logger import setup_logger
from utils.config_loader import ConfigLoader
from ai_providers.provider_manager import AIProviderManager
console = Console()
logger = setup_logger()
ascii_art = r"""
$$\    $$\           $$\
$$ |   $$ |          $$ |
$$ |   $$ |$$\   $$\ $$ |$$$$$$$\  $$$$$$\$$$$\   $$$$$$\   $$$$$$\
\$$\  $$  |$$ |  $$ |$$ |$$  __$$\ $$  _$$  _$$\  \____$$\ $$  __$$\
 \$$\$$  / $$ |  $$ |$$ |$$ |  $$ |$$ / $$ / $$ | $$$$$$$ |$$ /  $$ |
  \$$$  /  $$ |  $$ |$$ |$$ |  $$ |$$ | $$ | $$ |$$  __$$ |$$ |  $$ |
   \$  /   \$$$$$$  |$$ |$$ |  $$ |$$ | $$ | $$ |\$$$$$$$ |$$$$$$$  |
    \_/     \______/ \__|\__|  \__|\__| \__| \__| \_______|$$  ____/
                                                           $$ |
                                                           $$ |
                                                           \__|
"""
BANNER = f"[#0000FF]{ascii_art}[/]"
def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')
def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Vulnmap - AI-Driven Penetration Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Scan with target from CLI:
    python vulnmap.py -u https://example.com
  Scan with target from config:
    python vulnmap.py --config myconfig.yaml
  Verbose mode:
    python vulnmap.py -u https://example.com -v
Note: All scan options are configured in config.yaml
      Use --config to specify a custom configuration file
        """
    )
    parser.add_argument(
        '-u', '--url',
        type=str,
        help='Target URL to scan (overrides config)'
    )
    parser.add_argument(
        '-c', '--config',
        type=str,
        default='config/config.yaml',
        help='Configuration file path (default: config/config.yaml)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    parser.add_argument(
        '--version',
        action='version',
        version='Vulnmap v1.3.0 (Hestia)', # Changed version name
        help='Show version and exit'
    )
    parser.add_argument(
        '--no-banner',
        action='store_true',
        help='Disable banner display'
    )
    return parser.parse_args()
def display_banner():
    """Display the Vulnmap banner."""
    console.print(BANNER, style="bold #00FFFF")
    console.print("[bold #FFFFFF]Vulnmap - Advanced AI-Driven Penetration Testing Tool[/bold #FFFFFF]")
    console.print("⚠️  [bold #FFFF00]Use only on authorized targets[/bold #FFFF00] ⚠️\n")
def validate_config(config: Dict, target_url: str) -> bool:
    """Validate configuration and target URL."""
    if not target_url:
        console.print("[bold #FF0000]Error:[/bold #FF0000] Target URL is required. Specify in config or use -u option.")
        return False
    if not target_url.startswith(('http://', 'https://')):
        console.print("[bold #FF0000]Error:[/bold #FF0000] URL must start with http:// or https://")
        return False
    scanner_config = config.get('scanner', {})
    depth = scanner_config.get('default_depth', 2)
    threads = scanner_config.get('default_threads', 5)
    if depth < 1 or depth > 10:
        console.print("[bold #FF0000]Error:[/bold #FF0000] Depth must be between 1 and 10 (check config)")
        return False
    if threads < 1 or threads > 50:
        console.print("[bold #FF0000]Error:[/bold #FF0000] Threads must be between 1 and 50 (check config)")
        return False
    return True
def main():
    """Main execution function."""
    try:
        args = parse_arguments()
        clear_screen() # Ensure screen is cleared at the start
        if not args.no_banner:
            display_banner()
        console.print("[bold #0000FF]Loading configuration...[/bold #0000FF]")
        config = ConfigLoader.load(args.config)
        scanner_config = config.get('scanner', {})
        target_url = args.url or scanner_config.get('target_url', '')
        if not validate_config(config, target_url):
            sys.exit(1)
        depth = scanner_config.get('default_depth', 2)
        threads = scanner_config.get('default_threads', 5)
        ai_provider = scanner_config.get('ai_provider', 'openai')
        enable_recon = scanner_config.get('enable_recon', False)
        full_scan = scanner_config.get('full_scan', False)
        quick_scan = scanner_config.get('quick_scan', False)
        proxy = scanner_config.get('proxy') or None
        custom_headers = scanner_config.get('custom_headers', {})
        cookies = scanner_config.get('cookies', {})
        verbose = args.verbose
        console.print(f"[bold #0000FF]Initializing AI Provider: {ai_provider}[/bold #0000FF]")
        ai_manager = AIProviderManager(config)
        ai_manager.set_provider(ai_provider)
        console.print("[bold #0000FF]Initializing Scanner Engine...[/bold #0000FF]")
        scanner = ScannerEngine(
            target_url=target_url,
            config=config,
            ai_manager=ai_manager,
            depth=depth,
            threads=threads,
            proxy=proxy,
            custom_headers=custom_headers,
            cookies=cookies,
            verbose=verbose
        )
        scan_mode = 'Full Scan' if full_scan else 'Quick Scan' if quick_scan else 'Standard Scan'
        scan_info = Panel(
            f"""[bold #FFFFFF]Target:[/bold #FFFFFF] {target_url}
[bold #FFFFFF]Depth:[/bold #FFFFFF] {depth}
[bold #FFFFFF]Threads:[/bold #FFFFFF] {threads}
[bold #FFFFFF]AI Provider:[/bold #FFFFFF] {ai_provider}
[bold #FFFFFF]Scan Mode:[/bold #FFFFFF] {scan_mode}
[bold #FFFFFF]Reconnaissance:[/bold #FFFFFF] {'Enabled' if enable_recon else 'Disabled'}""",
            title="Scan Configuration",
            border_style="#00FF00"
        )
        console.print(scan_info)
        console.print("\n[bold #00FF00]Starting scan...[/bold #00FF00]\n")
        results = scanner.scan(
            enable_recon=enable_recon,
            full_scan=full_scan,
            quick_scan=quick_scan
        )
        reporting_config = config.get('reporting', {})
        if reporting_config.get('enabled', True):
            console.print("\n[bold #0000FF]Generating report...[/bold #0000FF]")
            report_gen = ReportGenerator(config)
            output_dir = reporting_config.get('output_directory', 'reports')
            output_filename = reporting_config.get('output_filename', '')
            report_format = reporting_config.get('default_format', 'html')
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            if not output_filename:
                from datetime import datetime
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                domain = Path(target_url).stem.replace(':', '_')
                output_filename = f"vulnmap_{domain}_{timestamp}.{report_format}" # Changed filename
            output_path = str(Path(output_dir) / output_filename)
            report_gen.generate(
                results=results,
                output_path=output_path,
                format=report_format
            )
            console.print(f"[bold #00FF00]✓[/bold #00FF00] Report saved to: {output_path}")
        vuln_count = len(results.get('vulnerabilities', []))
        severity_counts = results.get('severity_summary', {})
        summary = Panel(
            f"""[bold #FFFFFF]Total Vulnerabilities:[/bold #FFFFFF] {vuln_count}
[bold #FF0000]Critical:[/bold #FF0000] {severity_counts.get('critical', 0)}
[bold #FFFF00]High:[/bold #FFFF00] {severity_counts.get('high', 0)}
[bold #0000FF]Medium:[/bold #0000FF] {severity_counts.get('medium', 0)}
[bold #00FF00]Low:[/bold #00FF00] {severity_counts.get('low', 0)}
[bold #FFFFFF]URLs Crawled:[/bold #FFFFFF] {results.get('urls_crawled', 0)}
[bold #FFFFFF]Scan Duration:[/bold #FFFFFF] {results.get('duration', 'N/A')}""",
            title="Scan Summary",
            border_style="#00FFFF"
        )
        console.print("\n", summary)
        console.print("\n[bold #00FF00]Scan completed successfully![/bold #00FF00] 🎉\n")
    except KeyboardInterrupt:
        console.print("\n[bold #FFFF00]Scan interrupted by user[/bold #FFFF00]")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        console.print(f"\n[bold #FF0000]Error:[/bold #FF0000] {str(e)}")
        sys.exit(1)
if __name__ == "__main__":
    main()
