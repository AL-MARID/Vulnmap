This directory contains custom vulnerability scanner plugins for Vulnmap.
1. Create a new Python file in this directory (e.g., `my_scanner.py`)
2. Import and extend `PluginBase` class
3. Implement the `scan()` method
4. Enable plugins in `config/config.yaml`
```python
from typing import Dict, List
from core.plugin_manager import PluginBase
class MyCustomScanner(PluginBase):
    """My custom vulnerability scanner."""
    name = "My Custom Scanner"
    version = "1.0.0"
    author = "Your Name"
    description = "Scans for custom vulnerabilities"
    def scan(self, url: str, context: Dict) -> List[Dict]:
        """
        Scan URL for vulnerabilities.
        Args:
            url: Target URL
            context: Scan context (response, headers, etc.)
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        response = context.get('response')
        if response:
            if 'X-Custom-Header' not in response.headers:
                vulnerabilities.append({
                    'type': 'Missing Custom Header',
                    'severity': 'low',
                    'url': url,
                    'evidence': 'X-Custom-Header not found',
                    'description': 'Custom security header is missing',
                    'remediation': 'Add X-Custom-Header to responses',
                    'plugin': self.name
                })
        return vulnerabilities
```
Enable plugins in `config/config.yaml`:
```yaml
plugin_manager:
  enabled: true
  plugin_directory: "plugins"
  auto_load: true
plugins:
  mycustomscanner:  # Plugin ID (lowercase class name without 'plugin')
    enabled: true
    custom_setting: "value"
```
**Attributes:**
- `name` (str) - Plugin display name
- `version` (str) - Plugin version
- `author` (str) - Plugin author
- `description` (str) - Plugin description
- `http_client` - HTTP client instance
- `config` - Full configuration dictionary
- `plugin_config` - Plugin-specific configuration
**Methods:**
- `get_plugin_id()` - Get unique plugin identifier
- `is_enabled()` - Check if plugin is enabled
- `scan(url, context)` - Main scanning method (implement this)
- `get_info()` - Get plugin information
The `context` parameter contains:
- `url` - Target URL
- `response` - HTTP response object
- `headers` - Response headers
- `osint_data` - OSINT data from reconnaissance (if available)
Each vulnerability should be a dictionary with:
- `type` (str) - Vulnerability type
- `severity` (str) - critical, high, medium, low, info
- `url` (str) - Vulnerable URL
- `evidence` (str) - Evidence of vulnerability
- `description` (str) - Detailed description
- `remediation` (str) - How to fix
- `plugin` (str) - Plugin name (optional)
- `parameter` (str) - Vulnerable parameter (optional)
- `payload` (str) - Payload used (optional)
1. **Error Handling** - Always wrap code in try/except
2. **Logging** - Use `logger` for debugging
3. **Performance** - Limit number of requests
4. **Documentation** - Add docstrings to methods
5. **Testing** - Test plugins thoroughly before deployment
1. Plugin file placed in `plugins/` directory
2. PluginManager scans for `.py` files
3. Loads classes extending PluginBase
4. Checks if plugin is enabled in config
5. Runs plugin during scanning phase
6. Results merged into final report
- `example_plugin.py` - Example security header checker
See the example plugin or open an issue on GitHub.
