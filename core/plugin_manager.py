"""
Plugin Manager
Manages custom vulnerability scanner plugins
"""
import os
import importlib.util
import inspect
from typing import Dict, List, Optional, Type
from pathlib import Path
from utils.logger import get_logger
logger = get_logger(__name__)
class PluginBase:
    """Base class for all vulnerability scanner plugins."""
    name: str = "Unknown Plugin"
    version: str = "1.0.0"
    author: str = "Unknown"
    description: str = "No description"
    def __init__(self, http_client, config: Dict):
        """
        Initialize plugin.
        Args:
            http_client: HTTP client instance
            config: Configuration dictionary
        """
        self.http_client = http_client
        self.config = config
        self.plugin_config = config.get('plugins', {}).get(self.get_plugin_id(), {})
    @classmethod
    def get_plugin_id(cls) -> str:
        """Get unique plugin identifier."""
        return cls.__name__.lower().replace('plugin', '')
    def is_enabled(self) -> bool:
        """Check if plugin is enabled in configuration."""
        return self.plugin_config.get('enabled', False)
    def scan(self, url: str, context: Dict) -> List[Dict]:
        """
        Scan URL for vulnerabilities.
        Args:
            url: Target URL
            context: Scan context including response data
        Returns:
            List of discovered vulnerabilities
        """
        raise NotImplementedError("Plugin must implement scan() method")
    def get_info(self) -> Dict:
        """Get plugin information."""
        return {
            'id': self.get_plugin_id(),
            'name': self.name,
            'version': self.version,
            'author': self.author,
            'description': self.description,
            'enabled': self.is_enabled()
        }
class PluginManager:
    """Manages loading and execution of vulnerability scanner plugins."""
    def __init__(self, http_client, config: Dict):
        """
        Initialize plugin manager.
        Args:
            http_client: HTTP client instance
            config: Configuration dictionary
        """
        self.http_client = http_client
        self.config = config
        self.plugins: Dict[str, PluginBase] = {}
        self.plugin_dir = Path(config.get('plugin_manager', {}).get('plugin_directory', 'plugins'))
    def load_plugins(self) -> int:
        """
        Load all plugins from plugin directory.
        Returns:
            Number of plugins loaded
        """
        if not self.plugin_dir.exists():
            logger.info(f"Plugin directory not found: {self.plugin_dir}")
            self.plugin_dir.mkdir(parents=True, exist_ok=True)
            return 0
        loaded_count = 0
        for plugin_file in self.plugin_dir.glob('*.py'):
            if plugin_file.name.startswith('_'):
                continue
            try:
                plugin_class = self._load_plugin_file(plugin_file)
                if plugin_class:
                    plugin_instance = plugin_class(self.http_client, self.config)
                    plugin_id = plugin_instance.get_plugin_id()
                    self.plugins[plugin_id] = plugin_instance
                    loaded_count += 1
                    logger.info(f"Loaded plugin: {plugin_instance.name} v{plugin_instance.version}")
            except Exception as e:
                logger.error(f"Error loading plugin {plugin_file.name}: {e}")
        logger.info(f"Loaded {loaded_count} plugin(s)")
        return loaded_count
    def _load_plugin_file(self, plugin_file: Path) -> Optional[Type[PluginBase]]:
        """
        Load plugin class from file.
        Args:
            plugin_file: Path to plugin file
        Returns:
            Plugin class or None
        """
        try:
            spec = importlib.util.spec_from_file_location(plugin_file.stem, plugin_file)
            if not spec or not spec.loader:
                return None
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            for name, obj in inspect.getmembers(module):
                if (inspect.isclass(obj) and 
                    issubclass(obj, PluginBase) and 
                    obj is not PluginBase):
                    return obj
            logger.warning(f"No PluginBase subclass found in {plugin_file.name}")
            return None
        except Exception as e:
            logger.error(f"Error loading plugin file {plugin_file.name}: {e}")
            return None
    def get_enabled_plugins(self) -> List[PluginBase]:
        """Get list of enabled plugins."""
        return [plugin for plugin in self.plugins.values() if plugin.is_enabled()]
    def get_plugin(self, plugin_id: str) -> Optional[PluginBase]:
        """Get plugin by ID."""
        return self.plugins.get(plugin_id)
    def scan_with_plugins(self, url: str, context: Dict) -> List[Dict]:
        """
        Run all enabled plugins against URL.
        Args:
            url: Target URL
            context: Scan context
        Returns:
            List of vulnerabilities found by plugins
        """
        vulnerabilities = []
        enabled_plugins = self.get_enabled_plugins()
        for plugin in enabled_plugins:
            try:
                logger.debug(f"Running plugin: {plugin.name}")
                plugin_vulns = plugin.scan(url, context)
                vulnerabilities.extend(plugin_vulns)
            except Exception as e:
                logger.error(f"Error running plugin {plugin.name}: {e}")
        return vulnerabilities
    def list_plugins(self) -> List[Dict]:
        """Get information about all loaded plugins."""
        return [plugin.get_info() for plugin in self.plugins.values()]
