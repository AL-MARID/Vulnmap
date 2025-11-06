"""
Configuration loader utility
"""
import yaml
from pathlib import Path
from typing import Dict, Any
from utils.logger import get_logger
logger = get_logger(__name__)
class ConfigLoader:
    """Load and manage configuration."""
    @staticmethod
    def load(config_path: str) -> Dict[str, Any]:
        """
        Load configuration from YAML file.
        Args:
            config_path: Path to configuration file
        Returns:
            Configuration dictionary
        """
        config_file = Path(config_path)
        if not config_file.exists():
            logger.warning(f"Config file not found: {config_path}")
            return ConfigLoader._get_default_config()
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"Configuration loaded from {config_path}")
            return config
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            return ConfigLoader._get_default_config()
    @staticmethod
    def _get_default_config() -> Dict[str, Any]:
        """Get default configuration."""
        return {
            'ai_providers': {
                'openai': {
                    'enabled': False,
                    'model': 'gpt-4o',
                    'temperature': 0.7,
                    'max_tokens': 2000
                }
            },
            'scanner': {
                'default_threads': 5,
                'default_depth': 2,
                'timeout': 10,
                'user_agent': 'Vulnmap/1.0'
            },
            'vulnerability_scanner': {
                'enabled_checks': [
                    'sql_injection',
                    'xss',
                    'command_injection',
                    'ssrf',
                    'xxe',
                    'path_traversal',
                    'csrf',
                    'open_redirect',
                    'cors_misconfiguration',
                    'security_misconfiguration'
                ],
                'payload_generation': {
                    'use_ai': False
                }
            },
            'reconnaissance': {
                'enabled_modules': []
            },
            'reporting': {
                'default_format': 'html'
            },
            'logging': {
                'level': 'INFO'
            }
        }
