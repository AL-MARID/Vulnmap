"""
OLLAMA Provider (Local LLM)
"""
from typing import Dict
import requests
from utils.logger import get_logger
logger = get_logger(__name__)
class OllamaProvider:
    """OLLAMA local LLM provider."""
    def __init__(self, config: Dict):
        """Initialize OLLAMA provider."""
        self.config = config
        self.base_url = config.get('base_url', 'http://localhost:11434')
        self.model = config.get('model', 'llama2')
        self.temperature = config.get('temperature', 0.7)
        self.timeout = config.get('timeout', 60)
    def generate(self, prompt: str, **kwargs) -> str:
        """
        Generate response using OLLAMA.
        Args:
            prompt: Input prompt
            **kwargs: Additional arguments
        Returns:
            Generated response
        """
        try:
            url = self.base_url
            payload = {
                "model": kwargs.get('model', self.model),
                "prompt": f"You are a security expert. {prompt}",
                "temperature": kwargs.get('temperature', self.temperature),
                "stream": False
            }
            response = requests.post(
                url,
                json=payload,
                timeout=self.timeout
            )
            if response.status_code == 200:
                return response.json().get('response', '')
            else:
                raise Exception(f"OLLAMA API error: {response.status_code}")
        except Exception as e:
            logger.error(f"OLLAMA generation error: {e}")
            raise
