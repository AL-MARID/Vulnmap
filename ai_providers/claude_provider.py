"""
Claude Provider (Anthropic)
"""
from typing import Dict
from anthropic import Anthropic
from utils.logger import get_logger
logger = get_logger(__name__)
class ClaudeProvider:
    """Anthropic Claude API provider."""
    def __init__(self, config: Dict):
        """Initialize Claude provider."""
        self.config = config
        self.api_key = config.get('api_key')
        self.model = config.get('model', 'claude-3-5-sonnet-20241022')
        self.temperature = config.get('temperature', 0.7)
        self.max_tokens = config.get('max_tokens', 2000)
        if not self.api_key:
            raise ValueError("Claude API key not provided")
        self.client = Anthropic(api_key=self.api_key)
    def generate(self, prompt: str, **kwargs) -> str:
        """
        Generate response using Claude.
        Args:
            prompt: Input prompt
            **kwargs: Additional arguments
        Returns:
            Generated response
        """
        try:
            response = self.client.messages.create(
                model=kwargs.get('model', self.model),
                max_tokens=kwargs.get('max_tokens', self.max_tokens),
                temperature=kwargs.get('temperature', self.temperature),
                system="You are a security expert specializing in penetration testing and vulnerability research.",
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )
            return response.content[0].text
        except Exception as e:
            logger.error(f"Claude generation error: {e}")
            raise
