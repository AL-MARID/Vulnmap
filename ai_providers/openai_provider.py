"""
OpenAI Provider
"""
from typing import Dict, Optional
from openai import OpenAI
from utils.logger import get_logger
logger = get_logger(__name__)
class OpenAIProvider:
    """OpenAI API provider."""
    def __init__(self, config: Dict):
        """Initialize OpenAI provider."""
        self.config = config
        self.api_key = config.get('api_key')
        self.model = config.get('model', 'gpt-4o')
        self.temperature = config.get('temperature', 0.7)
        self.max_tokens = config.get('max_tokens', 2000)
        if not self.api_key:
            raise ValueError("OpenAI API key not provided")
        self.client = OpenAI(api_key=self.api_key)
    def generate(self, prompt: str, **kwargs) -> str:
        """
        Generate response using OpenAI.
        Args:
            prompt: Input prompt
            **kwargs: Additional arguments
        Returns:
            Generated response
        """
        try:
            response = self.client.chat.completions.create(
                model=kwargs.get('model', self.model),
                messages=[
                    {
                        "role": "system",
                        "content": "You are a security expert specializing in penetration testing and vulnerability research."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=kwargs.get('temperature', self.temperature),
                max_tokens=kwargs.get('max_tokens', self.max_tokens)
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"OpenAI generation error: {e}")
            raise
