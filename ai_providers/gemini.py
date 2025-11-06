from typing import Dict
import google.generativeai as genai
from utils.logger import get_logger
logger = get_logger(__name__)
class GeminiProvider:
    """Google Gemini AI provider."""
    def __init__(self, config: Dict):
        """Initialize Gemini provider."""
        self.config = config
        self.api_key = config.get('api_key')
        self.model_name = config.get('model', 'gemini-2.5-flash') # Let's stick with gemini-pro
        self.temperature = config.get('temperature', 0.7)
        self.timeout = config.get('timeout', 60)
        if not self.api_key:
            raise ValueError("Gemini API key is not configured.")
        try:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel(
                model_name=f"models/{self.model_name}",
                generation_config=genai.types.GenerationConfig(temperature=self.temperature)
            )
            logger.info("Gemini provider initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to configure Gemini: {e}")
            raise
    def generate(self, prompt: str, **kwargs) -> str:
        """
        Generate response using Gemini.
        """
        try:
            full_prompt = f"You are a security expert. {prompt}"
            response = self.model.generate_content(
                full_prompt,
                request_options={'timeout': self.timeout}
            )
            if response.parts:
                return response.text
            else:
                logger.warning("Gemini response was empty. This might be due to safety settings.")
                return ""
        except Exception as e:
            logger.error(f"Gemini generation error: {e}")
            return ""
