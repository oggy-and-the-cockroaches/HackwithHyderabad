"""LLM service abstraction for Gemini and Grok providers."""

import os
import json
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate a text response from the LLM."""
        pass

    @abstractmethod
    def generate_json(self, prompt: str, system_prompt: Optional[str] = None) -> Dict[str, Any]:
        """Generate a JSON response from the LLM."""
        pass


class GeminiProvider(LLMProvider):
    """Google Gemini LLM provider using modern google-genai SDK."""

    def __init__(self, api_key: Optional[str] = None, model: str = "gemini-2.5-flash"):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.model_name = model or os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
        self._client = None
        if self.api_key and self.api_key != "your_gemini_api_key_here":
            try:
                from google import genai
                self._client = genai.Client(api_key=self.api_key)
            except ImportError:
                pass

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        if not self.api_key or self.api_key == "your_gemini_api_key_here":
            return "LLM not configured (missing GEMINI_API_KEY in .env)"

        full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt

        if self._client:
            try:
                response = self._client.models.generate_content(
                    model=self.model_name,
                    contents=full_prompt,
                )
                return response.text
            except Exception as e:
                # Fallback to direct HTTP call if SDK call fails
                pass

        # Direct REST API fallback
        import urllib.request
        import urllib.parse
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}:generateContent?key={self.api_key}"
        headers = {"Content-Type": "application/json"}
        contents = [{"role": "user", "parts": [{"text": full_prompt}]}]
        data = json.dumps({"contents": contents}).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers)
        try:
            with urllib.request.urlopen(req) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                return result["candidates"][0]["content"]["parts"][0]["text"]
        except Exception as err:
            return f"Gemini API Error ({self.model_name}): {str(err)}"

    def generate_json(self, prompt: str, system_prompt: Optional[str] = None) -> Dict[str, Any]:
        if not self.api_key or self.api_key == "your_gemini_api_key_here":
            return {"error": "LLM not configured", "summary": "AI analysis unavailable - missing GEMINI_API_KEY"}
        json_prompt = f"{prompt}\n\nRespond with valid JSON only, no markdown formatting."
        full_system = f"{system_prompt}\n\nYou must respond with valid JSON only." if system_prompt else "You must respond with valid JSON only."
        response = self.generate(json_prompt, full_system)
        response = response.strip()
        if response.startswith("```"):
            response = response.split("```", 2)[1]
            if response.startswith("json"):
                response = response[4:]
        try:
            return json.loads(response)
        except Exception:
            return {"raw_response": response, "summary": "AI generated analysis"}


class GrokProvider(LLMProvider):
    """xAI Grok LLM provider via OpenAI-compatible API."""

    def __init__(self, api_key: Optional[str] = None, model: str = "grok-3"):
        self.api_key = api_key or os.environ.get("GROK_API_KEY")
        self.model_name = model
        self._client = None
        if self.api_key:
            try:
                from openai import OpenAI
                self._client = OpenAI(
                    api_key=self.api_key,
                    base_url="https://api.x.ai/v1"
                )
            except ImportError:
                pass

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        if not self._client:
            return "LLM not configured (missing openai or API key)"
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        response = self._client.chat.completions.create(
            model=self.model_name,
            messages=messages
        )
        return response.choices[0].message.content

    def generate_json(self, prompt: str, system_prompt: Optional[str] = None) -> Dict[str, Any]:
        if not self._client:
            return {"error": "LLM not configured", "summary": "AI analysis unavailable - LLM not configured"}
        json_prompt = f"{prompt}\n\nRespond with valid JSON only, no markdown formatting."
        full_system = f"{system_prompt}\n\nYou must respond with valid JSON only." if system_prompt else "You must respond with valid JSON only."
        response = self.generate(json_prompt, full_system)
        response = response.strip()
        if response.startswith("```"):
            response = response.split("```", 2)[1]
            if response.startswith("json"):
                response = response[4:]
        return json.loads(response)


def get_llm_provider() -> Optional[LLMProvider]:
    """Create the appropriate LLM provider based on environment variables."""
    provider = os.environ.get("SHIPCHECK_LLM_PROVIDER", "gemini").lower()

    if provider == "gemini":
        api_key = os.environ.get("GEMINI_API_KEY")
        model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
        return GeminiProvider(api_key=api_key, model=model)

    elif provider == "grok":
        api_key = os.environ.get("GROK_API_KEY")
        model = os.environ.get("GROK_MODEL", "grok-3")
        return GrokProvider(api_key=api_key, model=model)

    return None


# Global provider instance
_llm_provider: Optional[LLMProvider] = None


def get_llm() -> Optional[LLMProvider]:
    """Get the configured LLM provider."""
    global _llm_provider
    _llm_provider = get_llm_provider()
    return _llm_provider


def set_llm_provider(provider: LLMProvider):
    """Override the LLM provider (useful for testing)."""
    global _llm_provider
    _llm_provider = provider