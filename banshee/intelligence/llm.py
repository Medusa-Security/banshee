import abc
import os
import json
import logging
import urllib.request
import urllib.error

logger = logging.getLogger(__name__)

class LLMProvider(abc.ABC):
    """
    Abstract base class for all LLM intelligence providers used by Banshee.
    """
    def __init__(self, model: str, api_key: str = None):
        self.model = model
        self.api_key = api_key or os.getenv(self._get_api_key_env_var(), "")

    @abc.abstractmethod
    def _get_api_key_env_var(self) -> str:
        pass

    @abc.abstractmethod
    async def evaluate_security_risk(self, prompt: str, context: str) -> dict:
        """
        Evaluate a security risk. Should return a dictionary with:
        - risk_level: str ("none", "low", "medium", "high", "critical")
        - confidence: float (0.0 to 1.0)
        - reasoning: str
        """
        pass

    # A simplistic synchronous HTTP wrapper for demonstration in standard library.
    # In a real async environment, use aiohttp or httpx.
    def _make_http_request(self, url: str, headers: dict, data: dict) -> dict:
        import asyncio
        loop = asyncio.get_event_loop()
        
        def do_request():
            req = urllib.request.Request(url, data=json.dumps(data).encode('utf-8'), headers=headers, method='POST')
            try:
                with urllib.request.urlopen(req, timeout=10) as response:
                    return json.loads(response.read().decode())
            except urllib.error.URLError as e:
                logger.error(f"LLM Request failed: {e}")
                return None
                
        return loop.run_in_executor(None, do_request)


class OpenAIProvider(LLMProvider):
    def _get_api_key_env_var(self) -> str:
        return "OPENAI_API_KEY"

    async def evaluate_security_risk(self, prompt: str, context: str) -> dict:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        data = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a security evaluator. Return JSON with risk_level (none/low/medium/high/critical), confidence (0.0-1.0), and reasoning."},
                {"role": "user", "content": f"Context: {context}\\nPrompt: {prompt}"}
            ],
            "response_format": {"type": "json_object"}
        }
        
        resp = await self._make_http_request(url, headers, data)
        if resp and "choices" in resp:
            content = resp["choices"][0]["message"]["content"]
            try:
                return json.loads(content)
            except:
                pass
        return {"risk_level": "medium", "confidence": 0.0, "reasoning": "Provider failed to respond correctly."}


class AnthropicProvider(LLMProvider):
    def _get_api_key_env_var(self) -> str:
        return "ANTHROPIC_API_KEY"

    async def evaluate_security_risk(self, prompt: str, context: str) -> dict:
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json"
        }
        data = {
            "model": self.model,
            "max_tokens": 300,
            "system": "You are a security evaluator. Return JSON with risk_level (none/low/medium/high/critical), confidence (0.0-1.0), and reasoning.",
            "messages": [{"role": "user", "content": f"Context: {context}\\nPrompt: {prompt}\\nRespond only with valid JSON."}]
        }
        
        resp = await self._make_http_request(url, headers, data)
        if resp and "content" in resp:
            text = resp["content"][0]["text"]
            try:
                return json.loads(text)
            except:
                pass
        return {"risk_level": "medium", "confidence": 0.0, "reasoning": "Provider failed to respond correctly."}


class GroqProvider(LLMProvider):
    def _get_api_key_env_var(self) -> str:
        return "GROQ_API_KEY"

    async def evaluate_security_risk(self, prompt: str, context: str) -> dict:
        # Groq uses OpenAI-compatible API format
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        data = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a security evaluator. Return JSON with risk_level (none/low/medium/high/critical), confidence (0.0-1.0), and reasoning."},
                {"role": "user", "content": f"Context: {context}\\nPrompt: {prompt}"}
            ],
            "response_format": {"type": "json_object"}
        }
        
        resp = await self._make_http_request(url, headers, data)
        if resp and "choices" in resp:
            content = resp["choices"][0]["message"]["content"]
            try:
                return json.loads(content)
            except:
                pass
        return {"risk_level": "medium", "confidence": 0.0, "reasoning": "Provider failed to respond correctly."}


class OpenRouterProvider(LLMProvider):
    def _get_api_key_env_var(self) -> str:
        return "OPENROUTER_API_KEY"

    async def evaluate_security_risk(self, prompt: str, context: str) -> dict:
        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        data = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a security evaluator. Return JSON with risk_level (none/low/medium/high/critical), confidence (0.0-1.0), and reasoning."},
                {"role": "user", "content": f"Context: {context}\\nPrompt: {prompt}"}
            ]
        }
        
        resp = await self._make_http_request(url, headers, data)
        if resp and "choices" in resp:
            content = resp["choices"][0]["message"]["content"]
            try:
                import re
                match = re.search(r'\\{.*\\}', content, re.DOTALL)
                if match:
                    return json.loads(match.group(0))
            except:
                pass
        return {"risk_level": "medium", "confidence": 0.0, "reasoning": "Provider failed to respond correctly."}


class XAIProvider(LLMProvider):
    def _get_api_key_env_var(self) -> str:
        return "XAI_API_KEY"

    async def evaluate_security_risk(self, prompt: str, context: str) -> dict:
        url = "https://api.x.ai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        data = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a security evaluator. Return JSON with risk_level (none/low/medium/high/critical), confidence (0.0-1.0), and reasoning."},
                {"role": "user", "content": f"Context: {context}\\nPrompt: {prompt}"}
            ]
        }
        
        resp = await self._make_http_request(url, headers, data)
        if resp and "choices" in resp:
            content = resp["choices"][0]["message"]["content"]
            try:
                return json.loads(content)
            except:
                pass
        return {"risk_level": "medium", "confidence": 0.0, "reasoning": "Provider failed to respond correctly."}


class OllamaProvider(LLMProvider):
    def __init__(self, model: str, host: str = "http://localhost:11434"):
        self.model = model
        self.host = host

    def _get_api_key_env_var(self) -> str:
        return ""

    async def evaluate_security_risk(self, prompt: str, context: str) -> dict:
        url = f"{self.host}/api/chat"
        headers = {"Content-Type": "application/json"}
        data = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a security evaluator. Return JSON with risk_level (none/low/medium/high/critical), confidence (0.0-1.0), and reasoning."},
                {"role": "user", "content": f"Context: {context}\\nPrompt: {prompt}"}
            ],
            "format": "json",
            "stream": False
        }
        
        resp = await self._make_http_request(url, headers, data)
        if resp and "message" in resp:
            content = resp["message"]["content"]
            try:
                return json.loads(content)
            except:
                pass
        return {"risk_level": "medium", "confidence": 0.0, "reasoning": "Provider failed to respond correctly."}
