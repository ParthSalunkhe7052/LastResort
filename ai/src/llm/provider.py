import os
import json
from abc import ABC, abstractmethod
from typing import Dict, Any

# Optional imports that might not be loaded if we don't use them, but we declare them since we installed them
try:
    import google.generativeai as genai
except ImportError:
    genai = None

try:
    import requests
except ImportError:
    requests = None


class LLMProvider(ABC):
    """Abstract interface for LLM providers."""

    @abstractmethod
    def generate_text(self, prompt: str, system_instruction: str = None) -> str:
        pass

    @abstractmethod
    def generate_json(self, prompt: str, schema: Dict[str, Any], system_instruction: str = None) -> Dict[str, Any]:
        pass


class MockProvider(LLMProvider):
    """A mock LLM provider for local development without dependencies."""

    def generate_text(self, prompt: str, system_instruction: str = None) -> str:
        # Mock responses based on keywords in prompt
        prompt_lower = prompt.lower()
        if "recon" in prompt_lower or "headers" in prompt_lower:
            return "Detected technology: Nginx. Suggested authentication: Cookie-based session ID."
        return "This is a mock text generation response from MockProvider."

    def generate_json(self, prompt: str, schema: Dict[str, Any], system_instruction: str = None) -> Dict[str, Any]:
        # Return mock JSON structures based on keywords
        prompt_lower = prompt.lower()
        if "hypotheses" in prompt_lower or "endpoints" in prompt_lower:
            return {
                "hypotheses": [
                    {
                        "id": "h-001",
                        "title": "Broken Access Control on User Profile",
                        "description": "The application endpoint does not check authorization token claims properly.",
                        "confidence": 0.85,
                        "vulnerability_type": "IDOR"
                    },
                    {
                        "id": "h-002",
                        "title": "SQL Injection in Search Input",
                        "description": "Search input parameter shows verbose database errors when single quotes are injected.",
                        "confidence": 0.9,
                        "vulnerability_type": "SQLi"
                    }
                ]
            }
        
        if "confidence" in prompt_lower or "false_positive" in prompt_lower:
            return {
                "confidence": 0.95,
                "explanation": "The endpoint returns database error details which is a strong indicator of SQL injection.",
                "is_false_positive": False
            }

        return {}


class GeminiProvider(LLMProvider):
    """LLM provider utilizing the Gemini API."""

    def __init__(self, api_key: str = None, model_name: str = "gemini-2.5-flash"):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.model_name = model_name
        if genai is None:
            raise ImportError("google-generativeai package is not installed.")
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY is not set.")
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel(self.model_name)

    def generate_text(self, prompt: str, system_instruction: str = None) -> str:
        # If system instruction is provided, we can pass it during configuration
        config = {}
        if system_instruction:
            model = genai.GenerativeModel(self.model_name, system_instruction=system_instruction)
        else:
            model = self.model

        response = model.generate_content(prompt)
        return response.text

    def generate_json(self, prompt: str, schema: Dict[str, Any], system_instruction: str = None) -> Dict[str, Any]:
        # Gemini supports structured JSON output
        generation_config = {
            "response_mime_type": "application/json",
            "response_schema": schema,
        }
        
        if system_instruction:
            model = genai.GenerativeModel(
                self.model_name, 
                system_instruction=system_instruction,
                generation_config=generation_config
            )
        else:
            model = genai.GenerativeModel(
                self.model_name,
                generation_config=generation_config
            )

        response = model.generate_content(prompt)
        try:
            return json.loads(response.text)
        except json.JSONDecodeError:
            # Fallback parsing
            return {"error": "Failed to parse JSON response from Gemini", "raw": response.text}


class OllamaProvider(LLMProvider):
    """LLM provider utilizing local Ollama instance."""

    def __init__(self, host: str = "http://localhost:11434", model_name: str = "llama3"):
        self.host = host
        self.model_name = model_name
        if requests is None:
            raise ImportError("requests package is not installed.")

    def generate_text(self, prompt: str, system_instruction: str = None) -> str:
        url = f"{self.host}/api/generate"
        system_prompt = system_instruction or ""
        
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "system": system_prompt,
            "stream": False
        }
        
        try:
            res = requests.post(url, json=payload, timeout=30)
            res.raise_for_status()
            return res.json().get("response", "")
        except Exception as e:
            return f"Ollama error: {str(e)}"

    def generate_json(self, prompt: str, schema: Dict[str, Any], system_instruction: str = None) -> Dict[str, Any]:
        url = f"{self.host}/api/generate"
        system_prompt = system_instruction or ""
        
        # Inject json instructions to prompt for Ollama compatibility
        full_prompt = prompt + "\nRespond strictly in valid JSON format."
        
        payload = {
            "model": self.model_name,
            "prompt": full_prompt,
            "system": system_prompt,
            "stream": False,
            "format": "json" # Ollama native JSON output parameter
        }
        
        try:
            res = requests.post(url, json=payload, timeout=30)
            res.raise_for_status()
            text = res.json().get("response", "")
            return json.loads(text)
        except Exception as e:
            return {"error": f"Failed to execute Ollama JSON generate: {str(e)}"}
