import os
import sys
import json
import time
import traceback
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional

# Optional imports that might not be loaded if we don't use them
try:
    from google import genai
    from google.genai import types
except ImportError:
    genai = None
    types = None

try:
    import requests
except ImportError:
    requests = None


class LLMProvider(ABC):
    """Abstract interface for LLM providers."""

    @abstractmethod
    def generate_text(self, prompt: str, system_instruction: str = None, model_name: str = None) -> str:
        pass

    @abstractmethod
    def generate_json(self, prompt: str, schema: Dict[str, Any], system_instruction: str = None, image_data: bytes = None, image_mime_type: str = "image/png", model_name: str = None) -> Dict[str, Any]:
        pass


class MockProvider(LLMProvider):
    """A mock LLM provider for local development and testing without credentials."""

    def generate_text(self, prompt: str, system_instruction: str = None, model_name: str = None) -> str:
        prompt_lower = prompt.lower()
        if "recon" in prompt_lower or "headers" in prompt_lower:
            return "Detected technology: Nginx. Suggested authentication: Cookie-based session ID."
        return "This is a mock text generation response from MockProvider."

    def generate_json(self, prompt: str, schema: Dict[str, Any], system_instruction: str = None, image_data: bytes = None, image_mime_type: str = "image/png", model_name: str = None) -> Dict[str, Any]:
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
                    },
                    {
                        "id": "h-003",
                        "title": "Reflected XSS in query parameter",
                        "description": "Input parameter is reflected back into the HTML document context without proper sanitization.",
                        "confidence": 0.88,
                        "vulnerability_type": "Reflected XSS"
                    },
                    {
                        "id": "h-004",
                        "title": "CSRF on State-Changing Action",
                        "description": "No anti-CSRF tokens are present on state-changing endpoints.",
                        "confidence": 0.82,
                        "vulnerability_type": "CSRF"
                    },
                    {
                        "id": "h-005",
                        "title": "Path Traversal in file parameter",
                        "description": "File parameter allows reading arbitrary files using relative dot-dot-slash patterns.",
                        "confidence": 0.80,
                        "vulnerability_type": "Path Traversal"
                    }
                ]
            }
        
        if "confidence" in prompt_lower or "false_positive" in prompt_lower:
            vuln_type = "vulnerability"
            if "xss" in prompt_lower or "reflected xss" in prompt_lower:
                vuln_type = "Reflected XSS (alert execution detected)"
            elif "csrf" in prompt_lower:
                vuln_type = "CSRF protection missing"
            elif "traversal" in prompt_lower or "path" in prompt_lower:
                vuln_type = "Path Traversal (file content read successful)"
            elif "rate limit" in prompt_lower:
                vuln_type = "Rate Limiting missing"
            elif "sqli" in prompt_lower or "sql" in prompt_lower:
                vuln_type = "SQL Injection error detected"

            return {
                "confidence": 0.95,
                "explanation": f"The response confirms {vuln_type}.",
                "is_false_positive": False
            }

        if "action" in prompt_lower or "goal" in prompt_lower:
            return {
                "action": "finish",
                "selector": "",
                "value": "",
                "explanation": "Mock action: finishing."
            }

        return {}


class GeminiProvider(LLMProvider):
    """LLM provider utilizing the Gemini API with automatic key cycling."""

    _shared_current_key_index = 0

    def __init__(self, api_key: str = None, model_name: str = "gemini-3.5-flash"):
        self.model_name = model_name
        if genai is None or types is None:
            raise ImportError("google-genai package is not installed.")
            
        primary = api_key or os.getenv("GEMINI_API_KEY")
        backups = os.getenv("GEMINI_BACKUP_KEYS", "")
        self.api_keys = []
        if primary:
            self.api_keys.append(primary)
        if backups:
            for k in backups.split(','):
                k = k.strip()
                if k and k not in self.api_keys:
                    self.api_keys.append(k)

        if not self.api_keys:
            raise ValueError("GEMINI_API_KEY is not set.")

    def _execute_with_retry(self, method_name: str, *args, **kwargs):
        attempts = len(self.api_keys)
        for attempt in range(attempts):
            idx = GeminiProvider._shared_current_key_index % len(self.api_keys)
            key = self.api_keys[idx]
            client = genai.Client(api_key=key)
            func = getattr(client.models, method_name)
            try:
                return func(*args, **kwargs)
            except Exception as e:
                err_str = str(e).lower()
                is_retryable = any(term in err_str for term in ["429", "403", "quota", "exhausted", "limit", "permission", "api_key", "invalid"])
                if is_retryable and attempt < attempts - 1:
                    GeminiProvider._shared_current_key_index = (GeminiProvider._shared_current_key_index + 1) % len(self.api_keys)
                    print(f"[AI] Gemini API Key failover: Rotating to key index {GeminiProvider._shared_current_key_index}.")
                    continue
                raise e

    def generate_text(self, prompt: str, system_instruction: str = None, model_name: str = None) -> str:
        config = {}
        if system_instruction:
            config["system_instruction"] = system_instruction

        response = self._execute_with_retry(
            "generate_content",
            model=model_name or self.model_name,
            contents=prompt,
            config=config if config else None
        )
        return response.text

    def generate_json(self, prompt: str, schema: Dict[str, Any], system_instruction: str = None, image_data: bytes = None, image_mime_type: str = "image/png", model_name: str = None) -> Dict[str, Any]:
        config = {
            "response_mime_type": "application/json",
            "response_schema": schema,
        }
        if system_instruction:
            config["system_instruction"] = system_instruction
            
        contents = [prompt]
        if image_data:
            image_part = types.Part.from_bytes(
                data=image_data,
                mime_type=image_mime_type
            )
            contents.append(image_part)

        response = self._execute_with_retry(
            "generate_content",
            model=model_name or self.model_name,
            contents=contents,
            config=config
        )
        try:
            return json.loads(response.text)
        except json.JSONDecodeError:
            return {"error": "Failed to parse JSON response from Gemini", "raw": response.text}


class OpenAICompatProvider(LLMProvider):
    """LLM provider for OpenAI-compatible services (DeepSeek, Kimi, GLM)."""

    def __init__(self, api_key: str, base_url: str, model_name: str):
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')
        self.model_name = model_name
        if requests is None:
            raise ImportError("requests package is not installed.")

    def generate_text(self, prompt: str, system_instruction: str = None, model_name: str = None) -> str:
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        messages = []
        if system_instruction:
            messages.append({"role": "system", "content": system_instruction})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": model_name or self.model_name,
            "messages": messages,
            "temperature": 0.1
        }

        res = requests.post(url, json=payload, headers=headers, timeout=30)
        res.raise_for_status()
        res_json = res.json()
        
        # Track usage token metadata (logged by Manager)
        self.last_usage = res_json.get("usage", {})
        return res_json["choices"][0]["message"]["content"]

    def generate_json(self, prompt: str, schema: Dict[str, Any], system_instruction: str = None, image_data: bytes = None, image_mime_type: str = "image/png", model_name: str = None) -> Dict[str, Any]:
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        # Format prompt to enforce JSON output constraints
        json_instruction = "\nIMPORTANT: Return strictly valid JSON matching the requested structure. Do not output conversational text."
        full_prompt = prompt + json_instruction

        messages = []
        if system_instruction:
            messages.append({"role": "system", "content": system_instruction})
            
        # Multimodal capability check (for visual page screenshots)
        if image_data:
            image_b64 = base64_image = base64_image = base64_image = base64_image = base64_image = base64_image = ""
            import base64
            image_b64 = base64.b64encode(image_data).decode('utf-8')
            messages.append({
                "role": "user",
                "content": [
                    {"type": "text", "text": full_prompt},
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:{image_mime_type};base64,{image_b64}"
                        }
                    }
                ]
            })
        else:
            messages.append({"role": "user", "content": full_prompt})

        payload = {
            "model": model_name or self.model_name,
            "messages": messages,
            "temperature": 0.1,
            "response_format": {"type": "json_object"}
        }

        res = requests.post(url, json=payload, headers=headers, timeout=45)
        res.raise_for_status()
        res_json = res.json()
        
        # Track usage tokens
        self.last_usage = res_json.get("usage", {})
        text = res_json["choices"][0]["message"]["content"].strip()
        
        # Strip markdown syntax if returned
        if text.startswith("```"):
            lines = text.split("\n")
            if lines[0].startswith("```json"):
                text = "\n".join(lines[1:-1])
            elif lines[0].startswith("```"):
                text = "\n".join(lines[1:-1])
        
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"error": "Failed to parse OpenAICompat JSON response", "raw": text}


class ProviderManager(LLMProvider):
    """Abstraction layer managing primary and fallback providers, retries, and health scores."""

    def __init__(self):
        self.providers: Dict[str, LLMProvider] = {}
        self.health_scores: Dict[str, Dict[str, Any]] = {}
        self.circuit_breakers: Dict[str, Dict[str, Any]] = {}
        self.cost_log: List[Dict[str, Any]] = []

        # Boot Gemini (Primary)
        gemini_key = os.getenv("GEMINI_API_KEY")
        if gemini_key:
            try:
                self.providers["gemini"] = GeminiProvider(api_key=gemini_key, model_name="gemini-3.5-flash")
                self._init_health("gemini")
            except Exception as e:
                print(f"[AI Manager] [WARNING] Failed to load Gemini: {e}")

        # Boot Fallback Providers
        deepseek_key = os.getenv("DEEPSEEK_API_KEY")
        if deepseek_key:
            self.providers["deepseek"] = OpenAICompatProvider(
                api_key=deepseek_key,
                base_url="https://api.deepseek.com",
                model_name="deepseek-chat"
            )
            self._init_health("deepseek")

        kimi_key = os.getenv("KIMI_API_KEY")
        if kimi_key:
            self.providers["kimi"] = OpenAICompatProvider(
                api_key=kimi_key,
                base_url="https://api.moonshot.cn/v1",
                model_name="moonshot-v1-8k"
            )
            self._init_health("kimi")

        glm_key = os.getenv("GLM_API_KEY")
        if glm_key:
            self.providers["glm"] = OpenAICompatProvider(
                api_key=glm_key,
                base_url="https://open.bigmodel.cn/api/paas/v4",
                model_name="glm-4-flash"
            )
            self._init_health("glm")

        # Provider priority order for failovers
        self.priority_order = ["gemini", "deepseek", "glm", "kimi"]

    def _init_health(self, name: str):
        self.health_scores[name] = {"latency_sum": 0.0, "calls": 0, "failures": 0}
        self.circuit_breakers[name] = {"tripped": False, "consecutive_failures": 0, "tripped_until": 0.0}

    def _update_health(self, name: str, elapsed: float, success: bool):
        health = self.health_scores.get(name)
        cb = self.circuit_breakers.get(name)
        if not health or not cb:
            return

        health["calls"] += 1
        if success:
            health["latency_sum"] += elapsed
            cb["consecutive_failures"] = 0
            if cb["tripped"]:
                print(f"[AI Manager] Circuit Breaker RESET for provider: {name}")
                cb["tripped"] = False
        else:
            health["failures"] += 1
            cb["consecutive_failures"] += 1
            if cb["consecutive_failures"] >= 3:
                cb["tripped"] = True
                cb["tripped_until"] = time.time() + 60.0 # Trip for 60s
                print(f"[AI Manager] [CRITICAL] Circuit Breaker TRIPPED for provider: {name} until {cb['tripped_until']}. Failures: {cb['consecutive_failures']}")

    def _get_active_provider(self) -> tuple[str, LLMProvider]:
        now = time.time()
        for name in self.priority_order:
            if name not in self.providers:
                continue
            
            cb = self.circuit_breakers[name]
            if cb["tripped"]:
                if now > cb["tripped_until"]:
                    # Cooldown finished, probe provider
                    cb["tripped"] = False
                else:
                    # Bypassed
                    continue
            
            return name, self.providers[name]
        
        # All crashed - fallback to first available
        if self.providers:
            first = list(self.providers.keys())[0]
            return first, self.providers[first]
        
        # Ultimate fallback
        return "mock", MockProvider()

    def _log_cost(self, provider_name: str, model_name: str, usage: Dict[str, Any]):
        if not usage:
            return
        
        prompt_tokens = usage.get("prompt_tokens", 0)
        completion_tokens = usage.get("completion_tokens", 0)
        
        # Basic cost estimation models
        rates = {
            "gemini-3.5-flash": {"in": 0.075 / 1e6, "out": 0.30 / 1e6},
            "deepseek-chat": {"in": 0.14 / 1e6, "out": 2.19 / 1e6},
            "moonshot-v1-8k": {"in": 1.65 / 1e6, "out": 1.65 / 1e6},
            "glm-4-flash": {"in": 0.01 / 1e6, "out": 0.01 / 1e6}
        }
        
        rate = rates.get(model_name, {"in": 0.50 / 1e6, "out": 1.50 / 1e6})
        cost = (prompt_tokens * rate["in"]) + (completion_tokens * rate["out"])
        
        log_entry = {
            "timestamp": time.time(),
            "provider": provider_name,
            "model": model_name,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "cost_usd": cost
        }
        self.cost_log.append(log_entry)
        print(f"[AI Cost Tracker] Provider: {provider_name} ({model_name}) | Tokens: {prompt_tokens} In, {completion_tokens} Out | USD: ${cost:.6f}")

    def generate_text(self, prompt: str, system_instruction: str = None, model_name: str = None) -> str:
        max_retries = 3
        last_exception = None

        for retry in range(max_retries):
            p_name, provider = self._get_active_provider()
            start = time.time()
            try:
                # Apply model override parameters
                actual_model = model_name
                if not actual_model and hasattr(provider, "model_name"):
                    actual_model = provider.model_name

                res = provider.generate_text(prompt, system_instruction=system_instruction, model_name=actual_model)
                elapsed = time.time() - start
                self._update_health(p_name, elapsed, True)
                
                # Check for usage telemetry tracking
                if hasattr(provider, "last_usage"):
                    self._log_cost(p_name, actual_model, provider.last_usage)
                return res
            except Exception as e:
                elapsed = time.time() - start
                self._update_health(p_name, elapsed, False)
                print(f"[AI Manager] [ERROR] generate_text failed on {p_name} (Attempt {retry+1}/{max_retries}): {e}")
                last_exception = e
                # Backoff before retrying
                time.sleep(2 ** retry)

        raise last_exception or RuntimeError("All model providers failed generate_text execution.")

    def generate_json(self, prompt: str, schema: Dict[str, Any], system_instruction: str = None, image_data: bytes = None, image_mime_type: str = "image/png", model_name: str = None) -> Dict[str, Any]:
        max_retries = 3
        last_exception = None

        for retry in range(max_retries):
            p_name, provider = self._get_active_provider()
            start = time.time()
            try:
                actual_model = model_name
                if not actual_model and hasattr(provider, "model_name"):
                    actual_model = provider.model_name

                # Kimi and GLM do not support visual inputs natively; bypass image if selected fallback is blind
                active_image = image_data
                if p_name in ["glm", "kimi"] and active_image:
                    print(f"[AI Manager] [WARNING] Falling back to text-only mode on blind provider {p_name}.")
                    active_image = None

                res = provider.generate_json(
                    prompt,
                    schema=schema,
                    system_instruction=system_instruction,
                    image_data=active_image,
                    image_mime_type=image_mime_type,
                    model_name=actual_model
                )
                
                # Return code error indicator checks
                if "error" in res and not res.get("success", True):
                    raise ValueError(f"JSON Output Generation Error: {res.get('error')}")

                elapsed = time.time() - start
                self._update_health(p_name, elapsed, True)
                
                if hasattr(provider, "last_usage"):
                    self._log_cost(p_name, actual_model, provider.last_usage)
                return res
            except Exception as e:
                elapsed = time.time() - start
                self._update_health(p_name, elapsed, False)
                print(f"[AI Manager] [ERROR] generate_json failed on {p_name} (Attempt {retry+1}/{max_retries}): {e}")
                last_exception = e
                time.sleep(2 ** retry)

        raise last_exception or RuntimeError("All model providers failed generate_json execution.")
