import sys
import os
import time
import base64
import json
from concurrent import futures
import grpc
from dotenv import load_dotenv

# Add the generated proto directory to sys.path to enable direct imports
proto_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'proto'))
proto_sub_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'proto', 'ai', 'v1'))
sys.path.append(proto_dir)
sys.path.append(proto_sub_dir)

import ai_pb2
import ai_pb2_grpc
from llm.provider import LLMProvider, MockProvider, GeminiProvider, ProviderManager
from prompts.browser import BROWSER_SYSTEM_INSTRUCTION, get_decide_action_prompt

# Load environment variables
load_dotenv()


class AiServiceServicer(ai_pb2_grpc.AiServiceServicer):
    """gRPC Servicer implementing the AiService interface with dynamic key cycling and failover."""

    def __init__(self):
        # Select provider based on environment variable (defaults to manager)
        provider_type = os.getenv("AI_PROVIDER", "manager").lower()
        
        self.mock_provider = MockProvider()
        self.gemini_providers = {}  # Cache by model_name
        
        if provider_type == "mock":
            print("[AI] Initializing Mock LLM Provider (explicitly requested).")
            self.provider = self.mock_provider
        else:
            print("[AI] Initializing ProviderManager with failover & circuit breaker.")
            self.provider = ProviderManager()

    def _get_provider(self, context) -> LLMProvider:
        metadata = dict(context.invocation_metadata())
        provider_type = metadata.get('x-ai-provider')
        model_name = metadata.get('x-gemini-model', 'gemini-3.5-flash')
        
        if not provider_type:
            return self.provider
            
        provider_type = provider_type.lower()
        if provider_type == "mock":
            return self.mock_provider
        elif provider_type == "gemini":
            if model_name not in self.gemini_providers:
                api_key = os.getenv("GEMINI_API_KEY")
                self.gemini_providers[model_name] = GeminiProvider(api_key=api_key, model_name=model_name)
            return self.gemini_providers[model_name]
        else:
            return self.provider

    def Health(self, request, context):
        print("[AI] Received Health request")
        provider = self._get_provider(context)
        provider_name = "mock"
        model_name = "mock-model"
        initialized = True

        if isinstance(provider, GeminiProvider):
            provider_name = "gemini"
            model_name = getattr(provider, "model_name", "gemini-3.5-flash")
        elif isinstance(provider, ProviderManager):
            p_name, active_p = provider._get_active_provider()
            provider_name = f"manager({p_name})"
            model_name = getattr(active_p, "model_name", "unknown")
        else:
            requested = os.getenv("AI_PROVIDER", "mock").lower()
            if requested != "mock":
                initialized = False

        return ai_pb2.HealthResponse(
            status="ok",
            provider=provider_name,
            model=model_name,
            initialized=initialized
        )

    def AnalyzeRecon(self, request, context):
        print(f"[AI] Received AnalyzeRecon request for target: {request.target_url}")
        
        # Build prompt for LLM analysis
        prompt = (
            f"Analyze the following reconnaissance data for the target web application:\n"
            f"Target URL: {request.target_url}\n"
            f"HTTP Response Headers: {dict(request.headers)}\n"
            f"Discovered Cookie Names: {list(request.cookie_names)}\n"
            f"Describe the suspected technologies, authentication flow mechanism, and recommend security test categories."
        )
        
        system_instruction = "You are a senior penetration tester. Perform technical web application profiling."
        
        schema = {
            "type": "object",
            "properties": {
                "detected_technologies": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "authentication_model": {"type": "string"},
                "recommended_tests": {
                    "type": "array",
                    "items": {"type": "string"}
                }
            },
            "required": ["detected_technologies", "authentication_model", "recommended_tests"]
        }

        try:
            provider = self._get_provider(context)
            if isinstance(provider, MockProvider):
                # Mock response maps directly
                return ai_pb2.AnalyzeReconResponse(
                    detected_technologies=["Nginx", "PHP", "Laravel"],
                    authentication_model="Cookie-based Session Auth",
                    recommended_tests=["XSS Testing", "SQL Injection Fuzzing", "Authentication Bypass Check"]
                )

            # Query real provider using structured JSON generation
            res_json = provider.generate_json(
                prompt, 
                schema=schema, 
                system_instruction=system_instruction
            )
            
            return ai_pb2.AnalyzeReconResponse(
                detected_technologies=res_json.get("detected_technologies", ["Unknown Stack"]),
                authentication_model=res_json.get("authentication_model", "Unknown Auth Flow"),
                recommended_tests=res_json.get("recommended_tests", ["Standard Scan Profile"])
            )
        except Exception as e:
            print(f"[AI] [ERROR] AnalyzeRecon failed: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Internal LLM error: {str(e)}")
            return ai_pb2.AnalyzeReconResponse()

    def GenerateHypotheses(self, request, context):
        print(f"[AI] Received GenerateHypotheses request for: {request.target_url} with {len(request.endpoints)} endpoints")
        
        schema = {
            "type": "object",
            "properties": {
                "hypotheses": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "title": {"type": "string"},
                            "description": {"type": "string"},
                            "confidence": {"type": "number"},
                            "vulnerability_type": {"type": "string"}
                        },
                        "required": ["id", "title", "description", "confidence", "vulnerability_type"]
                    }
                }
            },
            "required": ["hypotheses"]
        }
        
        prompt = (
            f"Generate security test cases and attack hypotheses for the target: {request.target_url}.\n"
            f"Observed endpoints:\n" + "\n".join(request.endpoints)
        )
        
        try:
            provider = self._get_provider(context)
            result_json = provider.generate_json(
                prompt, 
                schema=schema, 
                system_instruction="Identify potential security issues and business logic flaws in endpoints."
            )
            
            hypotheses = []
            for h in result_json.get("hypotheses", []):
                hypotheses.append(ai_pb2.Hypothesis(
                    id=h.get("id", "unknown"),
                    title=h.get("title", ""),
                    description=h.get("description", ""),
                    confidence=float(h.get("confidence", 0.5)),
                    vulnerability_type=h.get("vulnerability_type", "")
                ))
                
            return ai_pb2.GenerateHypothesesResponse(hypotheses=hypotheses)
        except Exception as e:
            print(f"[AI] [ERROR] GenerateHypotheses failed: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return ai_pb2.GenerateHypothesesResponse()

    def ScoreConfidence(self, request, context):
        print(f"[AI] Received ScoreConfidence request for {request.vulnerability_type} on {request.endpoint}")
        
        schema = {
            "type": "object",
            "properties": {
                "confidence": {"type": "number"},
                "explanation": {"type": "string"},
                "is_false_positive": {"type": "boolean"}
            },
            "required": ["confidence", "explanation", "is_false_positive"]
        }
        
        prompt = (
            f"Verify if the following finding is a true positive vulnerability:\n"
            f"Type: {request.vulnerability_type}\n"
            f"Endpoint: {request.endpoint}\n"
            f"Payload: {request.payload}\n"
            f"Response Code: {request.response_status}\n"
            f"Response Body (sample): {request.response_body[:500]}"
        )
        
        try:
            provider = self._get_provider(context)
            res_json = provider.generate_json(prompt, schema=schema)
            return ai_pb2.ScoreConfidenceResponse(
                confidence=float(res_json.get("confidence", 0.5)),
                explanation=res_json.get("explanation", ""),
                is_false_positive=bool(res_json.get("is_false_positive", False))
            )
        except Exception as e:
            print(f"[AI] [ERROR] ScoreConfidence failed: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return ai_pb2.ScoreConfidenceResponse()

    def GenerateAttackPayload(self, request, context):
        print(f"[AI] Received GenerateAttackPayload request for: {request.hypothesis_title}")

        schema = {
            "type": "object",
            "properties": {
                "method": {"type": "string"},
                "url": {"type": "string"},
                "body": {"type": "string"},
                "headers_json": {"type": "string"},
                "explanation": {"type": "string"}
            },
            "required": ["method", "url", "body", "headers_json", "explanation"]
        }

        prompt = (
            f"Generate a specific adversarial HTTP request to test the following hypothesis:\n"
            f"Title: {request.hypothesis_title}\n"
            f"Description: {request.hypothesis_description}\n"
            f"Target Endpoint: {request.endpoint}\n"
            f"Observed Method: {request.method}\n\n"
            f"Provide a realistic exploit payload that proves the vulnerability exists.\n"
            f"Return headers_json as a JSON-encoded string mapping HTTP headers to values (e.g. '{{\"Content-Type\": \"application/json\"}}')."
        )

        try:
            provider = self._get_provider(context)
            if isinstance(provider, MockProvider):
                title_lower = request.hypothesis_title.lower()
                method = request.method
                url = request.endpoint
                body = ""
                
                # Check for query parameters or construct one
                param_name = "q"
                if "parameter:" in title_lower:
                    parts = title_lower.split("parameter:")
                    if len(parts) > 1:
                        param_name = parts[1].strip().split()[0].strip("[]()")
                elif "in " in title_lower:
                    parts = title_lower.split("in ")
                    if len(parts) > 1:
                        param_name = parts[1].strip().split()[0].strip("[]()")
                else:
                    param_name = "q"

                if "sqli" in title_lower or "sql injection" in title_lower:
                    payload = "1' OR '1'='1"
                elif "xss" in title_lower or "reflected xss" in title_lower:
                    payload = "<script>alert(1)</script>"
                elif "path traversal" in title_lower or "traversal" in title_lower:
                    payload = "../../../../etc/passwd"
                elif "csrf" in title_lower:
                    payload = "csrf_exploit_val"
                else:
                    payload = "mock_payload"

                if method.upper() == "GET":
                    sep = "&" if "?" in url else "?"
                    url = f"{url}{sep}{param_name}={payload}"
                else:
                    body = f"{param_name}={payload}"

                return ai_pb2.GenerateAttackPayloadResponse(
                    method=method,
                    url=url,
                    body=body,
                    headers={"X-LR-Mock": "true", "Content-Type": "application/x-www-form-urlencoded" if body else "text/html"},
                    explanation=f"Mock attack payload generated for {request.hypothesis_title}."
                )

            res_json = provider.generate_json(
                prompt,
                schema=schema,
                system_instruction="You are a professional penetration tester. Create targeted HTTP exploit payloads."
            )

            headers_raw = res_json.get("headers_json", "{}")
            headers_dict = {}
            if headers_raw:
                try:
                    if isinstance(headers_raw, dict):
                        headers_dict = headers_raw
                    else:
                        headers_dict = json.loads(headers_raw)
                except Exception:
                    headers_dict = {}

            return ai_pb2.GenerateAttackPayloadResponse(
                method=res_json.get("method", request.method),
                url=res_json.get("url", request.endpoint),
                body=res_json.get("body", ""),
                headers=headers_dict,
                explanation=res_json.get("explanation", "")
            )
        except Exception as e:
            print(f"[AI] [ERROR] GenerateAttackPayload failed: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return ai_pb2.GenerateAttackPayloadResponse()

    def DecideBrowserAction(self, request, context):
        print(f"[AI] Received DecideBrowserAction request for goal: {request.current_goal}")

        schema = {
            "type": "object",
            "properties": {
                "action": {"type": "string"},
                "selector": {"type": "string"},
                "value": {"type": "string"},
                "explanation": {"type": "string"}
            },
            "required": ["action", "selector", "value", "explanation"]
        }

        try:
            # Prepare prompt and image
            prompt = get_decide_action_prompt(request)
            
            image_data = None
            if request.screenshot_base64:
                try:
                    # Clean the base64 string if it has a prefix
                    b64_str = request.screenshot_base64
                    if "," in b64_str:
                        b64_str = b64_str.split(",")[1]
                    image_data = base64.b64decode(b64_str)
                except Exception as e:
                    print(f"[AI] [WARNING] Failed to decode screenshot: {e}")

            provider = self._get_provider(context)
            if isinstance(provider, MockProvider):
                # We can still use generate_json with MockProvider as it was updated
                res_json = provider.generate_json(
                    prompt,
                    schema=schema,
                    system_instruction=BROWSER_SYSTEM_INSTRUCTION,
                    image_data=image_data
                )
                return ai_pb2.DecideBrowserActionResponse(
                    action=res_json.get("action", "finish"),
                    selector=res_json.get("selector", ""),
                    value=res_json.get("value", ""),
                    explanation=res_json.get("explanation", "Mock response.")
                )

            res_json = provider.generate_json(
                prompt,
                schema=schema,
                system_instruction=BROWSER_SYSTEM_INSTRUCTION,
                image_data=image_data
            )

            return ai_pb2.DecideBrowserActionResponse(
                action=res_json.get("action", "wait"),
                selector=res_json.get("selector", ""),
                value=res_json.get("value", ""),
                explanation=res_json.get("explanation", "")
            )
        except Exception as e:
            print(f"[AI] [ERROR] DecideBrowserAction failed: {e}")
            import traceback
            traceback.print_exc()
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return ai_pb2.DecideBrowserActionResponse()

    def GenerateFindingNarrative(self, request, context):
        print(f"[AI] Received GenerateFindingNarrative request for: {request.title}")

        schema = {
            "type": "object",
            "properties": {
                "description": {"type": "string"},
                "remediation": {"type": "string"}
            },
            "required": ["description", "remediation"]
        }

        try:
            from prompts.report import REPORT_SYSTEM_INSTRUCTION, get_report_narrative_prompt
            prompt = get_report_narrative_prompt(
                request.vulnerability_type,
                request.title,
                request.endpoint,
                request.evidence,
                request.confidence
            )

            provider = self._get_provider(context)
            if isinstance(provider, MockProvider):
                return ai_pb2.GenerateFindingNarrativeResponse(
                    description=f"This is a mock description for finding '{request.title}'. It explains how this affects {request.endpoint}.",
                    remediation=f"This is a mock remediation for {request.vulnerability_type}. Ensure proper filters are applied."
                )

            res_json = provider.generate_json(
                prompt,
                schema=schema,
                system_instruction=REPORT_SYSTEM_INSTRUCTION
            )

            return ai_pb2.GenerateFindingNarrativeResponse(
                description=res_json.get("description", ""),
                remediation=res_json.get("remediation", "")
            )
        except Exception as e:
            print(f"[AI] [ERROR] GenerateFindingNarrative failed: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return ai_pb2.GenerateFindingNarrativeResponse()


def serve(port: int = 50052):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=5))
    ai_pb2_grpc.add_AiServiceServicer_to_server(AiServiceServicer(), server)
    server.add_insecure_port(f'127.0.0.1:{port}')
    print(f"[AI] Server started. Listening on gRPC port {port}...")
    server.start()
    try:
        while True:
            time.sleep(86400)
    except KeyboardInterrupt:
        print("[AI] Shutting down server...")
        server.stop(0)


if __name__ == '__main__':
    # Allow port override from env
    port = int(os.getenv("AI_PORT", 50052))
    serve(port=port)
