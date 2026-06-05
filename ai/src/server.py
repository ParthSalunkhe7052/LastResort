import sys
import os
import time
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

# Load environment variables
load_dotenv()


class AiServiceServicer(ai_pb2_grpc.AiServiceServicer):
    """gRPC Servicer implementing the AiService interface for report summaries."""

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

    def GenerateExecutiveSummary(self, request, context):
        print(f"[AI] Received GenerateExecutiveSummary request for target: {request.target_url}")

        schema = {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "risk_rating": {"type": "string"},
                "key_recommendations": {
                    "type": "array",
                    "items": {"type": "string"}
                }
            },
            "required": ["summary", "risk_rating", "key_recommendations"]
        }

        # Format findings for prompt context
        findings_details = []
        for f in request.findings:
            findings_details.append(
                f"- Title: {f.title}\n  Severity: {f.severity}\n  Type: {f.vulnerability_type}\n  Endpoint: {f.endpoint}\n  Confidence: {f.confidence}"
            )
        findings_context = "\n".join(findings_details)

        prompt = (
            f"Analyze the vulnerability results from the security assessment of target web application:\n"
            f"Target URL: {request.target_url}\n"
            f"Total HIGH Findings: {request.high_count}\n"
            f"Total MEDIUM Findings: {request.medium_count}\n"
            f"Total LOW Findings: {request.low_count}\n"
            f"Total INFO Findings: {request.info_count}\n"
            f"Scan Duration: {request.duration}\n"
            f"Detected Technologies: {request.detected_technologies}\n\n"
            f"Findings List:\n{findings_context}\n\n"
            f"Generate a professional executive summary of the security posture, a general risk rating (CRITICAL, HIGH, MEDIUM, or LOW), and top 3 key security recommendations."
        )

        system_instruction = "You are a senior security director. Provide a high-level executive summary and actionable recommendations."

        try:
            provider = self._get_provider(context)
            if isinstance(provider, MockProvider):
                return ai_pb2.GenerateExecutiveSummaryResponse(
                    summary=f"The automated security assessment of {request.target_url} revealed several issues. The overall risk is marked by high severity items.",
                    risk_rating="HIGH",
                    key_recommendations=[
                        "Enforce input filtering and output encoding to address injection vectors.",
                        "Harden application configurations and implement missing security headers.",
                        "Establish continuous vulnerability monitoring."
                    ]
                )

            res_json = provider.generate_json(
                prompt,
                schema=schema,
                system_instruction=system_instruction
            )

            return ai_pb2.GenerateExecutiveSummaryResponse(
                summary=res_json.get("summary", ""),
                risk_rating=res_json.get("risk_rating", "MEDIUM"),
                key_recommendations=res_json.get("key_recommendations", [])
            )
        except Exception as e:
            print(f"[AI] [ERROR] GenerateExecutiveSummary failed: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return ai_pb2.GenerateExecutiveSummaryResponse(
                summary="Failed to generate executive summary narrative due to LLM error.",
                risk_rating="UNKNOWN",
                key_recommendations=["Review the technical report findings directly."]
            )


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
