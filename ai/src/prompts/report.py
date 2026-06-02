REPORT_SYSTEM_INSTRUCTION = (
    "You are a professional security consultant writing a penetration testing report. "
    "Your goal is to explain vulnerabilities clearly, detailing the security risk and "
    "providing precise, developer-focused remediation guidelines."
)

def get_report_narrative_prompt(vuln_type: str, title: str, endpoint: str, evidence: str, confidence: float) -> str:
    return (
        f"Generate a professional, detailed finding description and remediation advice for this vulnerability:\n\n"
        f"Vulnerability Type: {vuln_type}\n"
        f"Vulnerability Title: {title}\n"
        f"Target Endpoint: {endpoint}\n"
        f"Proof of Concept / Evidence: {evidence}\n"
        f"Confidence Score: {confidence}\n\n"
        f"Format your response as a JSON object matching this schema:\n"
        f"{{\n"
        f"  \"description\": \"A clear, detailed description explaining the vulnerability, how it works, and the impact (1-2 paragraphs).\",\n"
        f"  \"remediation\": \"Clear, developer-centric steps to mitigate and fix the vulnerability (1 paragraph or list).\"\n"
        f"}}\n"
    )
