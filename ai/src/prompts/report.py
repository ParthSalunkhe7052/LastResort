REPORT_SYSTEM_INSTRUCTION = (
    "You are a professional security consultant writing a penetration testing report. "
    "Your goal is to explain vulnerabilities clearly, detailing the security risk and "
    "providing precise, developer-focused remediation guidelines."
)

def get_report_narrative_prompt(vuln_type: str, title: str, endpoint: str, evidence: str, confidence: float) -> str:
    return (
        f"Generate a concise security finding summary and remediation advice. "
        f"You must strictly follow these rules:\n"
        f"1. Maximum 4 bullets per section.\n"
        f"2. Maximum 1 sentence per bullet.\n"
        f"3. No giant paragraphs. No security consultant fluff.\n\n"
        f"Vulnerability Type: {vuln_type}\n"
        f"Vulnerability Title: {title}\n"
        f"Target Endpoint: {endpoint}\n"
        f"Proof of Concept / Evidence: {evidence}\n"
        f"Confidence Score: {confidence}\n\n"
        f"If the finding is an OBSERVATION (e.g. missing header, missing cookie flag, permissive config):\n"
        f"Use this exact format for the description field:\n"
        f"Risk:\\n- <1-sentence risk>\\n\\nEvidence:\\n- <1-sentence evidence>\\n\\nFix:\\n- <1-sentence fix>\\n\\nConfidence:\\n- <High/Medium/Low>\\n\n\n"
        f"If the finding is a VERIFIED_ATTACK (e.g. SQL Injection, Reflected XSS, etc.):\n"
        f"Use this exact format for the description field:\n"
        f"Result:\\n- <1-sentence result>\\n\\nImpact:\\n- <1-sentence impact>\\n\\nEvidence:\\n- <1-sentence evidence>\\n\\nConfidence:\\n- <High/Medium/Low>\\n\n\n"
        f"Format your response as a JSON object matching this schema:\n"
        f"{{\n"
        f"  \"description\": \"The formatted bullet-point text exactly matching the schema above.\",\n"
        f"  \"remediation\": \"A short mitigation step (1-sentence).\"\n"
        f"}}\n"
    )
