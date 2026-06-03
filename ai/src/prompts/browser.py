import re

BROWSER_SYSTEM_INSTRUCTION = (
    "You are an autonomous security agent driving a web browser for penetration testing. "
    "Your goal is to explore the application, find vulnerabilities, and achieve the stated objective. "
    "You must decide the next best action based on the page state and your previous actions."
)

def clean_html(html: str) -> str:
    """Remove script, style, and svg tags from HTML to save context window."""
    # Remove <script>...</script>
    html = re.sub(r'<script\b[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
    # Remove <style>...</style>
    html = re.sub(r'<style\b[^>]*>.*?</style>', '', html, flags=re.DOTALL | re.IGNORECASE)
    # Remove <svg>...</svg>
    html = re.sub(r'<svg\b[^>]*>.*?</svg>', '', html, flags=re.DOTALL | re.IGNORECASE)
    # Remove comments
    html = re.sub(r'<!--.*?-->', '', html, flags=re.DOTALL)
    # Collapse whitespace
    html = re.sub(r'\s+', ' ', html).strip()
    return html

def get_decide_action_prompt(request) -> str:
    """Build a detailed prompt for DecideBrowserAction."""
    
    # Header and Goal
    prompt = (
        f"Goal: {request.current_goal}\n"
        f"Current URL: {request.current_url or request.url}\n"
        f"Page Title: {request.page_title}\n\n"
    )
    
    # Feedback from last action
    if request.last_action:
        status = "SUCCESS" if request.last_action_success else "FAILED"
        prompt += f"Last Action: {request.last_action} (Status: {status})\n"
        if not request.last_action_success and request.last_action_error:
            prompt += f"Error from last action: {request.last_action_error}\n"
            prompt += "CRITICAL: The last action failed. Do not repeat the same failing action. Try a different approach or selector.\n"
        prompt += "\n"

    # Structured Elements
    if request.links:
        prompt += "--- DISCOVERED LINKS ---\n"
        for i, link in enumerate(request.links[:20]): # Limit to top 20
            prompt += f"[{i}] Text: '{link.text}' | Selector: '{link.selector}' | Href: '{link.href}'\n"
        prompt += "\n"

    if request.buttons:
        prompt += "--- DISCOVERED BUTTONS ---\n"
        for i, button in enumerate(request.buttons[:20]):
            prompt += f"[{i}] Text: '{button.text}' | Selector: '{button.selector}'\n"
        prompt += "\n"

    if request.forms:
        prompt += "--- DISCOVERED FORMS ---\n"
        for i, form in enumerate(request.forms[:5]):
            prompt += f"Form [{i}] Selector: '{form.selector}' | Method: '{form.method}' | Action: '{form.action}'\n"
            for input_el in form.inputs:
                prompt += f"  - Input Type: '{input_el.type}' | Name: '{input_el.name}' | Selector: '{input_el.selector}'\n"
        prompt += "\n"

    # Cleaned HTML
    cleaned_source = clean_html(request.page_source)
    # Truncate to a reasonable size if still too big, but prioritize structured data
    prompt += f"--- CLEANED PAGE SOURCE (TRUNCATED) ---\n{cleaned_source[:8000]}\n\n"
    
    prompt += (
        "Decide the next action to take. Available actions:\n"
        "- 'click': Click an element (requires 'selector').\n"
        "- 'fill': Fill a form field (requires 'selector' and 'value').\n"
        "- 'type': Type text into an element (requires 'selector' and 'value').\n"
        "- 'navigate': Go to a new URL (requires 'value').\n"
        "- 'wait': Wait for the page to load or for an element to appear (optional 'value' in ms).\n"
        "- 'finish': Goal achieved or impossible.\n\n"
        "Return your decision in JSON format with 'action', 'selector', 'value', and 'explanation' fields."
    )
    
    return prompt
