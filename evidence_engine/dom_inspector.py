"""
evidence_engine/dom_inspector.py — Advanced DOM inspection and analysis.
Compares static HTML with fully rendered DOM from Playwright to detect hidden/suspicious components.
"""

from __future__ import annotations

import re
from bs4 import BeautifulSoup


def analyze_dom(original_html: str, rendered_html: str) -> dict:
    """
    Compare original HTTP static HTML with fully rendered browser DOM.
    Detects dynamic changes, hidden elements, obfuscated scripts, and metrics.
    """
    if not original_html:
        original_html = "<html></html>"
    if not rendered_html:
        rendered_html = "<html></html>"

    try:
        original_soup = BeautifulSoup(original_html, "lxml")
    except Exception:
        original_soup = BeautifulSoup(original_html, "html.parser")

    try:
        rendered_soup = BeautifulSoup(rendered_html, "lxml")
    except Exception:
        rendered_soup = BeautifulSoup(rendered_html, "html.parser")

    # 1. Elements classification
    hidden_elements = 0
    hidden_forms = 0
    hidden_iframes = 0
    hidden_scripts = 0
    suspicious_links = 0

    hidden_style_pat = re.compile(
        r"(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|left\s*:\s*-\s*\d{3,9}px|top\s*:\s*-\s*\d{3,9}px|margin-left\s*:\s*-\s*\d{3,9}px)",
        re.IGNORECASE
    )

    for el in rendered_soup.find_all(True):
        is_hidden = False
        if el.has_attr("hidden"):
            is_hidden = True
        elif el.has_attr("style"):
            style_val = el["style"]
            if hidden_style_pat.search(style_val):
                is_hidden = True

        if is_hidden:
            hidden_elements += 1
            if el.name == "form":
                hidden_forms += 1
            elif el.name == "iframe":
                hidden_iframes += 1
            elif el.name == "script":
                hidden_scripts += 1

            # Hidden links
            if el.name == "a" or el.find("a"):
                suspicious_links += 1

    # 2. Dynamic injections
    original_scripts_src = {s["src"] for s in original_soup.find_all("script", src=True)}
    rendered_scripts_src = {s["src"] for s in rendered_soup.find_all("script", src=True)}
    new_injected_scripts = rendered_scripts_src - original_scripts_src

    # 3. Suspicious script check
    suspicious_scripts_count = 0
    dangerous_api_pat = re.compile(
        r"(\beval\s*\(|\bdocument\.write\s*\(|\.innerHTML\b|\.outerHTML\b|\.insertAdjacentHTML\b)",
        re.IGNORECASE
    )
    for s in rendered_soup.find_all("script"):
        script_content = s.string or ""
        if script_content:
            is_suspicious = False
            if dangerous_api_pat.search(script_content):
                is_suspicious = True
            if "atob(" in script_content or re.search(r"base64[a-zA-Z0-9+/=,]{20,}", script_content, re.IGNORECASE):
                is_suspicious = True
            if "String.fromCharCode" in script_content or re.search(r"\\x[0-9a-fA-F]{2}", script_content) or "eval(function(p,a,c,k,e," in script_content:
                is_suspicious = True

            if is_suspicious:
                suspicious_scripts_count += 1

    # 4. DOM Size Comparison
    original_tag_count = len(original_soup.find_all(True))
    rendered_tag_count = len(rendered_soup.find_all(True))
    dom_size_increase = max(0, rendered_tag_count - original_tag_count)
    
    dynamic_dom_modifications = "Yes" if dom_size_increase > 0 or len(new_injected_scripts) > 0 else "No"

    # 5. InnerHTML modifications detected
    innerHTML_mods = "No"
    if re.search(r"\.innerHTML\b|\.outerHTML\b|\.insertAdjacentHTML\b", rendered_html, re.IGNORECASE):
        innerHTML_mods = "Yes"

    # 6. Suspicious Links (javascript: protocols, etc.)
    for link in rendered_soup.find_all("a", href=True):
        href = link["href"].strip().lower()
        if href.startswith("javascript:") or href.startswith("data:"):
            suspicious_links += 1

    # 7. Risk calculation (capped at 100)
    risk_contrib = 0
    risk_contrib += min(15, hidden_elements)
    risk_contrib += min(30, hidden_forms * 10)
    risk_contrib += min(45, hidden_iframes * 15)
    risk_contrib += min(45, suspicious_scripts_count * 15)
    risk_contrib += min(20, suspicious_links * 5)
    if dom_size_increase > 100:
        risk_contrib += 15
    
    risk_score_contribution = min(100, risk_contrib)
    confidence_score = 95 if rendered_html else 0

    return {
        "hidden_elements": hidden_elements,
        "hidden_forms": hidden_forms,
        "hidden_iframes": hidden_iframes,
        "dynamic_dom_modifications": dynamic_dom_modifications,
        "innerHTML_modifications": innerHTML_mods,
        "suspicious_script_count": suspicious_scripts_count,
        "suspicious_link_count": suspicious_links,
        "risk_score_contribution": risk_score_contribution,
        "confidence_score": confidence_score,
        "dom_size_original": original_tag_count,
        "dom_size_rendered": rendered_tag_count,
        "dom_size_increase": dom_size_increase
    }
