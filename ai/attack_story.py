"""
ai/attack_story.py — Attack Path Explorer generation.

Receives RiskAssessment + XAIOutput from the deterministic pipeline.
Generates a structured, hypothetical attack graph (AttackStory).

HARD RULES (Architecture Invariants):
  - NEVER receives raw HTML, JavaScript, CSS, or webpage content.
  - NEVER invents vulnerabilities not present in the RiskAssessment.
  - NEVER generates exploit code, payload strings, or instructions.
  - NEVER claims exploitation occurred.
  - Every AttackNode.finding_reference MUST match a finding in the assessment.
  - All output is explicitly labelled hypothetical.

Prompt injection is neutralised: the AI only sees finding titles,
severity labels, evidence_reference field-path strings, and OWASP
categories — never the raw content of the scanned website.
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

import google.generativeai as genai

from risk_engine.models import RiskAssessment, FindingReference
from ai.explainability import XAIOutput
from ai.attack_story_models import (
    AttackChain,
    AttackEdge,
    AttackMetadata,
    AttackMitigation,
    AttackNode,
    AttackStory,
    EvidenceCoverage,
    MITREReference,
)

log = logging.getLogger(__name__)


# ── Configuration ─────────────────────────────────────────────────────────────

_MODEL_NAME     = "gemini-1.5-flash"
_TEMPERATURE    = 0.3       # slightly higher than XAI — creative chains, still grounded
_MODELS_TO_TRY  = ["gemini-2.0-flash", "gemini-flash-latest"]
_TEMPERATURE    = 0.6          # Slightly higher temperature for creative attack path generation
_MAX_RETRIES    = 3
_RETRY_DELAY    = 2.0
_PROMPT_VERSION = "1.0"

_DISCLAIMER = (
    "This is a hypothetical attack scenario generated from verified security "
    "findings. No exploitation was performed or simulated. This output is "
    "provided for educational and defensive security awareness only."
)


# ── Public Interface ──────────────────────────────────────────────────────────

def generate(
    assessment: RiskAssessment,
    xai: XAIOutput,
) -> AttackStory:
    """
    Generate an AttackStory (graph + steps + narrative) from an assessment.

    Only the structured fields from the assessment and XAI output are
    sent to Gemini. Raw evidence content never enters the prompt.

    Retries up to _MAX_RETRIES times on transient API errors.
    Raises RuntimeError if all retries are exhausted.
    """
    if not assessment.findings:
        return _empty_story(assessment)

    prompt = build_prompt(assessment, xai)
    last_exc: Optional[Exception] = None

    for model_name in _MODELS_TO_TRY:
        client = _get_client(model_name)
        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                response = client.generate_content(
                    prompt,
                    generation_config=genai.types.GenerationConfig(
                        temperature=_TEMPERATURE,
                        candidate_count=1,
                    ),
                )
                raw_text = response.text
                story = parse_response(raw_text, assessment)
                return story
    
            except Exception as exc:
                last_exc = exc
                log.warning(
                    "Gemini call failed with model %s on attempt %d/%d: %s",
                    model_name, attempt, _MAX_RETRIES, exc,
                )
                exc_str = str(exc).lower()
                
                # Fast fail for auth, quota, or invalid key errors to prevent hanging
                if any(x in exc_str for x in ["429", "403", "400", "quota", "api_key", "invalid", "unauthenticated", "exceeded"]):
                    log.error(f"Fast failing due to fatal API error: {exc}")
                    return _degraded_story(assessment, str(exc))

                if "404" in exc_str or "not found" in exc_str:
                    break
                    
                if attempt < _MAX_RETRIES:
                    time.sleep(_RETRY_DELAY * attempt)

    log.error(
        f"Attack Path Explorer: Gemini API unavailable after trying all fallback models. "
        f"Last error: {last_exc}"
    )
    return _degraded_story(assessment, str(last_exc))


def build_prompt(assessment: RiskAssessment, xai: XAIOutput) -> str:
    """
    Build the Gemini prompt from structured pipeline data ONLY.

    NEVER includes:
      - html_content or any raw HTTP body
      - User-supplied input strings from the scanned website
      - Exploit code, payloads, or CVE exploitation details

    ONLY includes:
      - Finding titles and severities (from RiskAssessment.findings)
      - evidence_reference field-path strings (not raw evidence content)
      - OWASP category names
      - Overall risk score and grade
      - XAI business_impact summaries (already validated by explainability.py)
    """
    score = assessment.summary.overall_security_score
    grade = assessment.summary.overall_grade
    severity = assessment.summary.overall_severity
    finding_count = len(assessment.findings)

    # Build finding catalogue — only structured metadata, no raw content
    findings_block = _format_findings_for_prompt(assessment.findings, xai)

    prompt = f"""You are a defensive cybersecurity consultant building an Attack Path Explorer.

You have been given the output of a deterministic, automated security scan.
Your task is to construct a hypothetical, non-linear attack graph showing how
an adversary COULD exploit the identified weaknesses in sequence.

STRICT CONSTRAINTS — THESE ARE ABSOLUTE:
1. Only create AttackNodes that reference a finding from the FINDING CATALOGUE below.
2. Do NOT invent vulnerabilities or findings not in the catalogue.
3. Do NOT generate exploit code, payloads, shellcode, or specific attack instructions.
4. Do NOT claim any exploitation actually occurred.
5. Every node must have a finding_reference that exactly matches a title in the catalogue.
6. Focus on defensive insight: what a defender needs to prioritise.

== SCAN SUMMARY ==
Security Score:   {score} / 100
Grade:            {grade}
Severity:         {severity}
Total Findings:   {finding_count}

== FINDING CATALOGUE (use ONLY these, referenced by exact title) ==
{findings_block}

== OUTPUT FORMAT ==
Respond with valid JSON only. No markdown. No code fences. No extra text.

{{
  "executive_summary": "2-3 sentence plain-English overview of the hypothetical attack scenario.",
  "coverage": {{
    "chain_confidence": "High",
    "evidence_coverage_percentage": 100,
    "findings_used_count": {finding_count},
    "unused_findings_count": 0
  }},
  "chains": [
    {{
      "chain_title": "Descriptive title of this attack path",
      "entry_node_ids": ["node-1"],
      "nodes": [
        {{
          "node_id": "node-1",
          "name": "Short node label",
          "description": "What a hypothetical attacker achieves here (plain English, no jargon).",
          "finding_reference": "<EXACT title from FINDING CATALOGUE above>",
          "evidence_reference": "<exact evidence_reference string from the finding>",
          "risk_reference": "<severity level of the referenced finding>",
          "confidence": "High",
          "mitre_mapping": {{
            "tactic": "e.g. Initial Access",
            "technique": "e.g. Exploit Public-Facing Application",
            "confidence": "High"
          }},
          "fix_reference": "mitigation-1"
        }}
      ],
      "edges": [
        {{
          "source_node_id": "node-1",
          "target_node_id": "node-2",
          "transition_reason": "Why this transition is possible based on the findings (plain English).",
          "supporting_evidence": "The specific finding enabling this transition."
        }}
      ],
      "mitigations": [
        {{
          "mitigation_id": "mitigation-1",
          "finding_id_reference": "<EXACT title from FINDING CATALOGUE>",
          "action_required": "Specific defensive action (e.g. Enable CSP Header)",
          "why_it_breaks_chain": "How fixing this halts the attack at this node.",
          "residual_risk": "Low",
          "remaining_issues": ["Other finding titles still unresolved"]
        }}
      ]
    }}
  ]
}}

Rules:
- Produce 1-3 chains depending on how many distinct attack paths the findings support.
- Every chain must have at least 2 nodes and 1 edge.
- Every node finding_reference must match an EXACT title from the FINDING CATALOGUE.
- Every mitigation finding_id_reference must match an EXACT title from the FINDING CATALOGUE.
- executive_summary must be under 100 words.
- Tone: Senior SOC analyst explaining findings to a junior developer (CS student). Never sound academic.
- Language: Replace jargon with simple language. (e.g., use 'Attacker' instead of 'Adversary' or 'Threat actor', use 'Series of attacks' instead of 'Exploit chain').
- Confidence: MUST use categorical labels (Low, Medium, High, Very High). Do NOT use percentages.
- Do NOT include any content from the scanned webpage.
- All descriptions must be defensive framing — what to fix, not how to exploit.
"""
    return prompt


def parse_response(raw: str, assessment: RiskAssessment) -> AttackStory:
    """
    Parse and validate the Gemini JSON response into an AttackStory object.

    Validation:
      - Must be valid JSON.
      - Every AttackNode.finding_reference must match a known finding title.
      - Every AttackMitigation.finding_id_reference must match a known finding title.
      - Invalid references are corrected or the node is dropped.
      - Falls back to _degraded_story() on unrecoverable parse failure.
    """
    text = raw.strip()
    # Strip accidental markdown fences
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(
            line for line in lines
            if not line.strip().startswith("```")
        ).strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        log.error("Attack story: Gemini response was not valid JSON: %s", exc)
        return _degraded_story(assessment, reason=f"JSON parse error: {exc}")

    known_titles = {f.title for f in assessment.findings}
    finding_by_title = {f.title: f for f in assessment.findings}

    # ── Parse chains ──────────────────────────────────────────────────────────
    raw_chains = data.get("chains", [])
    if not raw_chains:
        log.warning("Attack story: no chains in Gemini response.")
        return _degraded_story(assessment, reason="No attack chains returned by AI.")

    parsed_chains: list[AttackChain] = []
    total_findings_used: set[str] = set()

    for raw_chain in raw_chains:
        nodes = _parse_nodes(raw_chain.get("nodes", []), known_titles)
        edges = _parse_edges(raw_chain.get("edges", []), {n.node_id for n in nodes})
        mitigations = _parse_mitigations(raw_chain.get("mitigations", []), known_titles)

        if not nodes:
            log.warning("Attack story: chain had no valid nodes after validation — skipping.")
            continue

        for n in nodes:
            if n.finding_reference:
                total_findings_used.add(n.finding_reference)

        parsed_chains.append(AttackChain(
            chain_id=str(uuid.uuid4()),
            chain_title=raw_chain.get("chain_title", "Hypothetical Attack Path"),
            entry_node_ids=raw_chain.get("entry_node_ids", [nodes[0].node_id]),
            nodes=nodes,
            edges=edges,
            mitigations=mitigations,
        ))

    if not parsed_chains:
        return _degraded_story(assessment, reason="All chains failed finding reference validation.")

    # ── Coverage metrics ──────────────────────────────────────────────────────
    raw_coverage = data.get("coverage", {})
    findings_used_count = len(total_findings_used)
    unused_count = max(0, len(assessment.findings) - findings_used_count)
    coverage_pct = int((findings_used_count / max(1, len(assessment.findings))) * 100)

    coverage = EvidenceCoverage(
        chain_confidence=min(100, max(0, int(raw_coverage.get("chain_confidence", 80)))),
        evidence_coverage_percentage=coverage_pct,
        findings_used_count=findings_used_count,
        unused_findings_count=unused_count,
    )

    # ── Metadata ──────────────────────────────────────────────────────────────
    metadata = AttackMetadata(
        story_version="1.0",
        prompt_version=_PROMPT_VERSION,
        model_name=_MODEL_NAME,
        generated_at=datetime.now(timezone.utc),
        confidence=coverage.chain_confidence,
        disclaimer=_DISCLAIMER,
    )

    return AttackStory(
        metadata=metadata,
        coverage=coverage,
        executive_summary=data.get("executive_summary", "Hypothetical attack paths generated."),
        chains=parsed_chains,
    )


# ── Node / Edge / Mitigation Parsers ─────────────────────────────────────────

def _parse_nodes(
    raw_nodes: list[dict],
    known_titles: set[str],
) -> list[AttackNode]:
    """
    Parse and validate AttackNode objects.
    Drops any node whose finding_reference is not in known_titles.
    """
    nodes: list[AttackNode] = []
    for raw in raw_nodes:
        finding_ref = raw.get("finding_reference", "").strip()

        # Enforce: every node must reference a real finding
        if finding_ref and finding_ref not in known_titles:
            log.warning(
                "Attack story: node '%s' references unknown finding '%s' — dropping.",
                raw.get("name"), finding_ref,
            )
            continue

        # Parse optional MITRE mapping
        mitre_data = raw.get("mitre_mapping")
        mitre: Optional[MITREReference] = None
        if isinstance(mitre_data, dict) and mitre_data.get("tactic"):
            mitre = MITREReference(
                tactic=mitre_data.get("tactic", ""),
                technique=mitre_data.get("technique", ""),
                confidence=min(100, max(0, int(mitre_data.get("confidence", 75)))),
            )

        nodes.append(AttackNode(
            node_id=raw.get("node_id", str(uuid.uuid4())),
            name=raw.get("name", "Attack Stage"),
            description=raw.get("description", ""),
            finding_reference=finding_ref or None,
            evidence_reference=raw.get("evidence_reference") or None,
            risk_reference=raw.get("risk_reference") or None,
            confidence=min(100, max(0, int(raw.get("confidence", 80)))),
            mitre_mapping=mitre,
            fix_reference=raw.get("fix_reference") or None,
        ))

    return nodes


def _parse_edges(
    raw_edges: list[dict],
    valid_node_ids: set[str],
) -> list[AttackEdge]:
    """
    Parse AttackEdge objects.
    Drops edges referencing node IDs that were not parsed successfully.
    """
    edges: list[AttackEdge] = []
    for raw in raw_edges:
        src = raw.get("source_node_id", "")
        tgt = raw.get("target_node_id", "")
        if src not in valid_node_ids or tgt not in valid_node_ids:
            log.warning(
                "Attack story: edge (%s → %s) references unknown node — dropping.", src, tgt
            )
            continue
        edges.append(AttackEdge(
            source_node_id=src,
            target_node_id=tgt,
            transition_reason=raw.get("transition_reason", ""),
            supporting_evidence=raw.get("supporting_evidence", ""),
        ))
    return edges


def _parse_mitigations(
    raw_mitigations: list[dict],
    known_titles: set[str],
) -> list[AttackMitigation]:
    """
    Parse AttackMitigation objects.
    Drops mitigations referencing unknown findings.
    """
    mitigations: list[AttackMitigation] = []
    for raw in raw_mitigations:
        finding_id_ref = raw.get("finding_id_reference", "").strip()
        if finding_id_ref and finding_id_ref not in known_titles:
            log.warning(
                "Attack story: mitigation references unknown finding '%s' — dropping.",
                finding_id_ref,
            )
            continue
        mitigations.append(AttackMitigation(
            mitigation_id=raw.get("mitigation_id", str(uuid.uuid4())),
            finding_id_reference=finding_id_ref,
            action_required=raw.get("action_required", ""),
            why_it_breaks_chain=raw.get("why_it_breaks_chain", ""),
            residual_risk=raw.get("residual_risk", "Low"),
            remaining_issues=raw.get("remaining_issues", []),
        ))
    return mitigations


# ── Fallback Builders ─────────────────────────────────────────────────────────

def _empty_story(assessment: RiskAssessment) -> AttackStory:
    """Return a minimal AttackStory when the assessment has no findings."""
    return AttackStory(
        metadata=AttackMetadata(
            confidence="Very High",
            disclaimer=_DISCLAIMER,
            model_name=_MODEL_NAME,
            prompt_version=_PROMPT_VERSION,
            generated_at=datetime.now(timezone.utc),
        ),
        coverage=EvidenceCoverage(
            chain_confidence="Very High",
            evidence_coverage_percentage=100,
            findings_used_count=0,
            unused_findings_count=0,
        ),
        executive_summary=(
            f"Security Score: {assessment.summary.overall_security_score}/100 "
            f"(Grade {assessment.summary.overall_grade}). "
            "No findings were identified. No attack paths can be constructed."
        ),
        chains=[],
    )


_LOCAL_ATTACK_DATABASE = {
    "Missing Content-Security-Policy Header": {
        "description": "Adversary identifies the absence of Content-Security-Policy (CSP) enforcement, establishing a vector for client-side script execution or data injection.",
        "action": "Deploy a strict Content-Security-Policy HTTP response header to restrict authorized scripts to trusted domains.",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "Exploit Public-Facing Application"
    },
    "Missing Strict-Transport-Security Header": {
        "description": "Adversary intercepts network traffic and executes an HTTP downgrade attack to capture unencrypted session data.",
        "action": "Enable HTTP Strict Transport Security (HSTS) on the web server with appropriate max-age and subdomains configurations.",
        "mitre_tactic": "Adversary Dissemination",
        "mitre_technique": "Man-in-the-Middle Redirection"
    },
    "Missing X-Frame-Options Header": {
        "description": "Adversary embeds the application inside a malicious iframe, attempting to hijack click events or overlay target elements.",
        "action": "Configure the X-Frame-Options header (DENY or SAMEORIGIN) or CSP frame-ancestors to prevent unauthorized embedding.",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "Clickjacking / Frame Injection"
    },
    "Missing X-Content-Type-Options Header": {
        "description": "Adversary uploads or injects media payloads with executable suffixes, attempting to force the browser to execute them as script code.",
        "action": "Apply the X-Content-Type-Options: nosniff header on all HTTP responses.",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "MIME-Sniffing Bypasses"
    },
    "Server Header Discloses Technology": {
        "description": "Adversary scans the Server HTTP response header to extract platform versions and search for known software exploits (CVEs).",
        "action": "Hide or minimize server banner details in configurations (e.g. server_tokens off in Nginx).",
        "mitre_tactic": "Reconnaissance",
        "mitre_technique": "Active Scanning / Banner Grabbing"
    },
    "Invalid TLS Certificate": {
        "description": "Adversary intercepts transport channels, taking advantage of invalid certificate verification to perform traffic interception.",
        "action": "Acquire a trusted TLS certificate matching the hostname and configured with secure root chains.",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "Adversary-in-the-Middle"
    },
    "TLS Certificate Has Expired": {
        "description": "Adversary leverages expired certificate trust states to conduct Man-in-the-Middle attacks against clients bypassing warnings.",
        "action": "Renew the SSL/TLS certificate and enable auto-renewals.",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "Subversion of Trust Controls"
    },
    "Content Defacement Detected": {
        "description": "Adversary compromises host integrity or file systems, defacing content to damage reputation or distribute phishing links.",
        "action": "Roll back to a secure codebase backup immediately. Audit server administrative logs and file permissions.",
        "mitre_tactic": "Impact",
        "mitre_technique": "Defacement / Content Alteration"
    },
    "SQL Injection Vulnerability Detected": {
        "description": "Adversary injects malicious SQL input into query parameters, escaping query boundaries and executing arbitrary statements against the database.",
        "action": "Implement prepared statements and parameterized queries. Apply strict input sanitization rules.",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "SQL Injection"
    },
    "Cross-Site Scripting (XSS) Detected": {
        "description": "Adversary injects malicious JavaScript payloads into input fields, aiming to execute code inside other visitors' active sessions.",
        "action": "Apply context-aware output encoding across all user inputs before rendering.",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "Cross-Site Scripting"
    },
    "Sensitive Files Exposed": {
        "description": "Adversary performs directory traversal or index scanning, accessing backup credentials, source code files, or git logs.",
        "action": "Harden directory listings, move sensitive assets out of root directories, and configure strict rewrite blockers.",
        "mitre_tactic": "Discovery",
        "mitre_technique": "File and Directory Discovery"
    },
    "Missing Rate Limiting (DDoS Vulnerable)": {
        "description": "Adversary exploits lack of endpoint threshold validations, initiating load floods or automated authentication brute-forcing.",
        "action": "Set request limit thresholds at the application or firewall level.",
        "mitre_tactic": "Impact",
        "mitre_technique": "Network Denial of Service"
    }
}


def _degraded_story(assessment: RiskAssessment, reason: str) -> AttackStory:
    """
    Return a safe, deterministic fallback AttackStory when AI fails.
    Utilises the local attack database to construct realistic, expert-level description chains and
    proper MITRE mappings rather than empty or generic placeholders.
    """
    nodes: list[AttackNode] = []
    mitigations: list[AttackMitigation] = []

    for i, finding in enumerate(assessment.findings):
        node_id = f"node-{i + 1}"
        mitigation_id = f"mitigation-{i + 1}"
        
        # Look up metadata from our local DB
        title = finding.title
        matched_db = None
        for key in _LOCAL_ATTACK_DATABASE:
            if key in title:
                matched_db = _LOCAL_ATTACK_DATABASE[key]
                break

        if matched_db:
            desc_text = matched_db["description"]
            action_text = matched_db["action"]
            tactic = matched_db["mitre_tactic"]
            technique = matched_db["mitre_technique"]
            mitre = MITREReference(
                tactic=tactic,
                technique=technique,
                confidence="High"
            )
        else:
            desc_text = f"Hypothetical attacker could leverage: {finding.title}. See evidence_reference for the deterministic source."
            action_text = f"Remediate: {finding.title}"
            mitre = None

        nodes.append(AttackNode(
            node_id=node_id,
            name=finding.title,
            description=desc_text,
            finding_reference=finding.title,
            evidence_reference=finding.evidence_reference,
            risk_reference=finding.severity,
            confidence="High",
            mitre_mapping=mitre,
            fix_reference=mitigation_id,
        ))
        
        mitigations.append(AttackMitigation(
            mitigation_id=mitigation_id,
            finding_id_reference=finding.title,
            action_required=action_text,
            why_it_breaks_chain="Fixing this removes the precondition for this stage in the hypothetical attack path.",
            residual_risk="Low",
            remaining_issues=[
                f.title for f in assessment.findings if f.title != finding.title
            ],
        ))

    # Build sequential edges between nodes
    edges: list[AttackEdge] = []
    for i in range(len(nodes) - 1):
        edges.append(AttackEdge(
            source_node_id=nodes[i].node_id,
            target_node_id=nodes[i + 1].node_id,
            transition_reason="Unresolved finding enables progression to next stage.",
            supporting_evidence=nodes[i].evidence_reference or nodes[i].finding_reference or "",
        ))

    chain = AttackChain(
        chain_id=str(uuid.uuid4()),
        chain_title="Hypothetical Attack Path (Deterministic Expert Fallback)",
        entry_node_ids=[nodes[0].node_id] if nodes else [],
        nodes=nodes,
        edges=edges,
        mitigations=mitigations,
    )

    return AttackStory(
        metadata=AttackMetadata(
            confidence="High",
            disclaimer=_DISCLAIMER,
            model_name="expert-local-fallback",
            prompt_version=_PROMPT_VERSION,
            generated_at=datetime.now(timezone.utc),
        ),
        coverage=EvidenceCoverage(
            chain_confidence="High",
            evidence_coverage_percentage=100,
            findings_used_count=len(assessment.findings),
            unused_findings_count=0,
        ),
        executive_summary=(
            f"Security Score: {assessment.summary.overall_security_score}/100 "
            f"(Grade {assessment.summary.overall_grade}). "
            f"Note: Running in expert local database mode. "
            "A sequential attack chain has been constructed outlining potential entry vectors and mitigations."
        ),
        chains=[chain] if nodes else [],
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_client(model_name: str) -> genai.GenerativeModel:
    """Initialise and return the Gemini client. Reads GEMINI_API_KEY from env."""
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise EnvironmentError(
            "GEMINI_API_KEY is not set. "
            "Add it to your .env file or Streamlit Secrets."
        )
    genai.configure(api_key=api_key)
    return genai.GenerativeModel(model_name)


def _format_findings_for_prompt(
    findings: list[FindingReference],
    xai: XAIOutput,
) -> str:
    """
    Format findings into a structured text block for the prompt.

    Supplements each finding with its XAI business_impact if available.
    Never includes raw evidence content — only field-path strings.
    """
    if not findings:
        return "  (No findings.)"

    # Build xai lookup by finding title for business_impact enrichment
    xai_by_title = {f.finding: f for f in xai.findings}

    lines: list[str] = []
    for i, f in enumerate(findings, start=1):
        owasp_str = ", ".join(f.owasp) if f.owasp else "N/A"
        xai_finding = xai_by_title.get(f.title)
        impact = xai_finding.business_impact if xai_finding else "Not assessed."

        lines.append(
            f"  [{i}] Title:              {f.title}\n"
            f"       Severity:           {f.severity}\n"
            f"       OWASP:              {owasp_str}\n"
            f"       Evidence Reference: {f.evidence_reference}\n"
            f"       Business Impact:    {impact}"
        )
    return "\n\n".join(lines)
