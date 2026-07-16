"""
components/ai_panel.py — Explainable AI output and Attack Story display.
"""

from __future__ import annotations

import streamlit as st


# ── Public Interface ──────────────────────────────────────────────────────────

def render_xai(summary: str, findings: list[dict]) -> None:
    """
    Render the Explainable AI panel.
    """
    st.markdown(
        f"""
        <div style="background: rgba(0, 212, 255, 0.05); border: 1px dashed var(--accent); border-radius: var(--radius-md); padding: 1.25rem; margin-bottom: 1.5rem;">
            <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.75rem;">
                <span style="font-size: 1.5rem;">💡</span>
                <h4 style="margin: 0; color: var(--accent); font-family: var(--font-heading);">AI INCIDENT INTELLIGENCE</h4>
            </div>
            <p style="font-size: 0.9rem; line-height: 1.5; color: var(--text-primary); margin: 0;">
                <b>Executive Diagnosis:</b> {summary}
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    st.markdown("<h5 style='margin-bottom: 1rem;'>Deterministic Findings Explained</h5>", unsafe_allow_html=True)
    
    for i, finding in enumerate(findings):
        _render_finding_card(finding, i)


def render_attack_story(entry_point: str, progression: list[str], impact: str, likelihood: str, fixes: list[str]) -> None:
    """
    Render the hypothetical Attack Story panel.
    """
    disclaimer = (
        "This is a hypothetical attack scenario generated from the observed "
        "security findings. It does not represent actual exploitation and is "
        "provided for educational and risk-awareness purposes only."
    )
    
    st.markdown(
        f"""
        <div class="glass-panel" style="border-left: 4px solid var(--risk-critical) !important; background: rgba(255, 76, 76, 0.02) !important;">
            <div style="font-size: 0.75rem; color: var(--risk-critical); font-weight: 600; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 0.5rem; display: flex; align-items: center; gap: 0.4rem;">
                <span>⚠️</span> ATTACK SCENARIO DISCLAIMER
            </div>
            <p style="font-size: 0.8rem; color: var(--text-secondary); line-height: 1.4; margin: 0; font-style: italic;">
                {disclaimer}
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown(
            f"""
            <div class="glass-panel">
                <div style="font-size: 0.8rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.25rem;">Threat Entry Point</div>
                <div style="font-size: 1.1rem; font-weight: 600; color: var(--risk-high);">{entry_point}</div>
            </div>
            """, 
            unsafe_allow_html=True
        )
        
    with col2:
        st.markdown(
            f"""
            <div class="glass-panel">
                <div style="font-size: 0.8rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.25rem;">Estimated Likelihood</div>
                <div style="font-size: 1.1rem; font-weight: 600; color: var(--risk-critical);">{likelihood}</div>
            </div>
            """, 
            unsafe_allow_html=True
        )

    # Progression Timeline
    st.markdown("<h5 style='margin-top: 1rem; margin-bottom: 1rem;'>Attack Propagation Path</h5>", unsafe_allow_html=True)
    _render_attack_progression(progression)
    
    # Impact & Priority Fixes
    st.markdown("<hr style='border-color: var(--border); margin: 1.5rem 0;'>", unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    
    with c1:
        st.markdown(f"**Business Impact Assessment**  \n{impact}")
    with c2:
        st.markdown("**Priority Remediation Checklist**")
        for fix in fixes:
            st.markdown(f"- `[ ]` {fix}")


# ── Private Helpers ───────────────────────────────────────────────────────────

def _render_finding_card(finding: dict, index: int) -> None:
    """
    Render a single explainable finding inside an expander.
    """
    title = finding.get("title", "Finding")
    severity = finding.get("severity", "medium").upper()
    badge_type = "badge-medium"
    if severity == "CRITICAL":
        badge_type = "badge-critical"
    elif severity == "HIGH":
        badge_type = "badge-high"
    elif severity == "LOW":
        badge_type = "badge-low"
        
    header_html = f"""
    <div style="display: flex; justify-content: space-between; align-items: center; width: 100%;">
        <span style="font-weight: 600; color: var(--text-primary);">{title}</span>
        <span class="cyber-badge {badge_type}" style="font-size: 0.65rem; padding: 0.1rem 0.4rem;">{severity}</span>
    </div>
    """
    
    with st.expander(f"Explain Finding: {title} ({severity})", expanded=(index == 0)):
        st.markdown(f"**Evidence Checked:** `{finding.get('evidence', 'None')}`")
        st.markdown(f"**OWASP Mapping:** `{finding.get('owasp', 'A05:2021')}`")
        st.markdown(f"**AI Reason Analysis:** {finding.get('recommendation', '')}")
        
        st.markdown("---")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**Business Impact**  \n{finding.get('title')} could lead to disruption of service or unauthorized data collection.")
        with col2:
            st.markdown("**Verification Checklist**")
            st.markdown("- Verify header responses in developers tool Console.")
            st.markdown("- Conduct manual site security evaluation.")


def _render_attack_progression(steps: list[str]) -> None:
    """Render progression as steps."""
    for idx, step in enumerate(steps):
        st.markdown(
            f"""
            <div style="display: flex; align-items: flex-start; gap: 0.75rem; margin-bottom: 0.75rem;">
                <div style="display: flex; align-items: center; justify-content: center; width: 22px; height: 22px; border-radius: 50%; background: var(--accent); color: var(--bg-primary); font-weight: bold; font-size: 0.75rem; flex-shrink: 0; margin-top: 0.1rem;">
                    {idx + 1}
                </div>
                <div style="font-size: 0.9rem; color: var(--text-primary); line-height: 1.4;">
                    {step}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
