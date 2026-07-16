# SentinelAI SOC

## Project

SentinelAI SOC is an AI-powered Website Defacement Detection and Vulnerability Assessment Platform built for the System Seige Hackathon.

This project prioritizes:

1. Working MVP
2. Problem Statement Compliance
3. Security
4. Deployment
5. Professional UI
6. Explainable AI
7. AI Attack Story

Never sacrifice the required functionality for fancy features.

---

# Tech Stack

Frontend
- Streamlit

Backend
- Python

Authentication
- Firebase Authentication

Database
- Firebase Firestore

Charts
- Plotly

Deployment
- Streamlit Community Cloud

Environment
- .env

---

# UI Theme

Inspired by

- Microsoft Defender
- CrowdStrike Falcon
- Datadog
- Splunk

Theme

Dark

Accent

Neon Cyan

Cards

Glassmorphism

Professional SOC dashboard

No default Streamlit styling.

---

# Dashboard

Top

Security Score

Threat Level

Critical Alerts

Protected Assets

Today's Scans

Middle

Threat Timeline

Risk Distribution

Recent Scans

Bottom

AI Incident Intelligence

Audit Logs

Reports

---

# Required Features

Website Scanner

Website Defacement Detection

Snapshot Comparison

Visual Difference Detection

Vulnerability Assessment

Risk Scoring

Reports

Audit Logs

Role-based Access

Asset Management

---

# AI Feature 1

Explainable AI

Every AI output MUST contain

Finding

Confidence

Evidence

Reason

OWASP Mapping

Business Impact

Recommendation

Verification Checklist

No unexplained AI conclusions.

---

# AI Feature 2

Attack Story

Generate a hypothetical attack path derived from the scan findings.

Never claim exploitation occurred.

Always state

"This is a hypothetical attack scenario generated from the observed security findings."

The attack story should include

Entry Point

Attack Progression

Business Impact

Likelihood

Priority Fixes

---

# Security Principles

Never hardcode secrets.

Always validate inputs.

Use Firebase Security Rules.

Use ownership validation.

Handle errors gracefully.

No stack traces.

Escape HTML where appropriate.

Store secrets in .env.

---

# Folder Structure

app.py

pages/

components/

security/
  url_validator.py
  ssrf_guard.py
  input_sanitizer.py
  rate_limiter.py
  ownership.py

firebase/

evidence_engine/
  fetcher.py
  headers.py
  ssl_checker.py
  snapshot.py
  diff.py
  vulnerability.py
  risk_engine.py

ai/
  explainability.py
  attack_story.py
  report_generator.py

utils/

styles/

services/  (compatibility shims — do not add new code here)

---

# Coding Rules

Generate ONE FILE at a time.

Never generate multiple files together.

Never leave TODO placeholders.

Use modular code.

Prefer reusable functions.

Avoid unnecessary abstractions.

Optimize for readability.

---

# Design Philosophy

Think like a hackathon judge.

The application should look like a commercial cybersecurity product rather than a student project.

Every screen should answer

"What problem does this solve?"

Every feature should improve either

Security

Usability

or

Judge Experience.


## Architecture

The system has three layers in enforced order:

User → Streamlit UI → Firebase Auth → Security Validation Layer → Evidence Engine → AI Incident Intelligence → Firestore

No layer may be skipped. No layer may bypass this order.

---

## Security Validation Layer

Every user-supplied URL must pass ALL of the following before scanning begins:

- URL structure validation (scheme, host, length)
- Scheme validation (HTTP/HTTPS only — no file://, ftp://, etc.)
- SSRF prevention (DNS resolution + private IP blocklist)
- Input sanitisation (unicode normalisation, control character removal)
- Rate limiting (max scans per user per rolling time window)
- Ownership verification (user may only scan their own assets)

Modules: security/url_validator.py, security/ssrf_guard.py, security/input_sanitizer.py, security/rate_limiter.py, security/ownership.py

---

## Evidence Engine Principles

The Evidence Engine is deterministic.

It collects and verifies observable security facts.

It must NEVER use AI for any detection decision.

Its responsibilities:

- Fetch website with enforced timeout, redirect cap, response size cap
- Capture text-only snapshot (SHA-256 fingerprint — no raw HTML stored)
- Compare snapshots to detect defacement
- Analyse HTTP security headers
- Inspect TLS/SSL certificates
- Aggregate all evidence into a structured EvidenceReport

The EvidenceReport is the only object passed to the AI layer.

The EvidenceReport must NEVER contain raw HTML, JavaScript, CSS, or user-controlled web content.

Modules: evidence_engine/fetcher.py, evidence_engine/headers.py, evidence_engine/ssl_checker.py, evidence_engine/snapshot.py, evidence_engine/diff.py, evidence_engine/vulnerability.py, evidence_engine/risk_engine.py

---

## AI Incident Intelligence Principles

The AI layer is interpretive, not detective.

The AI explains deterministic findings. It does NOT discover vulnerabilities.

The AI receives ONLY structured EvidenceReport objects from the Evidence Engine.

The AI must NEVER receive:

- Raw HTML
- JavaScript
- CSS
- Markdown from the scanned webpage
- Any user-controlled web content

This is the primary defence against prompt injection from scanned websites.

Its responsibilities:

- Explainable AI findings (with evidence references from EvidenceReport)
- Hypothetical Attack Story
- Remediation Recommendations
- Executive Summary

Every AI conclusion must reference a specific field from the EvidenceReport.

Modules: ai/explainability.py, ai/attack_story.py, ai/report_generator.py

---

## Prompt Injection Defence

The pipeline is:

Website → Evidence Engine → Structured EvidenceReport → AI

Never:

Website → AI

Prompt injection attempts embedded in scanned webpages are neutralised because raw HTML never reaches the AI layer.

---

## AI Security Principles

- AI never analyses raw HTML.
- AI only receives structured EvidenceReport from the Evidence Engine.
- AI provides explanation, prioritization, remediation, and hypothetical attack stories.
- Every AI conclusion must reference evidence produced by the Evidence Engine.
- AI never detects vulnerabilities — it only explains them.

---

## Scanner Principles

Detection is deterministic.

AI is interpretive.

Detection and explanation are separate responsibilities.

AI never detects vulnerabilities.

AI explains deterministic findings.

AI never receives raw HTML.

Every AI conclusion must reference evidence produced by the Evidence Engine.

Every user request must pass through the Security Validation Layer before scanning begins.

## Architecture Status

The project architecture is frozen.

No module responsibilities should change.

Future prompts may only:

- implement missing functionality
- improve code quality
- fix bugs
- improve UI

Do not restructure folders.

Do not rename modules.

Do not introduce new frameworks.

Preserve existing interfaces unless explicitly instructed.