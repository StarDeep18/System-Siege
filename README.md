# SentinelAI SOC

> AI-powered Website Defacement Detection & Vulnerability Assessment Platform  
> Built for the **System Siege Hackathon**

---

## What It Does

SentinelAI SOC monitors websites for defacement and security vulnerabilities. Every finding is explained by AI — no black-box outputs. A hypothetical attack story is generated from each scan to help stakeholders understand real-world risk.

| Capability | Description |
|---|---|
| **Defacement Detection** | Snapshots a target URL and compares it against a saved baseline to detect visual or structural changes |
| **Vulnerability Assessment** | Checks HTTP headers, TLS config, and common misconfigurations with OWASP mapping |
| **Risk Scoring** | Aggregates findings into a 0–100 risk score |
| **Explainable AI** | Every AI output includes Finding, Confidence, Evidence, Reason, OWASP mapping, Business Impact, and Recommendation |
| **Attack Story** | Generates a hypothetical attack path from findings — clearly labelled as hypothetical |
| **Asset Management** | Add and track monitored URLs per user |
| **Reports** | Generate and export scan reports |
| **Audit Logs** | Full action log for compliance and accountability |
| **Role-Based Access** | Admin and Analyst roles enforced via Firebase |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Streamlit |
| Backend | Python |
| Auth | Firebase Authentication |
| Database | Firebase Firestore |
| AI | Google Gemini (via `google-generativeai`) |
| Charts | Plotly |
| Deployment | Streamlit Community Cloud |

---

## Project Structure

```
sentinelai-soc/
├── app.py                  # Entry point, auth gate, routing
├── pages/
│   ├── dashboard.py        # SOC overview, KPIs, charts
│   ├── scanner.py          # Run scans, view AI results
│   ├── assets.py           # Add / manage monitored URLs
│   ├── reports.py          # Report viewer and export
│   └── audit.py            # Audit log (admin only)
├── components/
│   ├── auth.py             # Login / register UI
│   ├── navbar.py           # Sidebar navigation
│   ├── cards.py            # Metric and glassmorphism cards
│   ├── charts.py           # Plotly chart wrappers
│   └── ai_panel.py         # Explainable AI + Attack Story display
├── services/
│   ├── scanner.py          # Defacement detection, snapshot comparison
│   ├── vuln.py             # Vulnerability checks, risk scoring
│   └── ai.py              # Gemini calls → XAI output + Attack Story
├── firebase/
│   ├── config.py           # Firebase SDK init
│   ├── auth.py             # Auth helpers
│   └── db.py               # Firestore CRUD
├── utils/
│   ├── security.py         # Input validation, HTML escape, ownership
│   └── helpers.py          # Formatting, constants
└── styles/
    └── theme.css           # Dark theme, neon cyan, glassmorphism
```

---

## Quickstart

### 1. Clone the repo

```bash
git clone https://github.com/your-org/sentinelai-soc.git
cd sentinelai-soc
```

### 2. Create a virtual environment

```bash
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

```bash
cp .env.example .env
```

Fill in your values in `.env` — see [.env.example](.env.example) for all required keys.

### 5. Run locally

```bash
streamlit run app.py
```

---

## Environment Variables

See [.env.example](.env.example) for the full list. Required keys:

| Variable | Source |
|---|---|
| `FIREBASE_API_KEY` | Firebase Console → Project Settings |
| `FIREBASE_PROJECT_ID` | Firebase Console → Project Settings |
| `FIREBASE_SERVICE_ACCOUNT_JSON` | Firebase Console → Service Accounts |
| `GEMINI_API_KEY` | [Google AI Studio](https://aistudio.google.com/app/apikey) |
| `APP_SECRET_KEY` | Generate with `python -c "import secrets; print(secrets.token_hex(32))"` |

> **Never commit `.env` or any file containing real credentials.**

---

## Deployment (Streamlit Community Cloud)

1. Push this repo to GitHub (ensure `.env` is in `.gitignore`).
2. Go to [share.streamlit.io](https://share.streamlit.io) and connect the repo.
3. Set all environment variables under **App Settings → Secrets** using the same keys from `.env.example`.
4. Set **Main file path** to `app.py`.
5. Deploy.

---

## AI Disclaimer

All AI-generated attack stories are **hypothetical scenarios** derived from observed security findings.  
They do not represent actual exploitation and are clearly labelled:

> *"This is a hypothetical attack scenario generated from the observed security findings."*

---

## Security Principles

- No hardcoded secrets — all credentials in `.env` or Streamlit Secrets
- Input validation on all user-supplied data
- Firebase Security Rules enforce data ownership
- No raw stack traces exposed to users
- HTML escaping applied where appropriate

---

## License

MIT — built for the System Siege Hackathon.
