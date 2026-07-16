# 🛡️ SentinelAI SOC

> **AI-Powered Website Defacement Detection & Vulnerability Assessment Platform**  
> Built for the **System Siege Hackathon**

---

## 🌟 Executive Summary

**SentinelAI SOC** is a next-generation Security Operations Center platform designed to automate the discovery, assessment, and explanation of web vulnerabilities. 

Unlike traditional vulnerability scanners that dump raw technical jargon, SentinelAI utilizes a multi-stage pipeline—culminating in **Google Gemini AI**—to translate complex technical findings into readable Explanations, clear Risk Scores, and hypothetical Attack Stories. This empowers both technical engineers and business stakeholders to understand their actual risk posture.

---

## 🚀 Core Capabilities

| Capability | Description |
|---|---|
| **Active Penetration Testing** | Safely executes targeted payloads (SQLi, XSS, Fuzzing, Rate Limiting) against assets to detect exploitable endpoints. |
| **Defacement Detection** | Captures cryptographic snapshots of a target URL and compares them against baselines to detect visual or structural tampering. |
| **Passive Reconnaissance** | Analyses HTTP security headers, TLS/SSL configuration, and common misconfigurations (mapped to OWASP Top 10). |
| **Mathematical Risk Engine** | Aggregates all deterministic findings into a rigid 0–100 security score using a strict, policy-driven penalty matrix. |
| **Explainable AI (XAI)** | Gemini AI explains exactly *why* a vulnerability matters, providing Business Impact and Remediation steps without hallucinating scores. |
| **Hypothetical Attack Paths** | Gemini generates a realistic narrative of how an attacker could chain the discovered vulnerabilities to breach the system. |
| **Role-Based Access Control** | Secure Firebase-backed authentication with strict separation between `user` and `admin` roles. |
| **Audit & Compliance** | A tamper-proof timeline logging every scan, login, and administrative action. |

---

## 🏗️ System Architecture

Our platform follows a strict deterministic-to-probabilistic pipeline to prevent AI hallucinations:

1. **Evidence Engine (Deterministic):** Connects to the target website, captures HTTP headers, SSL certificates, HTML snapshots, and runs active payloads (SQLi, XSS). Outputs a strictly typed `ScanEvidence` object.
2. **Risk Engine (Deterministic):** Compares the `ScanEvidence` against our `risk_policy.json` to calculate the mathematical 0-100 Risk Score. Outputs `FindingReferences`.
3. **AI Engine (Probabilistic):** Sends the deterministic findings to **Gemini 2.0 Flash** via strict JSON schemas to generate human-readable explanations and hypothetical attack paths.
4. **Incident Builder:** Compiles all data into a final Executive Incident Report stored in Firestore.

---

## 💻 Tech Stack

- **Frontend:** Streamlit (Python) with custom CSS/Glassmorphism for a premium SOC feel.
- **Backend Core:** Python 3.10+
- **Database & Auth:** Firebase Firestore (NoSQL) & Firebase Authentication
- **Artificial Intelligence:** Google Gemini API (`gemini-2.0-flash`)
- **Visualizations:** Plotly Express

---

## 🏁 Step-by-Step Guide for Judges (How to Run)

Follow these steps exactly to run the platform locally on your machine for evaluation.

### Step 1: Clone the Repository
```bash
git clone https://github.com/StarDeep18/System-Siege.git
cd System-Siege
```

### Step 2: Set Up Python Environment
Ensure you have Python 3.9+ installed. It is highly recommended to use a virtual environment.
```bash
# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables
You must set up your `.env` file to connect to Firebase and the Gemini API.

1. Locate the file named `.env` in the root folder (or rename `.env.example` to `.env`).
2. Ensure it contains the following structure:

```ini
# Google Gemini
GEMINI_API_KEY=your_gemini_api_key_here

# Firebase Configuration
FIREBASE_API_KEY=your_firebase_web_api_key
FIREBASE_PROJECT_ID=your_firebase_project_id
FIREBASE_SERVICE_ACCOUNT_JSON=serviceAccountKey.json

# App Configuration
APP_SECRET_KEY=your_random_secret_key_here
```
> *Note: If you have been provided a `serviceAccountKey.json` file by the team, ensure it is placed in the root directory.*

### Step 5: Start the Platform
```bash
streamlit run app.py
```
The SentinelAI SOC will automatically open in your default web browser at `http://localhost:8501`.

---

## 🧪 Evaluation Guide (What to Test)

To get the full experience of the platform, we recommend testing the following flows:

### 1. Test Role-Based Access Control (Admin vs User)
- **Log in as an Admin:** Use the admin email (`admin@sentinel.ai`) and the securely generated password provided by your setup script.
- Navigate to the **Admin Panel** in the sidebar.
- Notice how you can assign roles (`user`, `analyst`, `admin`) to other registered users, or completely delete accounts using the 🗑️ button.
- Notice the global **Audit Logs** at the bottom of the Admin Panel tracking all system activity.

### 2. Run a Vulnerability Scan
- Navigate to the **Scanner** tab.
- Enter a target URL (e.g., `http://example.com` or a known vulnerable test site like `http://testphp.vulnweb.com/`).
- Click **Start Scan**.
- Watch the live loading indicators as the engine progresses through:
  - Header Analysis
  - SSL/TLS Inspection
  - Snapshot Capture & Defacement Detection
  - **Active Penetration Testing** (DDoS, SQLi, XSS, Fuzzing)
  - Mathematical Risk Scoring
  - Google Gemini AI Generation

### 3. Review the Executive Incident Report
- Once the scan finishes, a comprehensive report will appear on the screen.
- Expand the **Explainable AI (XAI)** sections for each vulnerability to see how Gemini explains the technical issue in plain English.
- Read the **Hypothetical Attack Path** generated by Gemini, showing a realistic narrative of how a threat actor could chain the found vulnerabilities to breach the target.

### 4. View Analytics
- Navigate to the **Dashboard** to see live visualizations of all scans performed, security posture trends, and a breakdown of vulnerabilities by severity.

---

## 🔒 Security & AI Disclaimers

- **Active Scanning:** The platform actively sends payloads (like SQLi strings and rapid requests). Ensure you only scan assets you have permission to test.
- **AI Hallucinations:** To prevent hallucinations, the Gemini AI engine is strictly isolated from the scanning process. It *only* receives deterministic findings and is mathematically barred from inventing vulnerabilities. 
- **Attack Stories:** All AI-generated attack paths are **hypothetical scenarios** derived from observed findings to aid in threat modeling. They do not represent actual active exploitation.

---
*Built with ❤️ for the System Siege Hackathon.*
