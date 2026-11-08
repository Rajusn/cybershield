# 🛡️ CyberShield | AI Cybersecurity Threat Analysis Platform

**CyberShield** is an enterprise-grade, AI-powered cybersecurity log triage assistant designed for Security Operations Center (SOC) analysts and researchers. It combines deterministic regex-extracted indicators and rule-based checks with advanced LLM reasoning (via LangChain, LangGraph, and Groq) to analyze security logs, categorize threats, and track incident lifecycles.

---

## 🚀 Key Features

- **⚡ Instant Log Parsing:** Paste raw security text logs directly or upload standard `.txt` and `.log` files for automated analysis.
- **🔍 Hybrid Threat Triage:** Combines transparent rule-based flags (e.g., brute-force attempts, unauthorized privilege changes, malware signatures) with advanced Groq-powered LLM evaluation.
- **📊 Incident Lifecycle Management:** Built-in SQLite database (`incidents.db`) to persistently save analyzed incidents and track remediation statuses (`OPEN`, `IN PROGRESS`, `RESOLVED`).
- **🎨 SOC-Inspired UI:** Modern glassmorphism dashboard featuring real-time telemetry indicators, severity badges, and structured metric breakdowns.

---

## 🛠️ Tech Stack

- **Frontend & UI:** Streamlit (Python)
- **Orchestration & LLM Framework:** LangChain, LangGraph, ChatGroq
- **AI Inference Engine:** Groq API (High-speed LLM execution)
- **Data Processing & Storage:** Pandas, SQLite3
- **Environment Management:** python-dotenv

---

## 📦 Project Structure

```text
cybersecurity-app/
│
├── cyberthreatapp.py      # Main Streamlit application script
├── requirements.txt       # Python dependencies
├── .env                   # Local environment variables (API keys - DO NOT COMMIT)
├── .gitignore             # Git ignore file for secrets and databases
└── README.md              # Project documentation