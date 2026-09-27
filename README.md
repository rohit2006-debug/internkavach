# InternKavach — Cyber Forensics Platform

🛡 **AI-Powered detection of fake internship/job offer letter scams**

## Features

| Module | Capability |
|--------|-----------|
| 🛡 Pre-flight Gatekeeper | AI-powered classification rejecting non-recruitment documents (resumes, IDs, bills) |
| 🔍 ELA Engine | Pixel-level image tampering detection via Error Level Analysis |
| 📄 Metadata Inspector | PDF/EXIF authoring software detection + scam phrase scanner |
| 🏦 Banking Triangulator | IFSC mule-account detection + UPI risk profiling |
| 🕸 Syndicate Graph | Cross-document entity linking with NetworkX |
| 🤖 AI Evaluator | Gemini 2.5 Flash (with fallback to 2.0 Flash) multimodal vision & text analysis |
| ⚖️ Legal Dossier | BNS §318/§336 + IT Act §66D PDF report generation for cybercrime.gov.in |

## Quick Start

```bash
# 1. Create and activate virtual environment
python -m venv venv
venv\Scripts\activate      # Windows
# source venv/bin/activate  # Linux/Mac

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Configure Gemini API
copy .env.example .env
# Edit .env and add GEMINI_API_KEY=your_key

# 4. Generate test samples
python tests/create_samples.py

# 5. Run tests
python -m pytest tests/test_forensics.py -v

# 6. Launch the app
streamlit run app.py
```

## Architecture

```
InternKavach/
├── app.py                      # Streamlit dashboard
├── requirements.txt
├── .env.example
├── src/
│   ├── forensics/
│   │   ├── ela.py              # Error Level Analysis engine
│   │   ├── metadata.py         # PDF & EXIF inspector
│   │   ├── banking.py          # IFSC/UPI triangulation
│   │   └── network.py          # Syndicate graph engine
│   ├── legal/
│   │   └── bns_dossier.py      # FIR PDF generator
│   └── ai/
│       └── agent_evaluator.py  # Gemini + mock evaluator
└── tests/
    ├── create_samples.py       # Test document generator
    ├── test_forensics.py       # Pytest suite
    └── samples/                # Generated test files
```

## Legal Provisions Covered

- **BNS Section 318(4)** — Cheating & Fraud (up to 7 years)
- **BNS Section 336(3)** — Document Forgery (up to 7 years)
- **IT Act Section 66D** — Cheating by Impersonation (up to 3 years + ₹1L fine)

## Report a Cybercrime

- 🌐 [cybercrime.gov.in](https://cybercrime.gov.in)
- 📞 National Cyber Crime Helpline: **1930**

---
*100% free & open-source. Zero cost. Built for student protection under Indian law.*
