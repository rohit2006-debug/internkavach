"""
src/forensics/syndicate.py
Knowledge Base for Known Indian Internship/Job Scam Networks
────────────────────────────────────────────────────────────
Contains:
  • CERTIFICATE_MILLS — known mass unpaid virtual internship mills
  • PAYMENT_SCAM_PHRASES — keyword → risk score mapping
  • KNOWN_BAD_ACTORS — pre-seeded UPI/email entities for graph matching
  • check_certificate_mill(name) — returns match info or None
"""
from __future__ import annotations
from typing import Optional, Dict, Any

# ══════════════════════════════════════════════════════════════════════════════
# CERTIFICATE MILLS DATABASE
# Known mass-mailer unpaid virtual internship organisations
# Sources: student Reddit posts, LinkedIn complaints, consumer court filings
# ══════════════════════════════════════════════════════════════════════════════
CERTIFICATE_MILLS: Dict[str, Dict[str, Any]] = {
    "Prodigy InfoTech": {
        "risk_score": 75,
        "category": "CERTIFICATE_MILL",
        "description": (
            "Mass-mails identical offer letters to thousands of students. "
            "Offers unpaid 'virtual internships' in Data Science, ML, Web Dev. "
            "No CIN visible on letters. Token Rs.500 stipend rarely paid. "
            "Completion certificates issued after generic 4-week tasks with no mentorship."
        ),
        "reported_violations": ["Apprentices Act 1961 §19 (minimum stipend)", "UGC Internship Guidelines"],
        "typical_roles": ["Data Science Intern", "Machine Learning Intern", "Web Developer Intern"],
        "typical_duration": "1 month / 4 weeks",
        "typical_stipend": "None / Rs.500",
        "known_domains": ["prodigyinfotech.net", "prodigyinfotech.in"],
        "complaint_count": 5000,   # estimated based on public reports
        "is_certificate_mill": True,
        "severity": "HIGH",
    },
    "Oasis Infobyte": {
        "risk_score": 70,
        "category": "CERTIFICATE_MILL",
        "description": (
            "Offers unpaid virtual internships via mass email campaigns. "
            "No registered address or CIN in offer letters. "
            "Tasks are generic GitHub projects submitted via email. "
            "Issues completion certificates with no real company verification."
        ),
        "reported_violations": ["Apprentices Act 1961 §19"],
        "typical_roles": ["Web Developer", "Android Developer", "Data Science"],
        "typical_duration": "1 month",
        "typical_stipend": "None / performance-linked",
        "known_domains": ["oasisinfobyte.com", "oasisinfobyte.in"],
        "complaint_count": 3000,
        "is_certificate_mill": True,
        "severity": "HIGH",
    },
    "LetsGrowMore": {
        "risk_score": 65,
        "category": "CERTIFICATE_MILL",
        "description": (
            "Virtual internship program offering certificates after task submissions. "
            "Mass-distributed offer letters via email. No physical office visible. "
            "Widely reported on Quora/Reddit as a resume-padding mill."
        ),
        "reported_violations": ["Apprentices Act 1961 §19", "UGC Guidelines"],
        "typical_roles": ["ML Intern", "Python Developer", "Web Dev"],
        "typical_duration": "1 month",
        "typical_stipend": "None",
        "known_domains": ["letsgrowmore.in"],
        "complaint_count": 2000,
        "is_certificate_mill": True,
        "severity": "MEDIUM",
    },
    "YBI Foundation": {
        "risk_score": 65,
        "category": "CERTIFICATE_MILL",
        "description": (
            "Youth Business India Foundation offers virtual data science internships. "
            "No registered CIN in offer letters. Widely flagged as resume padding."
        ),
        "reported_violations": ["Apprentices Act 1961"],
        "typical_roles": ["Data Science Intern", "AI Intern"],
        "typical_duration": "1 month",
        "typical_stipend": "None",
        "known_domains": ["ybifoundation.org"],
        "complaint_count": 1500,
        "is_certificate_mill": True,
        "severity": "MEDIUM",
    },
    "CodSoft": {
        "risk_score": 60,
        "category": "CERTIFICATE_MILL",
        "description": (
            "Sends bulk internship offers via email. Tasks submitted to company email. "
            "Certificate issued. No real mentorship or stipend."
        ),
        "reported_violations": ["Apprentices Act 1961"],
        "typical_roles": ["Python Developer", "Java Developer", "Web Developer"],
        "typical_duration": "1 month",
        "typical_stipend": "None",
        "known_domains": ["codsoft.in"],
        "complaint_count": 1000,
        "is_certificate_mill": True,
        "severity": "MEDIUM",
    },
    "Bharat Intern": {
        "risk_score": 60,
        "category": "CERTIFICATE_MILL",
        "description": (
            "Offers virtual internships across domains. Bulk email campaigns. "
            "Certificate issued after task upload. No stipend offered."
        ),
        "reported_violations": ["Apprentices Act 1961"],
        "typical_roles": ["Data Science", "Video Editing", "Web Development"],
        "typical_duration": "1 month",
        "typical_stipend": "None",
        "known_domains": ["bharatintern.life"],
        "complaint_count": 800,
        "is_certificate_mill": True,
        "severity": "MEDIUM",
    },
    "Internpe": {
        "risk_score": 58,
        "category": "CERTIFICATE_MILL",
        "description": "Virtual internship issuer. Certificate-only program with no stipend.",
        "reported_violations": ["Apprentices Act 1961"],
        "typical_roles": ["Python", "ML", "Web Dev"],
        "typical_duration": "4 weeks",
        "typical_stipend": "None",
        "known_domains": ["internpe.in"],
        "complaint_count": 600,
        "is_certificate_mill": True,
        "severity": "MEDIUM",
    },
    "TechVision Pvt Ltd": {
        "risk_score": 90,
        "category": "PAYMENT_SCAM",
        "description": (
            "Demands registration fee / security deposit before joining. "
            "Fake corporate letterhead. Known mule account hubs detected in Jamtara."
        ),
        "reported_violations": ["BNS §318(4)", "IT Act §66D", "BNS §336(3)"],
        "typical_roles": ["HR Intern", "Marketing Associate"],
        "typical_stipend": "Promised Rs.15,000-25,000 (never paid)",
        "known_domains": [],
        "complaint_count": 500,
        "is_certificate_mill": False,
        "severity": "CRITICAL",
    },
}

# ── Alias lookup (lowercase → canonical) ─────────────────────────────────────
_MILL_ALIASES: Dict[str, str] = {
    "prodigy infotech": "Prodigy InfoTech",
    "prodigyinfotech": "Prodigy InfoTech",
    "oasis infobyte": "Oasis Infobyte",
    "oasisinfobyte": "Oasis Infobyte",
    "lets grow more": "LetsGrowMore",
    "letsgrowmore": "LetsGrowMore",
    "ybi foundation": "YBI Foundation",
    "ybifoundation": "YBI Foundation",
    "youth business india": "YBI Foundation",
    "codsoft": "CodSoft",
    "bharat intern": "Bharat Intern",
    "bharatintern": "Bharat Intern",
    "internpe": "Internpe",
    "techvision": "TechVision Pvt Ltd",
    "tech vision": "TechVision Pvt Ltd",
}


# ══════════════════════════════════════════════════════════════════════════════
# PAYMENT SCAM PHRASE SCORES
# ══════════════════════════════════════════════════════════════════════════════
PAYMENT_SCAM_PHRASES: Dict[str, int] = {
    "registration fee":  25,
    "security deposit":  25,
    "laptop deposit":    25,
    "id card fee":       20,
    "kit charges":       20,
    "uniform charges":   20,
    "joining fee":       22,
    "processing fee":    20,
    "training charge":   22,
    "advance payment":   20,
    "pay now":           18,
    "refundable deposit": 18,
    "telegram":          12,
    "whatsapp":          8,
    "transfer":          8,
    "google pay":        10,
    "phonepe":           10,
    "paytm":             8,
}


# ══════════════════════════════════════════════════════════════════════════════
# PRE-SEEDED BAD ACTOR UPI / DOMAINS
# ══════════════════════════════════════════════════════════════════════════════
KNOWN_BAD_ACTORS: set = {
    "fraudjobs@ybl",
    "hiringhub@ibl",
    "techvision.hr@gmail.com",
    "techvision@paytm",
    "jobsoffer2024@ybl",
    "indiajobs@axl",
    "naukri.fraud@ptyes",
}


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC LOOKUP
# ══════════════════════════════════════════════════════════════════════════════

def check_certificate_mill(name: str) -> Optional[Dict[str, Any]]:
    """
    Check if a company name matches the certificate mill database.

    Args:
        name: Company name extracted from document.

    Returns:
        Mill info dict if matched, or None.
    """
    if not name:
        return None
    name_lower = name.lower().strip()

    # Direct key match
    for canonical, info in CERTIFICATE_MILLS.items():
        if canonical.lower() in name_lower or name_lower in canonical.lower():
            return {"canonical_name": canonical, **info}

    # Alias match
    for alias, canonical in _MILL_ALIASES.items():
        if alias in name_lower:
            return {"canonical_name": canonical, **CERTIFICATE_MILLS[canonical]}

    return None


def get_all_mill_names() -> list[str]:
    """Return all canonical mill names for graph seeding."""
    return list(CERTIFICATE_MILLS.keys())


def get_mill_risk_score(name: str) -> int:
    """Return risk score 0-100 for a company name, 0 if not in database."""
    info = check_certificate_mill(name)
    return info.get("risk_score", 0) if info else 0
