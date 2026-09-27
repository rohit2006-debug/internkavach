"""
app.py — InternKavach National Cyber-Forensics Recruitment Verification Portal
World-class cyber-defense platform with cinematic visual architecture, responsive unclipped navbar,
flawless dual-theme engine (Light/Dark), strict 2-stage state separation, and deep multimodal forensic auditing.
Compliant with Bharatiya Nyaya Sanhita (BNS) 2023, IT Act 2000, and Apprentices Act 1961.
"""
from __future__ import annotations

# ── Environment bootstrap ────────────────────────────────────────────────────
from pathlib import Path as _Path
try:
    from dotenv import load_dotenv as _load_dotenv
    _load_dotenv(_Path(__file__).parent / ".env", override=True)
except ImportError:
    pass

import os
import sys
from pathlib import Path

import streamlit as st

# ── Workspace path setup ─────────────────────────────────────────────────────
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from src.pipeline import audit_pipeline

# ── Streamlit page configuration ─────────────────────────────────────────────
st.set_page_config(
    page_title="INTERNKAVACH | National Cyber-Forensics Recruitment Portal",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Session state initialization ─────────────────────────────────────────────
if "theme" not in st.session_state:
    st.session_state["theme"] = "dark"
if "investigator_name" not in st.session_state:
    st.session_state["investigator_name"] = "Rohit De"
if "investigator_email" not in st.session_state:
    st.session_state["investigator_email"] = "rohit.de@college.edu"
if "uploader_key" not in st.session_state:
    st.session_state["uploader_key"] = 0
if "audit_complete" not in st.session_state:
    st.session_state["audit_complete"] = False
if "results" not in st.session_state:
    st.session_state["results"] = None
if "audit_result" not in st.session_state:
    st.session_state["audit_result"] = None
if "audit_filename" not in st.session_state:
    st.session_state["audit_filename"] = ""
if "audit_filebytes" not in st.session_state:
    st.session_state["audit_filebytes"] = None

is_dark = st.session_state.get("theme", "dark") == "dark"

# ── Dynamic Dual-Theme Architecture (Flawless Light & Dark) ───────────────────
if is_dark:
    theme_tokens = """
    :root {
        --bg-main: #060911;
        --card-bg: rgba(13, 20, 36, 0.85);
        --card-border: rgba(0, 240, 255, 0.18);
        --text-primary: #F8FAFC;
        --text-secondary: #94A3B8;
        --accent-glow: rgba(0, 240, 255, 0.15);
        --input-bg: #090E1A;
        --input-border: rgba(0, 240, 255, 0.25);
        --subcard-bg: rgba(8, 12, 22, 0.75);
        --subcard-border: rgba(255, 255, 255, 0.08);
        --advisory-bg: rgba(245, 158, 11, 0.08);
        --advisory-border: #F59E0B;
        --advisory-text: #FDE68A;
        --brand-blue: #00F0FF;
        --brand-blue-hover: #38BDF8;
        --tag-bg: rgba(0, 240, 255, 0.12);
        --box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
    }

    /* Hero Banner: Dark Mode */
    .cinematic-hero {
        background: linear-gradient(180deg, rgba(6, 9, 17, 0.85) 0%, rgba(6, 9, 17, 0.95) 100%),
                    url('https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&w=1600&q=80') !important;
        background-size: cover !important;
        background-position: center !important;
        border: 1px solid rgba(0, 240, 255, 0.2) !important;
        border-radius: 16px !important;
        padding: 2.5rem 2rem !important;
        margin-bottom: 1.5rem !important;
        text-align: center !important;
        box-shadow: 0 12px 40px rgba(0, 0, 0, 0.5) !important;
    }
    .hero-title {
        color: #F8FAFC !important;
    }
    .hero-sub {
        color: #94A3B8 !important;
    }
    .hero-tag {
        background: rgba(255, 255, 255, 0.12) !important;
        color: #93C5FD !important;
        border: 1px solid rgba(147, 197, 253, 0.35) !important;
    }

    /* Verification Card: Dark Mode */
    .verification-card,
    .gov-card {
        background: rgba(13, 20, 36, 0.85) !important;
        border: 1px solid rgba(0, 240, 255, 0.18) !important;
        border-radius: 16px !important;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5) !important;
    }
    .stTextInput input {
        background: #090E1A !important;
        background-color: #090E1A !important;
        border: 1px solid rgba(0, 240, 255, 0.25) !important;
        color: #F8FAFC !important;
        border-radius: 8px !important;
    }

    /* Dropzone area: Dark Mode */
    [data-testid="stFileUploaderDropzone"] {
        background: rgba(15, 23, 42, 0.6) !important;
        background-color: rgba(15, 23, 42, 0.6) !important;
        border: 1px dashed rgba(0, 240, 255, 0.3) !important;
        border-radius: 12px !important;
    }
    /* The Upload Button inside the dropzone */
    [data-testid="stFileUploaderDropzone"] button {
        background: #1E293B !important;
        background-color: #1E293B !important;
        color: #F8FAFC !important;
        border: 1px solid rgba(0, 240, 255, 0.4) !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.3) !important;
        transition: all 0.2s ease !important;
    }
    [data-testid="stFileUploaderDropzone"] button:hover {
        background: #334155 !important;
        background-color: #334155 !important;
        border-color: #00F0FF !important;
        color: #00F0FF !important;
    }
    /* Upload Icon & Helper Text */
    [data-testid="stFileUploaderDropzone"] svg {
        fill: #00F0FF !important;
        stroke: #00F0FF !important;
    }
    [data-testid="stFileUploaderDropzone"] small,
    [data-testid="stFileUploaderDropzone"] span {
        color: #94A3B8 !important;
    }

    /* Popover Trigger Button: Dark Mode */
    [data-testid="stPopover"] > button,
    [data-testid="stPopover"] button {
        background-color: rgba(30, 41, 59, 0.8) !important;
        background: rgba(30, 41, 59, 0.8) !important;
        color: #F8FAFC !important;
        border: 1px solid rgba(255, 255, 255, 0.15) !important;
        border-radius: 9999px !important;
        font-size: 0.8rem !important;
        font-weight: 600 !important;
        padding: 6px 16px !important;
        box-shadow: none !important;
        height: 38px !important;
        min-height: 38px !important;
        display: inline-flex !important;
        align-items: center !important;
        justify-content: center !important;
        transition: all 0.2s ease !important;
    }
    [data-testid="stPopover"] > button:hover,
    [data-testid="stPopover"] button:hover {
        background-color: rgba(51, 65, 85, 0.9) !important;
        background: rgba(51, 65, 85, 0.9) !important;
        border-color: #00F0FF !important;
        color: #00F0FF !important;
    }

    /* Popover Content Dialog (Dropdown Card): Dark Mode */
    [data-testid="stPopoverBody"] {
        border-radius: 12px !important;
        padding: 1rem !important;
    }
    div[data-testid="stPopoverBody"] {
        background-color: #0F172A !important;
        background: #0F172A !important;
        color: #F8FAFC !important;
        border: 1px solid rgba(0, 240, 255, 0.2) !important;
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5) !important;
    }
    div[data-testid="stPopoverBody"] p,
    div[data-testid="stPopoverBody"] span,
    div[data-testid="stPopoverBody"] div,
    div[data-testid="stPopoverBody"] b,
    div[data-testid="stPopoverBody"] strong {
        color: #E2E8F0 !important;
    }

    /* Theme Toggle Button: Dark Mode */
    button[key="theme_toggle"],
    .theme-btn {
        background-color: rgba(30, 41, 59, 0.8) !important;
        background: rgba(30, 41, 59, 0.8) !important;
        border: 1px solid rgba(255, 255, 255, 0.15) !important;
        border-radius: 9999px !important;
        color: #F8FAFC !important;
        font-size: 1rem !important;
        padding: 6px 16px !important;
        height: 38px !important;
        min-height: 38px !important;
        cursor: pointer !important;
        box-shadow: none !important;
        outline: none !important;
        display: inline-flex !important;
        align-items: center !important;
        justify-content: center !important;
        transition: all 0.2s ease !important;
    }
    button[key="theme_toggle"]:hover,
    .theme-btn:hover {
        background-color: rgba(51, 65, 85, 0.9) !important;
        background: rgba(51, 65, 85, 0.9) !important;
        border-color: #00F0FF !important;
        color: #00F0FF !important;
    }
    """
else:
    theme_tokens = """
    :root {
        --bg-main: #F1F5F9;
        --card-bg: rgba(255, 255, 255, 0.95);
        --card-border: rgba(30, 41, 59, 0.12);
        --text-primary: #0F172A;
        --text-secondary: #475569;
        --accent-glow: rgba(37, 99, 235, 0.1);
        --input-bg: #F8FAFC;
        --input-border: #CBD5E1;
        --subcard-bg: rgba(248, 250, 252, 0.9);
        --subcard-border: #E2E8F0;
        --advisory-bg: #FFFBEB;
        --advisory-border: #F59E0B;
        --advisory-text: #92400E;
        --brand-blue: #1D4ED8;
        --brand-blue-hover: #1E40AF;
        --tag-bg: rgba(37, 99, 235, 0.08);
        --box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);
    }

    /* Hero Banner: Light Mode (Harmonized) */
    .cinematic-hero {
        background: linear-gradient(180deg, rgba(241, 245, 249, 0.92) 0%, rgba(226, 232, 240, 0.96) 100%),
                    url('https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&w=1600&q=80') !important;
        background-size: cover !important;
        background-position: center !important;
        border: 1px solid #CBD5E1 !important;
        border-radius: 16px !important;
        padding: 2.5rem 2rem !important;
        margin-bottom: 1.5rem !important;
        text-align: center !important;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.08) !important;
    }
    .hero-title {
        color: #0F172A !important;
    }
    .hero-sub {
        color: #334155 !important;
    }
    .hero-tag {
        background: rgba(37, 99, 235, 0.1) !important;
        color: #2563EB !important;
        border: 1px solid rgba(37, 99, 235, 0.3) !important;
    }

    /* Verification Card: Light Mode */
    .verification-card,
    .gov-card {
        background: #FFFFFF !important;
        border: 1px solid #CBD5E1 !important;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05) !important;
        border-radius: 16px !important;
    }
    .stTextInput input {
        background: #F8FAFC !important;
        background-color: #F8FAFC !important;
        border: 1px solid #CBD5E1 !important;
        color: #0F172A !important;
        border-radius: 8px !important;
    }

    /* Dropzone area: Light Mode */
    [data-testid="stFileUploaderDropzone"] {
        background: #F8FAFC !important;
        background-color: #F8FAFC !important;
        border: 2px dashed #94A3B8 !important;
        border-radius: 12px !important;
    }
    /* The Upload Button inside the dropzone */
    [data-testid="stFileUploaderDropzone"] button {
        background: #0F172A !important;
        background-color: #0F172A !important;
        color: #FFFFFF !important;
        border: none !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1) !important;
        transition: all 0.2s ease !important;
    }
    [data-testid="stFileUploaderDropzone"] button:hover {
        background: #1E293B !important;
        background-color: #1E293B !important;
        color: #FFFFFF !important;
    }
    /* Upload Icon & Helper Text */
    [data-testid="stFileUploaderDropzone"] svg {
        fill: #1D4ED8 !important;
        stroke: #1D4ED8 !important;
    }
    [data-testid="stFileUploaderDropzone"] small,
    [data-testid="stFileUploaderDropzone"] span {
        color: #475569 !important;
    }

    /* Popover Trigger Button: Light Mode */
    [data-testid="stPopover"] > button,
    [data-testid="stPopover"] button {
        background-color: #FFFFFF !important;
        background: #FFFFFF !important;
        color: #0F172A !important;
        border: 1px solid #CBD5E1 !important;
        border-radius: 9999px !important;
        font-size: 0.8rem !important;
        font-weight: 600 !important;
        padding: 6px 16px !important;
        box-shadow: none !important;
        height: 38px !important;
        min-height: 38px !important;
        display: inline-flex !important;
        align-items: center !important;
        justify-content: center !important;
        transition: all 0.2s ease !important;
    }
    [data-testid="stPopover"] > button:hover,
    [data-testid="stPopover"] button:hover {
        background-color: #F1F5F9 !important;
        background: #F1F5F9 !important;
        border-color: #2563EB !important;
        color: #2563EB !important;
    }

    /* Popover Content Dialog (Dropdown Card): Light Mode */
    [data-testid="stPopoverBody"] {
        border-radius: 12px !important;
        padding: 1rem !important;
    }
    div[data-testid="stPopoverBody"] {
        background-color: #FFFFFF !important;
        background: #FFFFFF !important;
        color: #0F172A !important;
        border: 1px solid #CBD5E1 !important;
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.08) !important;
    }
    div[data-testid="stPopoverBody"] p,
    div[data-testid="stPopoverBody"] span,
    div[data-testid="stPopoverBody"] div,
    div[data-testid="stPopoverBody"] b,
    div[data-testid="stPopoverBody"] strong {
        color: #334155 !important;
    }

    /* Theme Toggle Button: Light Mode */
    button[key="theme_toggle"],
    .theme-btn {
        background-color: #FFFFFF !important;
        background: #FFFFFF !important;
        border: 1px solid #CBD5E1 !important;
        border-radius: 9999px !important;
        color: #0F172A !important;
        font-size: 1rem !important;
        padding: 6px 16px !important;
        height: 38px !important;
        min-height: 38px !important;
        cursor: pointer !important;
        box-shadow: none !important;
        outline: none !important;
        display: inline-flex !important;
        align-items: center !important;
        justify-content: center !important;
        transition: all 0.2s ease !important;
    }
    button[key="theme_toggle"]:hover,
    .theme-btn:hover {
        background-color: #F1F5F9 !important;
        background: #F1F5F9 !important;
        border-color: #2563EB !important;
        color: #2563EB !important;
    }
    """

st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

{theme_tokens}

/* Reset Streamlit chrome headers */
header,
header[data-testid="stHeader"],
[data-testid="stToolbar"],
.stAppHeader,
div[data-testid="stDecoration"] {{
    background: transparent !important;
    background-color: transparent !important;
    display: none !important;
}}

/* Suppress any default white background or outline on header buttons */
header div[data-testid="stBaseButton-secondary"],
header div.stButton,
header div.stButton > button,
div[data-testid="stToolbar"] button,
.stAppHeader button {{
    background-color: transparent !important;
    background: transparent !important;
    border: none !important;
    box-shadow: none !important;
    outline: none !important;
}}

/* Base canvas */
html, body, .stApp {{
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
    background-color: var(--bg-main) !important;
    color: var(--text-primary) !important;
    min-height: 100vh;
    overflow-x: hidden !important;
}}

/* Streamlit Container Reset */
.block-container {{
    padding: 0.6rem 1rem 3.5rem 1rem !important;
    max-width: 1140px !important;
    margin: 0 auto !important;
}}

/* Hide Sidebar */
[data-testid="stSidebar"], section[data-testid="stSidebar"], [data-testid="collapsedControl"] {{
    display: none !important;
}}

/* Eliminate Ghost White Box Glitch on button/popover wrappers */
div[data-testid="stPopover"],
div.stButton,
div[data-testid="stColumn"] > div > div.stButton,
div[data-testid="stPopover"] > div {{
    background: transparent !important;
    background-color: transparent !important;
    border: none !important;
    box-shadow: none !important;
}}

/* Frosted Cyber Cards */
.gov-card {{
    background: var(--card-bg) !important;
    backdrop-filter: blur(16px) !important;
    -webkit-backdrop-filter: blur(16px) !important;
    border: 1px solid var(--card-border) !important;
    border-radius: 16px !important;
    padding: 1.6rem !important;
    box-shadow: var(--box-shadow) !important;
    margin-bottom: 1.25rem !important;
}}

.gov-subcard {{
    background: var(--subcard-bg) !important;
    border: 1px solid var(--subcard-border) !important;
    border-radius: 10px !important;
    padding: 1.1rem !important;
    margin-bottom: 0.85rem !important;
}}

/* Official Advisory Banner */
.advisory-banner {{
    background: var(--advisory-bg) !important;
    border: 1px solid var(--advisory-border) !important;
    border-left: 5px solid var(--advisory-border) !important;
    border-radius: 12px !important;
    padding: 1rem 1.35rem !important;
    margin-bottom: 1.25rem !important;
}}

/* Red Pulse Animation for Toll-Free Helpline */
@keyframes redPulse {{
    0% {{ transform: scale(0.95); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7); }}
    70% {{ transform: scale(1); box-shadow: 0 0 0 6px rgba(239, 68, 68, 0); }}
    100% {{ transform: scale(0.95); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }}
}}
.pulse-dot {{
    display: inline-block;
    width: 8px;
    height: 8px;
    background-color: #EF4444;
    border-radius: 50%;
    animation: redPulse 2s infinite;
}}

/* Pills & Badges */
.gov-pill {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.74rem;
    font-weight: 700;
    padding: 5px 12px;
    border-radius: 9999px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    white-space: nowrap;
}}

.pill-red {{
    background: rgba(239, 68, 68, 0.15);
    color: #EF4444;
    border: 1px solid rgba(239, 68, 68, 0.35);
}}

.pill-blue {{
    background: var(--tag-bg);
    color: var(--brand-blue);
    border: 1px solid var(--card-border);
}}

.pill-green {{
    background: rgba(16, 185, 129, 0.15);
    color: #10B981;
    border: 1px solid rgba(16, 185, 129, 0.35);
}}

.pill-amber {{
    background: rgba(245, 158, 11, 0.15);
    color: #F59E0B;
    border: 1px solid rgba(245, 158, 11, 0.35);
}}

/* Form Inputs */
.stTextInput input {{
    background-color: var(--input-bg) !important;
    color: var(--text-primary) !important;
    border: 1px solid var(--input-border) !important;
    border-radius: 8px !important;
    font-size: 0.92rem !important;
    padding: 10px 14px !important;
    transition: all 0.2s ease !important;
}}
.stTextInput input:focus {{
    border-color: #3B82F6 !important;
    box-shadow: 0 0 0 3px var(--accent-glow) !important;
}}

/* Royal Cobalt Audit Button */
.primary-audit-btn div[data-testid="stButton"] > button,
div[data-testid="stButton"] > button[kind="primary"],
.stButton > button {{
    background: linear-gradient(90deg, #1D4ED8 0%, #2563EB 50%, #3B82F6 100%) !important;
    color: #FFFFFF !important;
    border: 1px solid rgba(59, 130, 246, 0.4) !important;
    border-radius: 8px !important;
    font-weight: 700 !important;
    font-size: 0.95rem !important;
    letter-spacing: 0.04em !important;
    padding: 12px 20px !important;
    box-shadow: 0 4px 20px rgba(37, 99, 235, 0.35) !important;
    transition: all 0.2s ease !important;
}}
.stButton > button:hover {{
    background: linear-gradient(90deg, #1E40AF 0%, #1D4ED8 50%, #2563EB 100%) !important;
    box-shadow: 0 6px 25px rgba(37, 99, 235, 0.5) !important;
    transform: translateY(-1px);
}}

/* Back to Audit Action Button */
button[key="back_to_audit_btn"] {{
    background: var(--card-bg) !important;
    color: var(--text-primary) !important;
    border: 1px solid var(--card-border) !important;
    border-radius: 8px !important;
    font-weight: 700 !important;
    font-size: 0.86rem !important;
    padding: 8px 16px !important;
    box-shadow: none !important;
    transition: all 0.2s ease !important;
}}
button[key="back_to_audit_btn"]:hover {{
    border-color: #3B82F6 !important;
    color: #3B82F6 !important;
    box-shadow: 0 0 15px var(--accent-glow) !important;
}}

/* Popover dropdown container common layout */
div[data-testid="stPopoverBody"] {{
    min-width: 340px !important;
}}

.stDownloadButton > button {{
    background: linear-gradient(90deg, #059669 0%, #10B981 100%) !important;
    color: #FFFFFF !important;
    border: none !important;
    border-radius: 8px !important;
    font-weight: 700 !important;
    font-size: 0.92rem !important;
    padding: 12px 20px !important;
    width: 100% !important;
    box-shadow: 0 4px 15px rgba(16, 185, 129, 0.3) !important;
    transition: all 0.2s ease !important;
}}
.stDownloadButton > button:hover {{
    background: linear-gradient(90deg, #047857 0%, #059669 100%) !important;
    box-shadow: 0 6px 20px rgba(16, 185, 129, 0.5) !important;
}}

.evidence-tag {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    background: var(--subcard-bg);
    border: 1px solid var(--subcard-border);
    padding: 5px 9px;
    border-radius: 6px;
    color: var(--text-secondary);
    word-break: break-all;
}}
</style>
""", unsafe_allow_html=True)


# ── Indian National Tricolor Top Strip ───────────────────────────────────────
st.markdown("""
<div style="height: 4px; width: 100%; display: flex; margin-bottom: 10px; border-radius: 2px; overflow: hidden;">
  <div style="flex: 1; background-color: #FF9933;"></div>
  <div style="flex: 1; background-color: #FFFFFF;"></div>
  <div style="flex: 1; background-color: #138808;"></div>
</div>
""", unsafe_allow_html=True)


# ── Responsive, Full-Width Top Navigation Bar (Always Visible Across Stages) ──
nav_brand, nav_toll, nav_advisory, nav_theme = st.columns([4.2, 1.4, 2.2, 0.7], vertical_alignment="center")

with nav_brand:
    st.markdown("""
    <div style="display: flex; align-items: center; gap: 12px;">
      <!-- High-res Cyber Shield Crest Badge -->
      <svg width="42" height="42" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="24" cy="24" r="22" stroke="#1D4ED8" stroke-width="2" fill="#0F172A"/>
        <path d="M24 7L38 13V24C38 32.5 32 39 24 42C16 39 10 32.5 10 24V13L24 7Z" fill="#1E3A8A" stroke="#3B82F6" stroke-width="1.8"/>
        <circle cx="24" cy="24" r="7" stroke="#FF9933" stroke-width="1.5" fill="none"/>
        <path d="M24 19V29M19 24H29M20.5 20.5L27.5 27.5M20.5 27.5L27.5 20.5" stroke="#FF9933" stroke-width="1.2"/>
        <path d="M21 24L23.5 26.5L27.5 21.5" stroke="#10B981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <div>
        <div style="font-weight: 800; font-size: 1.25rem; letter-spacing: -0.01em; color: var(--brand-blue); line-height: 1.1;">
          INTERNKAVACH
        </div>
        <div style="font-size: 0.78rem; color: var(--text-secondary); font-weight: 500;">
          National Cyber-Forensics Portal
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)

with nav_toll:
    st.markdown("""
    <div style="display: flex; align-items: center; justify-content: center; height: 100%;">
      <span class="gov-pill pill-red" style="padding: 6px 12px; font-size: 0.75rem; height: 38px; display: inline-flex; align-items: center;">
        <span class="pulse-dot"></span>
        TOLL-FREE: 1930
      </span>
    </div>
    """, unsafe_allow_html=True)

with nav_advisory:
    with st.popover("STATUTORY & ACADEMIC STANDARDS", use_container_width=True):
        st.markdown("""
        <div style="font-size: 0.88rem; font-weight: 700; margin-bottom: 8px; color: var(--brand-blue);">
          INSTITUTIONAL &amp; FEDERAL STANDARDS MATRIX
        </div>
        <div style="font-size: 0.80rem; line-height: 1.6; color: var(--text-secondary);">
          <p><b>1. NIST SP 800-86 (Digital Forensics):</b><br>
          &bull; <b>4-Phase Lifecycle:</b> Collection &rarr; Examination &rarr; Analysis &rarr; Reporting.<br>
          &bull; Magic-byte inspection, bit-stream write-blocking, and metadata MAC tracking.</p>

          <p><b>2. NIST SP 800-181 Rev. 1 (NICE Framework):</b><br>
          &bull; <b>PR-CDA-001:</b> Cyber Defense Forensics Analyst credentialing.<br>
          &bull; <b>OV-LGA-001:</b> Cyber Legal Advisor statutory compliance review.</p>

          <p><b>3. Prakash &amp; Sadawarti (2022) Forensic Architecture:</b><br>
          &bull; Context-Triggered Piecewise Fuzzy Hashing (CTPH) &amp; immutable Chain of Custody (CoC) ledger.</p>

          <p><b>4. Katsantonis et al. (2023) COFELET Framework:</b><br>
          &bull; Multi-vector threat rubric &amp; pedagogical Forensic Coach remediation.</p>

          <p><b>5. Indian Penal &amp; Labor Statutes:</b><br>
          &bull; <b>BNS 2023 Sec 318(4):</b> Cheating and dishonest inducement to deliver property.<br>
          &bull; <b>BNS 2023 Sec 336(3):</b> Forgery of valuable electronic recruitment documents.<br>
          &bull; <b>IT Act 2000 Sec 66D:</b> Punishment for cyber personation.<br>
          &bull; <b>Apprentices Act 1961 Sec 3 &amp; 4:</b> Mandatory stipends; absolute prohibition of fees.</p>
        </div>
        <hr style="margin: 10px 0; border: none; border-top: 1px solid var(--subcard-border);">
        <div style="font-size: 0.75rem; color: var(--text-secondary);">
          National Reporting: <a href="https://cybercrime.gov.in" target="_blank" style="color: var(--brand-blue); font-weight:700;">cybercrime.gov.in</a> &middot; Helpline: <b>1930</b>
        </div>
        """, unsafe_allow_html=True)

with nav_theme:
    theme_icon = "🌙" if is_dark else "☀️"
    if st.button(theme_icon, key="theme_toggle", use_container_width=True, help="Toggle Light / Dark Theme"):
        st.session_state["theme"] = "light" if is_dark else "dark"
        st.rerun()

st.markdown("<hr style='border: none; border-top: 1px solid var(--card-border); margin: 6px 0 16px 0;'>", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 1: UPLOAD & CONFIGURATION (HIDDEN WHEN RESULTS DISPLAY)
# ═══════════════════════════════════════════════════════════════════════════════
if not st.session_state.get("audit_complete", False):
    # ── Harmonized Hero Banner ────────────────────────────────────────────────
    st.markdown("""
    <div class="cinematic-hero">
      <div style="margin-bottom: 10px;">
        <span class="gov-pill hero-tag">
          OFFICIAL DIRECTIVE // FRAUD MITIGATION &amp; TAMPER DETECTION
        </span>
      </div>
      <div class="hero-title" style="font-size: clamp(1.5rem, 3.8vw, 2.3rem); font-weight: 800; letter-spacing: -0.02em; line-height: 1.2; margin-bottom: 12px;">
        NATIONAL CYBER-DEFENSE RECRUITMENT FORENSIC PORTAL
      </div>
      <div class="hero-sub" style="font-size: 0.96rem; max-width: 860px; margin: 0 auto; line-height: 1.6; font-weight: 400;">
        Autonomous multimodal intelligence safeguarding Indian engineering candidates and placement cells against unverified certificate mills, forged corporate seals, and mule account clearing networks.
      </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Official Advisory Notice Board ────────────────────────────────────────
    st.markdown("""
    <div class="advisory-banner">
      <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px;">
        <span class="gov-pill pill-amber" style="font-size: 0.70rem;">OFFICIAL NOTICE</span>
        <span style="font-weight: 800; font-size: 0.95rem; letter-spacing: -0.01em; color: var(--advisory-text);">
          NATIONAL ADVISORY: MASS-MAILING VIRTUAL INTERNSHIP SYNDICATES
        </span>
      </div>
      <div style="font-size: 0.85rem; line-height: 1.6; color: var(--text-secondary);">
        Placement cells and candidates are advised to verify all unverified virtual internship offers demanding fees, using free generic email domains (@gmail/@outlook), or omitting Corporate Identification Numbers (CIN) under the <b>Apprentices Act, 1961</b>. Any document demanding security deposits or certificate processing charges is unlawful.
      </div>
    </div>
    """, unsafe_allow_html=True)

    # ── High-Impact Verification Console & Dropzone ───────────────────────────
    st.markdown("""
    <div class="gov-card verification-card">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; border-bottom: 1px solid var(--subcard-border); padding-bottom: 12px;">
        <div>
          <div style="font-size: 1.20rem; font-weight: 800; color: var(--text-primary); letter-spacing: -0.01em;">
            OFFER LETTER FORENSIC VERIFICATION CONSOLE
          </div>
          <div style="font-size: 0.82rem; color: var(--text-secondary); margin-top: 2px;">
            Submit digital appointment letters, virtual internship contracts, or WhatsApp recruitment screenshots for autonomous integrity audit.
          </div>
        </div>
        <span class="gov-pill pill-blue">LEVEL-1 AUDIT</span>
      </div>
    """, unsafe_allow_html=True)

    # Form Fields for Complainant / Candidate
    col_name, col_email = st.columns(2)
    with col_name:
        st.markdown("<div style='font-size:0.78rem; font-weight:700; margin-bottom:4px; color:var(--text-secondary); text-transform:uppercase;'>Investigator / Candidate Name</div>", unsafe_allow_html=True)
        candidate_name = st.text_input(
            "Candidate Name",
            value=st.session_state.get("investigator_name", "Rohit De"),
            label_visibility="collapsed",
            key="candidate_name_input",
        )
        st.session_state["investigator_name"] = candidate_name

    with col_email:
        st.markdown("<div style='font-size:0.78rem; font-weight:700; margin-bottom:4px; color:var(--text-secondary); text-transform:uppercase;'>College / Institutional Email</div>", unsafe_allow_html=True)
        candidate_email = st.text_input(
            "Candidate Email",
            value=st.session_state.get("investigator_email", "rohit.de@college.edu"),
            label_visibility="collapsed",
            key="candidate_email_input",
        )
        st.session_state["investigator_email"] = candidate_email

    st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)

    # File Dropzone
    st.markdown("<div style='font-size:0.78rem; font-weight:700; margin-bottom:4px; color:var(--text-secondary); text-transform:uppercase;'>Upload Offer Letter, Appointment PDF, or WhatsApp Screenshot (PDF, PNG, JPG)</div>", unsafe_allow_html=True)
    uploaded_file = st.file_uploader(
        "Upload Offer Letter, Appointment PDF, or WhatsApp Screenshot",
        type=["pdf", "png", "jpg", "jpeg"],
        label_visibility="collapsed",
        key=f"gov_uploader_{st.session_state['uploader_key']}",
    )

    # Prevent stale report leakage if a new file is uploaded
    if uploaded_file is not None and st.session_state.get("audit_filename") != uploaded_file.name:
        st.session_state["results"] = None
        st.session_state["audit_result"] = None

    st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)

    # Single Primary Audit Button (clean, no competing reset buttons)
    audit_triggered = st.button("INITIATE FORENSIC INTEGRITY AUDIT", use_container_width=True, key="initiate_audit_btn")

    st.markdown("</div>", unsafe_allow_html=True)

    # Handle Audit Execution
    if audit_triggered:
        if uploaded_file is None:
            st.warning("[REQUIRED] Please upload an offer letter, contract PDF, or image screenshot to begin audit.")
        else:
            file_bytes = uploaded_file.read()
            file_name = uploaded_file.name

            # Immediately wipe any previous report to prevent stale data leakage
            st.session_state["results"] = None
            st.session_state["audit_result"] = None
            st.session_state["audit_filebytes"] = None

            with st.spinner("Analyzing document structure, executing pixel ELA, and verifying corporate banking rails..."):
                res = audit_pipeline(
                    file_bytes=file_bytes,
                    file_name=file_name,
                    runtime_key=os.environ.get("GEMINI_API_KEY", ""),
                    complainant_name=candidate_name.strip() or "Rohit De",
                    complainant_contact=f"{candidate_email.strip() or 'rohit.de@college.edu'} (Student Applicant)",
                )
                st.session_state["results"] = res
                st.session_state["audit_result"] = res
                st.session_state["audit_filename"] = file_name
                st.session_state["audit_filebytes"] = file_bytes
                st.session_state["audit_complete"] = True
                st.rerun()


# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 2: EXECUTIVE FORENSIC DASHBOARD (HERO & DROPZONE COMPLETELY HIDDEN)
# ═══════════════════════════════════════════════════════════════════════════════
else:
    result = st.session_state.get("results") or st.session_state.get("audit_result")
    file_name = st.session_state.get("audit_filename", "Evidence Document")
    file_bytes = st.session_state.get("audit_filebytes")

    # If results are missing for any unexpected reason, safely revert to Stage 1
    if result is None:
        st.session_state["audit_complete"] = False
        st.rerun()

    # Sleek Top Action Bar
    bar_left, bar_right = st.columns([3.5, 1.2])
    with bar_left:
        st.markdown(f"""
        <div style="display: flex; align-items: center; gap: 10px; padding: 4px 0;">
          <span class="gov-pill pill-blue">FORENSIC DOSSIER</span>
          <span style="font-size: 1.15rem; font-weight: 800; color: var(--text-primary);">
            AUDIT REPORT: <span style="font-family:'JetBrains Mono', monospace; color: var(--brand-blue);">{file_name}</span>
          </span>
        </div>
        """, unsafe_allow_html=True)
    with bar_right:
        if st.button("← AUDIT ANOTHER OFFER", key="back_to_audit_btn", use_container_width=True):
            st.session_state["audit_complete"] = False
            st.session_state["results"] = None
            st.session_state["audit_result"] = None
            st.session_state["audit_filename"] = ""
            st.session_state["audit_filebytes"] = None
            st.session_state["uploader_key"] += 1
            st.rerun()

    st.markdown("<hr style='border: none; border-top: 1px solid var(--subcard-border); margin: 8px 0 16px 0;'>", unsafe_allow_html=True)

    # Gatekeeper Rejection Check (Non-Recruitment Documents)
    if not result.get("is_recruitment_document", True):
        st.markdown(f"""
        <div class="gov-card" style="border-left: 5px solid #EF4444;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
            <div style="font-size: 1.15rem; font-weight: 800; color: #EF4444;">
              [ALERT] NON-RECRUITMENT DOCUMENT DETECTED: {result.get('detected_type', 'Invalid Document')}
            </div>
            <span class="gov-pill pill-red">REJECTED BY GATEKEEPER</span>
          </div>
          <div style="font-size: 0.88rem; color: var(--text-secondary); margin-bottom: 12px;">
            {result.get('rejection_reason', 'Uploaded file does not match employment contract or internship criteria.')}
          </div>
          <div style="font-size: 0.80rem; color: var(--text-secondary);">
            InternKavach is calibrated exclusively for internship contracts, job appointment letters, and recruitment communications.
          </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        verdict = result.get("verdict", "SUSPICIOUS")
        risk_score = result.get("risk_score", 0)

        # 1. Threat Verdict Card (Visual Verdict Banner)
        if verdict == "HIGH RISK":
            seal_pill = '<span class="gov-pill pill-red">CRITICAL RISK &middot; LIKELY FRAUD</span>'
            seal_color = "#EF4444"
            verdict_text = "VERDICT: SUSPICIOUS (UNLAWFUL RECRUITMENT OFFER)"
            seal_border = "border-left: 6px solid #EF4444;"
        elif verdict == "SUSPICIOUS":
            seal_pill = '<span class="gov-pill pill-amber">SUSPICIOUS ANOMALIES</span>'
            seal_color = "#F59E0B"
            verdict_text = "VERDICT: SUSPICIOUS (UNVERIFIED CORPORATE ENTITY)"
            seal_border = "border-left: 6px solid #F59E0B;"
        else:
            seal_pill = '<span class="gov-pill pill-green">OFFICIALLY VERIFIED</span>'
            seal_color = "#10B981"
            verdict_text = "VERDICT: CLEAN (LEGITIMATE APPOINTMENT DOCUMENT)"
            seal_border = "border-left: 6px solid #10B981;"

        st.markdown(f"""
        <div class="gov-card" style="{seal_border}">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <div>{seal_pill}</div>
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.90rem; font-weight: 700; color: {seal_color};">
              THREAT INDEX: {risk_score} / 100
            </div>
          </div>
          <div style="font-size: 1.45rem; font-weight: 800; color: var(--text-primary); margin-bottom: 10px; letter-spacing: -0.01em;">
            {verdict_text}
          </div>
          <div style="font-size: 0.88rem; color: var(--text-secondary); margin-bottom: 12px; line-height: 1.6;">
            <b>Audited Evidence:</b> <span class="evidence-tag">{file_name}</span> &nbsp;&middot;&nbsp;
            <b>SHA-256 Digest:</b> <span class="evidence-tag">{result.get('sha256', '--')}</span>
          </div>
        """, unsafe_allow_html=True)

        for item in result.get("summary", []):
            st.markdown(f"<div style='font-size:0.86rem; color:var(--text-secondary); padding: 4px 0;'>&bull;&nbsp;{item}</div>", unsafe_allow_html=True)

        st.markdown("</div>", unsafe_allow_html=True)

        # 1.5 Academic & Institutional Telemetry Bento Bar
        template_match = result.get("template_match", {})
        cofelet = result.get("cofelet_rubric", {})
        coc = result.get("chain_of_custody", {})
        nice = result.get("nice_credentials", {})

        col_bento_sim, col_bento_std = st.columns([1.5, 1])
        with col_bento_sim:
            sim_score = template_match.get("template_similarity_score", 0)
            sim_color = "#EF4444" if sim_score >= 60 else "#F59E0B" if sim_score >= 35 else "#10B981"
            st.markdown(f"""
            <div class="gov-card" style="padding: 1.1rem 1.4rem;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <div style="font-size: 0.88rem; font-weight: 800; color: var(--text-primary); text-transform: uppercase;">
                  Template Similarity &amp; Chain of Custody (CoC)
                </div>
                <span class="gov-pill pill-blue">PRAKASH &amp; SADAWARTI (2022)</span>
              </div>
              <div style="display: flex; align-items: baseline; gap: 10px; margin-bottom: 6px;">
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 1.6rem; font-weight: 800; color: {sim_color};">
                  {sim_score}%
                </div>
                <div style="font-size: 0.82rem; color: var(--text-secondary);">
                  Syndicate Match: <b style="color: var(--text-primary);">{template_match.get('matched_template_name', 'Unique Document Structure')}</b>
                </div>
              </div>
              <div style="font-size: 0.76rem; color: var(--text-secondary); line-height: 1.5; font-family: 'JetBrains Mono', monospace;">
                CoC ID: {coc.get('coc_id', '--')[:28]}… &middot; CTPH Digest: {template_match.get('fuzzy_hash', '--')[:24]}…
              </div>
            </div>
            """, unsafe_allow_html=True)

        with col_bento_std:
            st.markdown(f"""
            <div class="gov-card" style="padding: 1.1rem 1.4rem;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <div style="font-size: 0.88rem; font-weight: 800; color: var(--text-primary); text-transform: uppercase;">
                  Forensic Methodology Standard
                </div>
                <span class="gov-pill pill-green">NIST ACCREDITED</span>
              </div>
              <div style="margin: 6px 0;">
                <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.84rem; font-weight: 700; color: var(--brand-blue); background: var(--tag-bg); padding: 4px 8px; border-radius: 6px; border: 1px solid var(--card-border);">
                  NIST SP 800-86 &amp; BNS COMPLIANT
                </span>
              </div>
              <div style="font-size: 0.78rem; color: var(--text-secondary); margin-top: 6px;">
                Investigator Role: <b style="color: var(--text-primary);">{nice.get('primary_role_title', 'Cyber Defense Analyst')}</b> ({nice.get('primary_role_id', 'PR-CDA-001')})
              </div>
            </div>
            """, unsafe_allow_html=True)

        # 2. Forensic Artifacts Grid
        col_res_l, col_res_r = st.columns(2)

        # Left Column: Side-by-Side ELA Pixel Tampering Heatmap
        with col_res_l:
            st.markdown("""
            <div class="gov-card">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                <div style="font-size: 1.0rem; font-weight: 800; color: var(--text-primary);">
                  ERROR LEVEL ANALYSIS (ELA) &middot; PIXEL INTEGRITY
                </div>
                <span class="gov-pill pill-blue">TAMPER DETECTION</span>
              </div>
              <div style="font-size: 0.82rem; color: var(--text-secondary); margin-bottom: 12px;">
                Identifies digitally spliced company stamps, signature alterations, and modified stipend figures.
              </div>
            """, unsafe_allow_html=True)

            ela_bytes = result.get("ela_image")
            file_ext = Path(file_name).suffix.lower()

            if ela_bytes is not None:
                ela_c1, ela_c2 = st.columns(2)
                with ela_c1:
                    st.markdown("<div style='font-size:0.75rem; font-weight:600; color:var(--text-secondary); margin-bottom:4px;'>SUBMITTED DOCUMENT</div>", unsafe_allow_html=True)
                    if file_bytes:
                        st.image(file_bytes, use_container_width=True)
                with ela_c2:
                    st.markdown("<div style='font-size:0.75rem; font-weight:600; color:var(--text-secondary); margin-bottom:4px;'>ELA RESIDUAL MAP</div>", unsafe_allow_html=True)
                    st.image(ela_bytes, use_container_width=True)

                ela_prob = int(result.get("ela_prob", 0) * 100)
                prob_color = "#EF4444" if ela_prob > 50 else "#10B981"
                st.markdown(f"""
                <div style="margin-top: 10px; font-size: 0.82rem; color: var(--text-secondary);">
                  Calculated Forgery Probability: <b style="color: {prob_color};">{ela_prob}%</b>
                </div>
                """, unsafe_allow_html=True)
            elif file_ext == ".pdf":
                st.markdown("""
                <div class="gov-subcard" style="font-size: 0.84rem; color: var(--text-secondary); line-height: 1.6;">
                  <b>Native PDF Document:</b> Verified structural PDF object stream and internal embedded font integrity. Raster pixel error level analysis applies to image captures (PNG/JPG) of appointment letters.
                </div>
                """, unsafe_allow_html=True)
            else:
                st.info("ELA could not be executed on this file format.")

            st.markdown("</div>", unsafe_allow_html=True)

        # Right Column: Corporate & Banking OSINT Audit
        with col_res_r:
            st.markdown("""
            <div class="gov-card">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                <div style="font-size: 1.0rem; font-weight: 800; color: var(--text-primary);">
                  CORPORATE &amp; CLEARING BANKING AUDIT
                </div>
                <span class="gov-pill pill-blue">ENTITY OSINT</span>
              </div>
              <div style="font-size: 0.82rem; color: var(--text-secondary); margin-bottom: 12px;">
                Validation of Corporate Identification Number (CIN), registered email domain, and beneficiary bank branch.
              </div>
            """, unsafe_allow_html=True)

            map_data = result.get("map_data", {})
            is_mule = map_data.get("is_mule", False)
            bank_status_color = "#EF4444" if is_mule else "#10B981" if map_data.get("has_route") else "#64748B"

            st.markdown(f"""
            <div class="gov-subcard">
              <div style="font-size: 0.70rem; color: var(--text-secondary); text-transform: uppercase; font-weight: 700;">Claimed Corporate Entity</div>
              <div style="font-size: 0.95rem; font-weight: 700; color: var(--text-primary);">{result.get('company_name', 'Unknown Entity')}</div>
              <div style="font-size: 0.78rem; color: var(--text-secondary);">
                Claimed HQ: {map_data.get('claimed_hq', 'Unspecified')} &middot; CIN: <b style="color:var(--text-primary);">{result.get('cin_number', 'ABSENT / UNVERIFIED')}</b>
              </div>
            </div>

            <div class="gov-subcard">
              <div style="font-size: 0.70rem; color: var(--text-secondary); text-transform: uppercase; font-weight: 700;">Beneficiary Banking Route (IFSC Check)</div>
              <div style="font-size: 0.95rem; font-weight: 700; color: {bank_status_color};">{map_data.get('bank_name', 'No Banking Details Found')}</div>
              <div style="font-size: 0.78rem; color: var(--text-secondary);">
                Branch: {map_data.get('bank_branch', '--')}, {map_data.get('bank_city', '--')} ({map_data.get('bank_state', '--')}) &middot; IFSC: {map_data.get('ifsc_code', '--')}
              </div>
              <div style="margin-top: 6px; font-size: 0.80rem; font-weight: 600; color: {bank_status_color};">
                Status: {'ALERT: MULE ACCOUNT HOTSPOT' if is_mule else 'CLEARING NORMAL' if map_data.get('has_route') else 'NO DISCREPANCY'}
                {f" &middot; {int(map_data['distance_km'])} km geographic discrepancy" if map_data.get('distance_km') is not None else ""}
              </div>
            </div>
            """, unsafe_allow_html=True)

            st.markdown("</div>", unsafe_allow_html=True)

        # ── COFELET Forensic Coach, Chain of Custody & Syndicate Tabs ──────────
        tab_coach, tab_coc, tab_syndicate = st.tabs([
            "COFELET Forensic Coach & Statutory Labor Remedies",
            "NIST SP 800-86 Chain of Custody (CoC) Ledger",
            "Syndicate Entity Graph & Payment Rails",
        ])

        with tab_coach:
            cofelet_data = result.get("cofelet_rubric", {})
            vectors = cofelet_data.get("threat_vectors", {})
            coach_remedies = cofelet_data.get("coach_recommendations", [])

            # Threat vector breakdown cards
            v_cols = st.columns(4)
            vector_keys = [
                ("labor_compliance", "Labor Compliance", "Apprentices Act 1961 (30%)"),
                ("corporate_identity", "Corporate Identity", "MCA CIN & Domain (25%)"),
                ("financial_risk", "Financial Risk", "IFSC & Mule Rails (25%)"),
                ("forensic_integrity", "Forensic Integrity", "ELA & CTPH Hash (20%)"),
            ]
            for (v_key, v_title, v_sub), col_v in zip(vector_keys, v_cols):
                v_info = vectors.get(v_key, {"score": 0, "flags": []})
                v_sc = v_info.get("score", 0)
                v_clr = "#EF4444" if v_sc >= 60 else "#F59E0B" if v_sc >= 35 else "#10B981"
                with col_v:
                    st.markdown(f"""
                    <div class="gov-subcard" style="text-align: center; padding: 0.8rem 0.5rem;">
                      <div style="font-size: 0.70rem; color: var(--text-secondary); font-weight: 700; text-transform: uppercase;">{v_title}</div>
                      <div style="font-size: 1.3rem; font-weight: 800; color: {v_clr}; margin: 2px 0;">{v_sc}/100</div>
                      <div style="font-size: 0.68rem; color: var(--text-secondary);">{v_sub}</div>
                    </div>
                    """, unsafe_allow_html=True)

            # Coach Remedial Directive Box
            st.markdown("""
            <div class="gov-card" style="border-left: 4px solid var(--brand-blue); margin-top: 10px;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                <div style="font-size: 0.95rem; font-weight: 800; color: var(--brand-blue);">
                  COFELET FORENSIC COACH // STATUTORY REMEDIAL DIRECTIVE
                </div>
                <span class="gov-pill pill-blue">KATSANTONIS ET AL. (2023)</span>
              </div>
            """, unsafe_allow_html=True)

            for idx, remedy in enumerate(coach_remedies, 1):
                st.markdown(f"""
                <div class="gov-subcard" style="margin-bottom: 8px;">
                  <div style="font-size: 0.82rem; font-weight: 800; color: var(--text-primary); margin-bottom: 2px;">
                    {idx}. {remedy.get('vector', 'Statutory Remedy')} &middot; <span style="color: var(--brand-blue); font-weight: 600;">{remedy.get('statute', '')}</span>
                  </div>
                  <div style="font-size: 0.82rem; color: var(--text-secondary); line-height: 1.5;">
                    {remedy.get('guidance', '')}
                  </div>
                </div>
                """, unsafe_allow_html=True)

            st.markdown("</div>", unsafe_allow_html=True)

            # Scenario Execution Flow (SEF)
            sef_list = cofelet_data.get("scenario_execution_flow", [])
            if sef_list:
                st.markdown("<div style='font-size:0.78rem; font-weight:700; color:var(--text-secondary); text-transform:uppercase; margin: 8px 0 4px 0;'>COFELET Scenario Execution Flow (SEF) Audit Track</div>", unsafe_allow_html=True)
                sef_html = " ".join([
                    f"<span class='gov-pill {'pill-red' if s.get('status') == 'FLAGGED' else 'pill-green' if s.get('status') == 'PASSED' else 'pill-blue'}' style='font-size:0.68rem; margin: 2px;'>{s.get('name')}</span>"
                    for s in sef_list
                ])
                st.markdown(f"<div style='display:flex; flex-wrap:wrap; gap:4px; margin-bottom:12px;'>{sef_html}</div>", unsafe_allow_html=True)

        with tab_coc:
            coc_block = result.get("chain_of_custody", {})
            st.markdown(f"""
            <div class="gov-card">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                <div style="font-size: 0.95rem; font-weight: 800; color: var(--text-primary);">
                  IMMUTABLE CHAIN OF CUSTODY (CoC) DIGITAL EVIDENCE LEDGER
                </div>
                <span class="gov-pill pill-green">PRAKASH &amp; SADAWARTI (2022)</span>
              </div>
              <div style="font-size: 0.82rem; color: var(--text-secondary); margin-bottom: 12px;">
                Cryptographically sealed transaction record guaranteeing forensic admissibility under Section 65B of the Indian Evidence Act &amp; NIST SP 800-86.
              </div>
              <div class="gov-subcard" style="font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; line-height: 1.7; color: var(--text-primary);">
                <b>LEDGER RECORD UUID:</b> {coc_block.get('coc_id', '--')}<br>
                <b>TIMESTAMP (UTC):</b> {coc_block.get('timestamp_utc', '--')}<br>
                <b>EVIDENCE FILE:</b> {coc_block.get('source_filename', '--')} ({coc_block.get('file_size_bytes', 0)} bytes)<br>
                <b>CRYPTOGRAPHIC SHA-256:</b> {coc_block.get('sha256', '--')}<br>
                <b>MD5 DIGEST:</b> {coc_block.get('md5', '--')}<br>
                <b>PIECEWISE FUZZY HASH (CTPH):</b> {coc_block.get('fuzzy_hash', '--')}<br>
                <b>EXAMINER WORK ROLE:</b> {coc_block.get('examiner_work_role', 'Cyber Defense Forensics Analyst (NICE PR-CDA-001)')}<br>
                <b>EXAMINER SIGNATURE:</b> {coc_block.get('examiner_name', 'Authorized Investigator')}<br>
                <b>BLOCK INTEGRITY SEAL:</b> <span style="color: var(--brand-blue);">{coc_block.get('block_signature', '--')}</span><br>
                <b>STATUS:</b> <span style="color: #10B981; font-weight: 700;">{coc_block.get('integrity_status', 'VERIFIED_TAMPER_EVIDENT')}</span>
              </div>
            </div>
            """, unsafe_allow_html=True)

        with tab_syndicate:
            st.markdown("""
            <div class="gov-card">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                <div style="font-size: 0.95rem; font-weight: 800; color: var(--text-primary);">
                  CROSS-DOCUMENT SYNDICATE CORRELATION GRAPH
                </div>
                <span class="gov-pill pill-blue">SYNDICATE INTEL</span>
              </div>
            """, unsafe_allow_html=True)

            graph_bytes = result.get("graph_image")
            if graph_bytes:
                st.image(graph_bytes, caption="Entity Link Graph (Cross-Document Correlation)", use_container_width=True)
            else:
                st.info("No cross-document syndicate clusters detected for this document.")

            if result.get("syndicate_flags"):
                st.markdown("<div style='margin-top: 10px;'>", unsafe_allow_html=True)
                for s_flag in result["syndicate_flags"]:
                    st.markdown(f"<div style='font-size:0.82rem; color:#EF4444; margin: 3px 0;'>&bull; {s_flag}</div>", unsafe_allow_html=True)
                st.markdown("</div>", unsafe_allow_html=True)

            st.markdown("</div>", unsafe_allow_html=True)

        # 3. Statutory Legal Dossier & FIR Action Bar
        col_action_fir, col_action_report = st.columns([1.5, 1])

        with col_action_fir:
            st.markdown("""
            <div class="gov-card">
              <div style="font-size: 1.0rem; font-weight: 800; color: var(--text-primary); margin-bottom: 6px;">
                OFFICIAL LEGAL DOSSIER &amp; COMPLAINT FILING
              </div>
              <div style="font-size: 0.84rem; color: var(--text-secondary); margin-bottom: 12px; line-height: 1.5;">
                Generates a court-admissible forensic audit report stamped with the complainant's institutional credentials, SHA-256 hash digests, and applicable BNS 2023 / IT Act provisions.
              </div>
            """, unsafe_allow_html=True)

            pdf_bytes = result.get("pdf_bytes")
            if pdf_bytes:
                st.download_button(
                    label="DOWNLOAD OFFICIAL CYBER COMPLAINT DOSSIER (PDF)",
                    data=pdf_bytes,
                    file_name=f"Official_Complaint_Dossier_{Path(file_name).stem}.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                )
            else:
                st.error("Dossier generation is unavailable for this specific document.")

            st.markdown("</div>", unsafe_allow_html=True)

        with col_action_report:
            st.markdown("""
            <div class="gov-card">
              <div style="font-size: 1.0rem; font-weight: 800; color: var(--text-primary); margin-bottom: 6px;">
                INCIDENT REPORTING STEPS
              </div>
              <div style="font-size: 0.82rem; color: var(--text-secondary); line-height: 1.6;">
                1. Download the certified PDF dossier above.<br>
                2. Visit the National Cyber Crime Reporting Portal: <a href="https://cybercrime.gov.in" target="_blank" style="color:var(--brand-blue); font-weight:700;">cybercrime.gov.in</a><br>
                3. File under <b>"Report Cyber Fraud / Recruitment Scam"</b>.<br>
                4. For immediate telephone reporting, dial Toll-Free: <b style="color:#EF4444;">1930</b>.
              </div>
            </div>
            """, unsafe_allow_html=True)


# ── Official Portal Footer ───────────────────────────────────────────────────
st.markdown("""
<div style="text-align: center; margin-top: 3.5rem; padding-top: 1.5rem; border-top: 1px solid var(--card-border); font-size: 0.76rem; color: var(--text-secondary); line-height: 1.6;">
  <b>INTERNKAVACH</b> &middot; National Cyber-Forensics Initiative for Student Recruitment &amp; Offer Integrity<br>
  Compliant with <b>Bharatiya Nyaya Sanhita (BNS) 2023</b> &middot; <b>Information Technology Act, 2000</b> &middot; <b>Apprentices Act, 1961</b><br>
  In integration with National Cyber Crime Reporting Portal (1930) &middot; Placement Cells &amp; Institutional Governance Unit
</div>
""", unsafe_allow_html=True)
