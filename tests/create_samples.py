"""
tests/create_samples.py
Generates mock sample documents for InternKavach testing.
Run once to populate tests/samples/.
"""
from __future__ import annotations

import io
import os
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

# ── Sample 1: Clean Legitimate Offer Letter ────────────────────────────────────
CLEAN_OFFER_TEXT = """
INTERNSHIP OFFER LETTER

Date: 15 January 2024
Reference: TCS/HR/2024/INT/8821

To,
Mr. Rahul Sharma
B.Tech Computer Science, 3rd Year
Delhi Technological University, New Delhi

Dear Rahul,

We are delighted to offer you an internship position at Tata Consultancy Services Limited
as a Software Development Intern in our Digital Division.

Internship Details:
- Duration: 6 months (01 February 2024 – 31 July 2024)
- Location: TCS Siruseri Campus, Chennai, Tamil Nadu – 603103
- Stipend: ₹25,000 per month (paid directly to your bank account)
- Employee ID: TCS-INT-2024-8821
- Reporting Manager: Ms. Priya Krishnamurthy (priya.k@tcs.com)

Terms & Conditions:
1. You will be required to sign a Non-Disclosure Agreement on Day 1.
2. The stipend will be credited to your registered bank account on the last working day of each month.
3. No fee of any kind is charged for this internship. Any communication demanding payment is fraudulent.
4. On successful completion, you will receive a certified experience letter and performance-based PPO consideration.
5. You are entitled to 2 days of sick leave per month.
6. Provident Fund and Gratuity benefits as per applicable law.

Annual CTC equivalent: ₹3,00,000

This offer is contingent upon successful completion of document verification and
medical fitness clearance.

Please confirm your acceptance by signing and returning this letter by 22 January 2024.

Warm Regards,

Ms. Ananya Mehta
Head of Human Resources, Digital Division
Tata Consultancy Services Limited
TCS House, Raveline Street, Fort, Mumbai – 400 001
Email: hr.intern@tcs.com | Tel: +91 22 6778 9999
CIN: L22210MH1995PLC084781
"""

# ── Sample 2: Scam / Doctored Offer Letter ────────────────────────────────────
SCAM_OFFER_TEXT = """
INTERNSHIP OFFER LETER  [sic]

Dated: 14/1/2024
Ref No: TechVision/HR/0001

To,
The Candidate

CONGRATULATION!! You Are SELECTED for INTERNSHIP at TechVision Pvt Ltd
(A leading IT company, Gurugram)

Post: Online Data Entry Intern (Work From Home)
Stipend: ₹45,000 per month (GUARANTEED DAILY PAYMENT)
Joining Date: IMMEDIATE

IMPORTANT NOTICE:
To confirm your selection and receive your Offer Letter Kit, you must pay the following:
- Registration Fee: ₹1,500 (non-refundable)
- Laptop Security Deposit: ₹3,000 (refundable after 6 months)
- ID Card & Kit Fee: ₹500
Total: ₹5,000

Pay immediately via:
UPI ID: fraudjobs@ybl
OR Bank Transfer:
Account No: 87654321001234
IFSC: SBIN0001234
Account Name: TechVision HR Dept

After payment, join our Telegram channel: t.me/TechVisionInterns
Send payment screenshot to WhatsApp: 9876543210

Note: Pay within 24 hours or your slot will be cancelled. Limited seats available.
DO NOT SHARE THIS OFFER WITH ANYONE.

HR Department
TechVision Pvt Ltd
(This is an online company, no physical address)
hr@techvision-jobs.co.in
"""


def create_pdf_sample(text: str, output_path: Path, title: str, creator: str = "Microsoft Word 2016") -> None:
    """Create a PDF with given text using reportlab."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from reportlab.lib.enums import TA_JUSTIFY

        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf, pagesize=A4,
            rightMargin=2.5*cm, leftMargin=2.5*cm,
            topMargin=2*cm, bottomMargin=2*cm,
            title=title,
            author="HR Department",
            creator=creator,
        )
        styles = getSampleStyleSheet()
        story = []
        for line in text.strip().split("\n"):
            if line.strip():
                story.append(Paragraph(line.strip().replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"), styles["Normal"]))
                story.append(Spacer(1, 3))
            else:
                story.append(Spacer(1, 8))

        doc.build(story)
        output_path.write_bytes(buf.getvalue())
        print(f"  ✅ Created: {output_path}")
    except ImportError:
        # Fallback to plain text if reportlab not yet installed
        output_path.with_suffix(".txt").write_text(text, encoding="utf-8")
        print(f"  ⚠️  reportlab not available – saved as TXT: {output_path.with_suffix('.txt')}")


def create_image_sample(output_path: Path, tampered: bool = False) -> None:
    """Create a synthetic offer letter image (PNG) optionally with tampering artifacts."""
    try:
        from PIL import Image, ImageDraw, ImageFont
        import numpy as np

        # Base image
        img = Image.new("RGB", (800, 600), color=(255, 255, 255))
        draw = ImageDraw.Draw(img)

        # Simple text layout
        draw.rectangle([40, 40, 760, 80], fill=(0, 51, 102))
        draw.text((50, 50), "INTERNSHIP OFFER LETTER", fill=(255, 255, 255))
        draw.text((50, 100), "Company: TechVision Pvt Ltd", fill=(0, 0, 0))
        draw.text((50, 130), "Position: Online Data Entry Intern", fill=(0, 0, 0))
        draw.text((50, 160), "Pay Registration Fee: Rs. 1500 immediately", fill=(200, 0, 0))
        draw.text((50, 190), "UPI: fraudjobs@ybl", fill=(0, 0, 0))
        draw.text((50, 220), "IFSC: SBIN0001234  (Jamtara Branch)", fill=(0, 0, 0))
        draw.text((50, 280), "Join Telegram: t.me/TechVisionInterns", fill=(0, 0, 150))

        if tampered:
            # Inject a "pasted" block (high ELA artifact)
            arr = np.array(img, dtype=np.uint8)
            # Paste a slightly different block at the signature area
            arr[400:480, 100:400] = np.clip(arr[400:480, 100:400].astype(int) + 40, 0, 255).astype(np.uint8)
            # Add noise to simulate JPEG re-compression artifact
            noise = np.random.randint(-8, 8, arr[300:350, 200:500].shape, dtype=np.int16)
            arr[300:350, 200:500] = np.clip(arr[300:350, 200:500].astype(np.int16) + noise, 0, 255).astype(np.uint8)
            img = Image.fromarray(arr)
            draw = ImageDraw.Draw(img)
            draw.text((100, 410), "[SIGNATURE BLOCK — PASTED FROM OTHER DOCUMENT]", fill=(180, 180, 180))

        img.save(output_path, format="PNG")
        print(f"  ✅ Created: {output_path}")
    except ImportError:
        print(f"  ⚠️  Pillow not available – skipping image sample")


if __name__ == "__main__":
    samples_dir = ROOT / "tests" / "samples"
    samples_dir.mkdir(parents=True, exist_ok=True)

    print("Creating test samples…")

    # PDF samples
    create_pdf_sample(
        CLEAN_OFFER_TEXT,
        samples_dir / "clean_offer_tcs.pdf",
        title="TCS Internship Offer Letter",
        creator="Adobe Acrobat Pro",
    )
    create_pdf_sample(
        SCAM_OFFER_TEXT,
        samples_dir / "scam_offer_techvision.pdf",
        title="TechVision Internship Offer",
        creator="Microsoft Word 2016",
    )

    # Image samples
    create_image_sample(samples_dir / "clean_offer_image.png", tampered=False)
    create_image_sample(samples_dir / "tampered_offer_image.png", tampered=True)

    print("\nAll samples created in:", samples_dir)
    print("\nSample files:")
    for f in sorted(samples_dir.iterdir()):
        size = f.stat().st_size
        print(f"  {f.name:40s} {size:>8,} bytes")
