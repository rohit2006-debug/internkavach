"""
src/forensics/banking.py
IFSC & UPI Triangulation Engine for InternKavach
Detects mule accounts and geographical anomalies in payment rails.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

# ── Regex patterns ─────────────────────────────────────────────────────────────
IFSC_PATTERN = re.compile(r"\b([A-Z]{4}0[A-Z0-9]{6})\b")
UPI_PATTERN  = re.compile(r"\b([\w.\-]{3,}@[\w]{3,})\b")

# ── Razorpay public IFSC API ──────────────────────────────────────────────────
RAZORPAY_IFSC_URL = "https://ifsc.razorpay.com/{code}"

# ── Known mule-account hot-spots (district/city → risk bump) ─────────────────
MULE_HOTSPOTS = {
    "jamtara": 45,
    "deoghar": 40,
    "giridih": 38,
    "dhanbad": 30,
    "bokaro":  28,
    "siwan":   35,
    "mewat":   32,
    "nuh":     32,
    "bharatpur": 25,
    "mathura": 22,
    "karnal":  20,
}

# ── Metropolitan HQs claimed by most fake job-offer companies ────────────────
LEGIT_HQ_CITIES = {
    "bengaluru", "bangalore", "mumbai", "delhi", "new delhi",
    "gurugram", "gurgaon", "hyderabad", "pune", "chennai",
    "noida", "kolkata",
}

# ── City Geolocation Coordinates for Distance Math ───────────────────────────
import math

CITY_COORDINATES: Dict[str, Tuple[float, float]] = {
    "bengaluru": (12.9716, 77.5946),
    "bangalore": (12.9716, 77.5946),
    "mumbai": (19.0760, 72.8777),
    "delhi": (28.7041, 77.1025),
    "new delhi": (28.6139, 77.2090),
    "gurugram": (28.4595, 77.0266),
    "gurgaon": (28.4595, 77.0266),
    "hyderabad": (17.3850, 78.4867),
    "pune": (18.5204, 73.8567),
    "chennai": (13.0827, 80.2707),
    "noida": (28.5355, 77.3910),
    "kolkata": (22.5726, 88.3639),
    "ahmedabad": (23.0225, 72.5714),
    "jaipur": (26.9124, 75.7873),
    "chandigarh": (30.7333, 76.7794),
    "lucknow": (26.8467, 80.9462),
    "jamtara": (23.9629, 86.8014),
    "deoghar": (24.4826, 86.6974),
    "giridih": (24.1903, 86.3006),
    "dhanbad": (23.7957, 86.4304),
    "bokaro": (23.6693, 86.1511),
    "siwan": (26.2200, 84.3600),
    "mewat": (28.1000, 77.0500),
    "nuh": (28.1100, 77.0100),
    "bharatpur": (27.2173, 77.4895),
    "mathura": (27.4924, 77.6737),
    "karnal": (29.6857, 76.9905),
}


def haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate the great-circle distance between two points on the Earth in km."""
    r_earth = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = math.sin(delta_phi / 2.0)**2 + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0)**2
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return round(r_earth * c, 1)


def get_city_coords(city_name: str) -> Optional[Tuple[float, float]]:
    """Look up coordinates for a city name, tolerating partial strings."""
    if not city_name:
        return None
    name_clean = re.sub(r"[^a-zA-Z\s]", "", city_name).lower().strip()
    for key, coords in CITY_COORDINATES.items():
        if key in name_clean or name_clean in key:
            return coords
    return None

# ── Risky UPI payment apps (prepaid/wallet heavy) ───────────────────────────
RISKY_UPI_HANDLES = [
    "ybl",   # PhonePe – widely abused
    "ibl",   # PhonePe
    "axl",   # Airtel
    "ptyes", # Paytm Yes Bank
    "wahed",
    "rbl",
    "fbl",   # Federal Bank / wallets
]

# ── Mock IFSC data for offline fallback ──────────────────────────────────────
MOCK_IFSC_DB: Dict[str, Dict] = {
    "SBIN0001234": {
        "BANK": "State Bank of India", "BRANCH": "Jamtara Main",
        "CITY": "Jamtara", "STATE": "Jharkhand",
        "ADDRESS": "Main Road, Jamtara, JH", "CONTACT": "0657-000000",
    },
    "HDFC0009876": {
        "BANK": "HDFC Bank", "BRANCH": "Bengaluru Koramangala",
        "CITY": "Bengaluru", "STATE": "Karnataka",
        "ADDRESS": "100 Ft Road, Koramangala, Bengaluru", "CONTACT": "080-123456",
    },
    "ICIC0005555": {
        "BANK": "ICICI Bank", "BRANCH": "Deoghar",
        "CITY": "Deoghar", "STATE": "Jharkhand",
        "ADDRESS": "Station Road, Deoghar, JH", "CONTACT": "06432-000000",
    },
}


def extract_ifsc_codes(text: str) -> List[str]:
    """Extract all IFSC codes from raw text."""
    return list(set(IFSC_PATTERN.findall(text)))


def extract_upi_handles(text: str) -> List[str]:
    """Extract all UPI IDs from raw text."""
    handles = UPI_PATTERN.findall(text)
    # Filter obvious non-UPI email-like patterns
    return list({h for h in handles if "@" in h and not h.endswith(".com")})


def lookup_ifsc(code: str, timeout: int = 5) -> Dict[str, Any]:
    """
    Fetch IFSC details from Razorpay public API.
    Falls back to mock data if offline or rate-limited.
    """
    # Try live API
    try:
        url = RAZORPAY_IFSC_URL.format(code=code)
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "BANK":    data.get("BANK", "Unknown"),
                "BRANCH":  data.get("BRANCH", "Unknown"),
                "CITY":    data.get("CITY", "Unknown"),
                "STATE":   data.get("STATE", "Unknown"),
                "ADDRESS": data.get("ADDRESS", ""),
                "CONTACT": data.get("CONTACT", ""),
                "source":  "live",
            }
    except Exception:
        pass

    # Fallback: check mock DB
    if code in MOCK_IFSC_DB:
        result = dict(MOCK_IFSC_DB[code])
        result["source"] = "mock"
        return result

    # Generic fallback
    return {
        "BANK": "Unknown Bank", "BRANCH": "Unknown Branch",
        "CITY": "Unknown", "STATE": "Unknown",
        "ADDRESS": "", "CONTACT": "", "source": "not_found",
    }


def assess_banking_risk(
    text: str,
    claimed_hq: str = "",
) -> Dict[str, Any]:
    """
    Full banking risk assessment from document text.

    Returns:
        dict with keys: ifsc_codes, upi_handles, ifsc_details,
                        risk_score, flags, mule_cities_detected.
    """
    ifsc_codes   = extract_ifsc_codes(text)
    upi_handles  = extract_upi_handles(text)
    ifsc_details: Dict[str, Dict] = {}
    flags:        List[str] = []
    risk_score    = 0
    mule_cities:  List[str] = []

    # ── Analyse each IFSC ──────────────────────────────────────────────────
    for code in ifsc_codes[:5]:  # cap at 5 to avoid rate-limiting
        info = lookup_ifsc(code)
        ifsc_details[code] = info

        city  = info.get("CITY", "").lower()
        state = info.get("STATE", "").lower()

        # Mule hotspot check
        for hotspot, bump in MULE_HOTSPOTS.items():
            if hotspot in city or hotspot in state:
                risk_score += bump
                mule_cities.append(info["CITY"])
                flags.append(
                    f"[MULE HUB DETECTED] IFSC {code} -> {info['BANK']}, {info['CITY']}, {info['STATE']} "
                    f"— Known mule-account hub."
                )
                break

        # HQ mismatch check
        if claimed_hq:
            hq_lower = claimed_hq.lower()
            if hq_lower in LEGIT_HQ_CITIES and city not in LEGIT_HQ_CITIES:
                risk_score += 20
                flags.append(
                    f"[LOCATION MISMATCH] Company claims HQ in '{claimed_hq}' but payment goes to "
                    f"{info['CITY']}, {info['STATE']} — routing discrepancy."
                )

    # ── Analyse UPI handles ───────────────────────────────────────────────
    risky_upi: List[str] = []
    for handle in upi_handles:
        suffix = handle.split("@")[-1].lower() if "@" in handle else ""
        for risky in RISKY_UPI_HANDLES:
            if suffix == risky:
                risky_upi.append(handle)
                risk_score += 15
                break

    if risky_upi:
        flags.append(f"[HIGH RISK WALLET] Suspicious UPI wallet handles: {', '.join(risky_upi)}")

    # ── Multiple payment methods = extra risk ─────────────────────────────
    if len(ifsc_codes) > 1:
        risk_score += 10
        flags.append(f"[PAYMENT SYNDICATE] Multiple IFSC codes ({len(ifsc_codes)}) detected.")

    if len(upi_handles) > 2:
        risk_score += 10
        flags.append(f"[PAYMENT SYNDICATE] Multiple UPI handles ({len(upi_handles)}) detected.")

    # No payment methods found in an offer letter is suspicious too
    if not ifsc_codes and not upi_handles:
        flags.append("[INFO] No payment identifiers detected in document.")

    risk_score = min(100, risk_score)

    return {
        "ifsc_codes":          ifsc_codes,
        "upi_handles":         upi_handles,
        "ifsc_details":        ifsc_details,
        "risk_score":          risk_score,
        "flags":               flags,
        "mule_cities_detected": list(set(mule_cities)),
        "risky_upi_handles":   risky_upi,
    }


def resolve_banking_route(
    text: str,
    claimed_hq: str = "",
    ifsc_details: Optional[Dict[str, Dict]] = None,
) -> Dict[str, Any]:
    """
    Computes distance and route anomalies between Claimed Corporate HQ
    and the actual geolocated bank branch derived from document IFSC codes.
    """
    if ifsc_details is None:
        codes = extract_ifsc_codes(text)
        ifsc_details = {c: lookup_ifsc(c) for c in codes[:5]}

    if not ifsc_details:
        return {
            "has_route": False,
            "claimed_hq": claimed_hq or "Unspecified",
            "bank_name": "No Payment Rails Detected",
            "bank_branch": "--",
            "bank_city": "--",
            "bank_state": "--",
            "ifsc_code": "--",
            "distance_km": None,
            "is_anomaly": False,
            "is_mule": False,
            "route_status": "[NO PAYMENT RAILS DETECTED]",
            "route_summary": f"Claimed HQ: {claimed_hq or 'Unspecified'} — No destination bank account identified.",
        }

    first_code = list(ifsc_details.keys())[0]
    info = ifsc_details[first_code]
    bank_city = info.get("CITY", "Unknown")
    bank_state = info.get("STATE", "Unknown")
    bank_name = info.get("BANK", "Unknown Bank")
    bank_branch = info.get("BRANCH", "Unknown Branch")

    city_lower = bank_city.lower()
    is_mule = any(h in city_lower for h in MULE_HOTSPOTS)

    claimed_coords = get_city_coords(claimed_hq) if claimed_hq else None
    bank_coords = get_city_coords(bank_city)

    distance_km = None
    if claimed_coords and bank_coords:
        distance_km = haversine_distance_km(
            claimed_coords[0], claimed_coords[1],
            bank_coords[0], bank_coords[1],
        )

    is_anomaly = False
    if is_mule:
        is_anomaly = True
    elif distance_km is not None and distance_km > 120:
        is_anomaly = True

    if is_mule and distance_km:
        route_status = f"[CRITICAL MISMATCH] {int(distance_km)} km discrepancy to flagged mule hub ({bank_city})"
    elif is_mule:
        route_status = f"[CRITICAL MULE HUB] Routed to known cybercrime mule corridor ({bank_city})"
    elif distance_km and distance_km > 120:
        route_status = f"[SUSPICIOUS ROUTE] {int(distance_km)} km distance discrepancy from claimed HQ ({claimed_hq})"
    elif distance_km is not None:
        route_status = f"[VERIFIED ROUTE] Bank branch ({bank_city}) is proximate to claimed HQ ({int(distance_km)} km)"
    else:
        route_status = f"[UNVERIFIED ORIGIN] Payment routed to {bank_city}, {bank_state}"

    return {
        "has_route": True,
        "claimed_hq": claimed_hq or "Unspecified HQ",
        "bank_name": bank_name,
        "bank_branch": bank_branch,
        "bank_city": bank_city,
        "bank_state": bank_state,
        "ifsc_code": first_code,
        "distance_km": distance_km,
        "is_anomaly": is_anomaly,
        "is_mule": is_mule,
        "route_status": route_status,
        "route_summary": f"Claimed HQ: {claimed_hq or 'Unspecified'} → Destination: {bank_name} ({bank_city}, {bank_state})",
    }

