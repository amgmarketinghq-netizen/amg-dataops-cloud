import re
from typing import Dict, Any

# Generic role-based email prefixes that lower cold outreach response rates
ROLE_PREFIXES = {
    'info', 'support', 'admin', 'sales', 'billing', 'contact', 'jobs', 
    'careers', 'help', 'office', 'marketing', 'team', 'enquiries'
}

# High-risk/toxic disposable email domain list
DISPOSABLE_DOMAINS = {
    'tempmail.com', 'throwawaymail.com', '10minutemail.com', 'trashmail.com',
    'guerrillamail.com', 'sharklasers.com', 'mailinator.com', 'yopmail.com'
}

def analyze_email_risk(email: str) -> Dict[str, Any]:
    """
    Evaluates email against role-based account lists, disposable domains, 
    and spam-trap patterns.
    """
    if not email or '@' not in email:
        return {"is_high_risk": True, "risk_score": 1.0, "risk_flags": ["INVALID_FORMAT"]}

    local_part, domain = email.strip().lower().split('@', 1)
    risk_flags = []
    risk_score = 0.0

    # 1. Check for Role-Based Account
    if local_part in ROLE_PREFIXES:
        risk_flags.append("ROLE_BASED_ACCOUNT")
        risk_score += 0.40

    # 2. Check for Disposable Email Provider
    if domain in DISPOSABLE_DOMAINS:
        risk_flags.append("DISPOSABLE_DOMAIN")
        risk_score += 0.90

    # 3. Check for Spam Trap Heuristics (e.g., suspicious random strings or trap keywords)
    if re.search(r'(spam|trap|honeypot|abuse|spamcheck)', email, re.IGNORECASE):
        risk_flags.append("POTENTIAL_SPAM_TRAP")
        risk_score += 0.85

    # Determine final risk category
    is_high_risk = risk_score >= 0.50

    return {
        "is_high_risk": is_high_risk,
        "risk_score": round(min(risk_score, 1.0), 2),
        "risk_flags": risk_flags
    }

def process_engine_05(row: dict) -> dict:
    """
    Main Execution Function for Engine 05.
    Scans row email addresses for deliverability risks and toxic domain indicators.
    """
    processed_row = row.copy()
    email = processed_row.get('email', '')

    if email:
        risk_analysis = analyze_email_risk(str(email))
        processed_row['is_high_risk'] = risk_analysis['is_high_risk']
        processed_row['risk_score'] = risk_analysis['risk_score']
        processed_row['risk_flags'] = ",".join(risk_analysis['risk_flags']) if risk_analysis['risk_flags'] else "NONE"
    else:
        processed_row['is_high_risk'] = False
        processed_row['risk_score'] = 0.0
        processed_row['risk_flags'] = "EMPTY_EMAIL"

    processed_row['engine_05_processed'] = True
    return processed_row
