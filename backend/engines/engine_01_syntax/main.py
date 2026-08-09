import re
from urllib.parse import urlparse, parse_qs, urlunparse

# List of legal suffixes to clean from company names
LEGAL_SUFFIXES = [
    r'\binc\b', r'\bincORPORATED\b', r'\bllc\b', r'\bltd\b', r'\blimited\b',
    r'\bpvt ltd\b', r'\bgmbh\b', r'\bcorp\b', r'\bcorporation\b', r'\bco\b'
]

def clean_text(text: str) -> str:
    """Trims whitespace and applies Proper Title Casing."""
    if not text or not isinstance(text, str):
        return ""
    # Strip spaces and normalize internal spacing
    text = " ".join(text.split())
    return text.title()

def clean_company_name(name: str) -> str:
    """Cleans company names by removing legal suffixes like LLC, Inc, Pvt Ltd."""
    if not name or not isinstance(name, str):
        return ""
    
    cleaned = name.strip()
    # Remove legal suffixes (case-insensitive)
    for suffix in LEGAL_SUFFIXES:
        cleaned = re.sub(suffix, '', cleaned, flags=re.IGNORECASE)
    
    # Remove lingering trailing punctuation/spaces
    cleaned = re.sub(r'[,\.\-_\s]+$', '', cleaned)
    return clean_text(cleaned)

def clean_domain_or_url(url_str: str) -> str:
    """Strips tracking parameters (utm_*) and cleans URLs to bare domains."""
    if not url_str or not isinstance(url_str, str):
        return ""
    
    url_str = url_str.strip().lower()
    if not url_str.startswith(('http://', 'https://')):
        url_str = 'https://' + url_str
        
    try:
        parsed = urlparse(url_str)
        # Extract hostname domain
        domain = parsed.netloc.replace('www.', '')
        return domain
    except Exception:
        return url_str

def validate_email_syntax(email: str) -> bool:
    """Validates basic RFC email syntax via standard regex."""
    if not email or not isinstance(email, str):
        return False
    
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email.strip()))

def process_engine_01(row: dict) -> dict:
    """
    Main Execution Function for Engine 01.
    Processes a single lead row data dictionary and normalizes syntax.
    """
    cleaned_row = row.copy()
    
    # 1. Normalize Names & Text
    if 'first_name' in cleaned_row:
        cleaned_row['first_name'] = clean_text(cleaned_row['first_name'])
    if 'last_name' in cleaned_row:
        cleaned_row['last_name'] = clean_text(cleaned_row['last_name'])
    if 'company_name' in cleaned_row:
        cleaned_row['company_name'] = clean_company_name(cleaned_row['company_name'])
        
    # 2. Clean Domains & URLs
    if 'website' in cleaned_row:
        cleaned_row['website'] = clean_domain_or_url(cleaned_row['website'])
        
    # 3. Validate Email Syntax
    if 'email' in cleaned_row:
        raw_email = cleaned_row['email'].strip().lower() if cleaned_row['email'] else ""
        cleaned_row['email'] = raw_email
        cleaned_row['is_syntax_valid'] = validate_email_syntax(raw_email)
    else:
        cleaned_row['is_syntax_valid'] = False
        
    cleaned_row['engine_01_processed'] = True
    return cleaned_row
