import re
from typing import Dict, Any

def format_e164(phone_raw: str, default_country_code: str = "1") -> Dict[str, Any]:
    """
    Cleans punctuation and formats raw phone numbers toward E.164 international standard.
    Removes spaces, dashes, brackets, and non-numeric characters.
    """
    if not phone_raw or not isinstance(phone_raw, str):
        return {"is_valid": False, "formatted_phone": "", "line_type": "UNKNOWN"}

    # Strip non-digit characters except leading plus
    digits_only = re.sub(r'[^\d+]', '', phone_raw.strip())
    
    if not digits_only:
        return {"is_valid": False, "formatted_phone": "", "line_type": "UNKNOWN"}

    # Handle standard lengths
    if digits_only.startswith('+'):
        e164_phone = digits_only
    elif len(digits_only) == 10:
        # Standard 10-digit number without country code
        e164_phone = f"+{default_country_code}{digits_only}"
    elif len(digits_only) == 11 and digits_only.startswith('1'):
        # US/North America with country code 1
        e164_phone = f"+{digits_only}"
    elif len(digits_only) == 12 and digits_only.startswith('91'):
        # India with country code 91
        e164_phone = f"+{digits_only}"
    else:
        e164_phone = f"+{digits_only}"

    # Basic length validation (E.164 numbers are between 8 and 15 digits)
    digit_count = len(re.sub(r'\D', '', e164_phone))
    is_valid = 8 <= digit_count <= 15

    # Heuristic Line Type Detection
    line_type = "POSSIBLE_MOBILE" if is_valid else "INVALID_LENGTH"

    return {
        "is_valid": is_valid,
        "formatted_phone": e164_phone if is_valid else digits_only,
        "line_type": line_type
    }

def process_engine_04(row: dict) -> dict:
    """
    Main Execution Function for Engine 04.
    Normalizes phone fields in lead rows.
    """
    processed_row = row.copy()
    raw_phone = processed_row.get('phone', '')

    if raw_phone:
        phone_data = format_e164(str(raw_phone))
        processed_row['phone'] = phone_data['formatted_phone']
        processed_row['is_phone_valid'] = phone_data['is_valid']
        processed_row['phone_line_type'] = phone_data['line_type']
    else:
        processed_row['is_phone_valid'] = False
        processed_row['phone_line_type'] = "MISSING"

    processed_row['engine_04_processed'] = True
    return processed_row
