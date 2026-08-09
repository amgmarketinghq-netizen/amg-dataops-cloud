import re
from typing import List, Dict, Any

def mask_email(email: str) -> str:
    """Masks email address for unpaid preview mode (e.g., h****r@domain.com)."""
    if not email or '@' not in email:
        return "****@****.com"
    
    local_part, domain = email.split('@', 1)
    if len(local_part) <= 2:
        masked_local = local_part[0] + "*"
    else:
        masked_local = local_part[0] + "*" * (len(local_part) - 2) + local_part[-1]
        
    return f"{masked_local}@{domain}"

def mask_phone(phone: str) -> str:
    """Masks phone number for unpaid preview mode (e.g., +91 *****-5678)."""
    if not phone or len(phone) < 6:
        return "+** *****-****"
    
    return phone[:3] + " *" * (len(phone) - 7) + phone[-4:]

def apply_paywall_masking(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Applies data masking to sensitive lead fields for blurred/locked preview mode."""
    masked_records = []
    for row in records:
        masked_row = row.copy()
        if 'email' in masked_row and masked_row['email']:
            masked_row['email'] = mask_email(str(masked_row['email']))
        if 'phone' in masked_row and masked_row['phone']:
            masked_row['phone'] = mask_phone(str(masked_row['phone']))
        masked_row['is_preview_masked'] = True
        masked_records.append(masked_row)
    return masked_records

def process_engine_08(
    records: List[Dict[str, Any]], 
    is_master_client: bool = False, 
    has_sufficient_credits: bool = False
) -> Dict[str, Any]:
    """
    Main Execution Function for Engine 08.
    Evaluates Master Client status and credit balance to grant full access or masked preview.
    """
    # 1. Check Master VIP Override or Credit Clearance
    if is_master_client or has_sufficient_credits:
        # Full Unlocked Access
        return {
            "is_unlocked": True,
            "delivery_type": "MASTER_UNLOCKED" if is_master_client else "CREDIT_UNLOCKED",
            "records": records,
            "total_records": len(records),
            "engine_08_processed": True
        }
    
    # 2. Unpaid/Free User -> Return Paywall Masked Sample
    masked_sample = apply_paywall_masking(records[:5])  # Show max 5 masked rows
    return {
        "is_unlocked": False,
        "delivery_type": "MASKED_PREVIEW_LOCK",
        "records": masked_sample,
        "total_records": len(records),
        "locked_records_count": max(0, len(records) - len(masked_sample)),
        "engine_08_processed": True
    }
