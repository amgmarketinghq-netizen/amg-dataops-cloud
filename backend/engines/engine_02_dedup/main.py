from difflib import SequenceMatcher
from typing import List, Dict, Any

def calculate_fuzzy_similarity(str1: str, str2: str) -> float:
    """Calculates string similarity ratio between 0.0 and 1.0."""
    if not str1 or not str2:
        return 0.0
    return SequenceMatcher(None, str1.lower().strip(), str2.lower().strip()).ratio()

def merge_survivor_records(master: Dict[str, Any], duplicate: Dict[str, Any]) -> Dict[str, Any]:
    """
    Survivorship Rule: Keeps master record data, but fills in missing 
    fields (like phone, website, LinkedIn) from the duplicate record.
    """
    merged = master.copy()
    for key, value in duplicate.items():
        # Fill missing or empty fields in master from duplicate
        if not merged.get(key) and value:
            merged[key] = value
    return merged

def process_engine_02(records: List[Dict[str, Any]], fuzzy_threshold: float = 0.88) -> Dict[str, Any]:
    """
    Main Execution Function for Engine 02.
    Performs Exact & Fuzzy Deduplication across a batch of lead records.
    """
    unique_records = []
    seen_emails = set()
    seen_phones = set()
    duplicate_count = 0

    for current in records:
        email = current.get('email', '').strip().lower()
        phone = current.get('phone', '').strip()
        
        # 1. Exact Match Check (Email or Phone)
        if email and email in seen_emails:
            duplicate_count += 1
            # Merge missing data into existing master record
            for idx, existing in enumerate(unique_records):
                if existing.get('email', '').strip().lower() == email:
                    unique_records[idx] = merge_survivor_records(existing, current)
                    break
            continue
            
        if phone and phone in seen_phones:
            duplicate_count += 1
            for idx, existing in enumerate(unique_records):
                if existing.get('phone', '').strip() == phone:
                    unique_records[idx] = merge_survivor_records(existing, current)
                    break
            continue

        # 2. Fuzzy Match Check (Company Name + Full Name similarity)
        is_fuzzy_duplicate = False
        current_company = current.get('company_name', '')
        current_name = f"{current.get('first_name', '')} {current.get('last_name', '')}".strip()

        if current_company and current_name:
            for idx, existing in enumerate(unique_records):
                existing_company = existing.get('company_name', '')
                existing_name = f"{existing.get('first_name', '')} {existing.get('last_name', '')}".strip()

                comp_sim = calculate_fuzzy_similarity(current_company, existing_company)
                name_sim = calculate_fuzzy_similarity(current_name, existing_name)

                # High probability fuzzy match threshold
                if comp_sim >= fuzzy_threshold and name_sim >= fuzzy_threshold:
                    duplicate_count += 1
                    unique_records[idx] = merge_survivor_records(existing, current)
                    is_fuzzy_duplicate = True
                    break

        if not is_fuzzy_duplicate:
            if email:
                seen_emails.add(email)
            if phone:
                seen_phones.add(phone)
            unique_records.append(current)

    return {
        "deduplicated_records": unique_records,
        "total_input": len(records),
        "duplicates_removed": duplicate_count,
        "engine_02_processed": True
    }
