import re
from typing import Dict, Any

def process_engine_01(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Engine 01: Syntax Normalization & Basic Cleaning
    """
    cleaned_record = record.copy()
    
    # Clean email
    if "email" in cleaned_record and isinstance(cleaned_record["email"], str):
        cleaned_record["email"] = cleaned_record["email"].strip().lower()
        
    # Clean phone (remove unwanted spaces/characters)
    if "phone" in cleaned_record and isinstance(cleaned_record["phone"], str):
        cleaned_record["phone"] = re.sub(r'[^\d+]', '', cleaned_record["phone"].strip())
        
    # Clean name
    if "name" in cleaned_record and isinstance(cleaned_record["name"], str):
        cleaned_record["name"] = cleaned_record["name"].strip().title()

    return cleaned_record
