import dns.resolver
from typing import Dict, Any

def check_domain_dns(domain: str) -> Dict[str, Any]:
    """Checks if a domain has valid MX (Mail Exchange) records."""
    if not domain:
        return {"has_mx": False, "mx_records": []}
    
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_list = [str(mx.exchange).rstrip('.') for mx in mx_records]
        return {
            "has_mx": len(mx_list) > 0,
            "mx_records": mx_list
        }
    except Exception:
        return {"has_mx": False, "mx_records": []}

def classify_email_deliverability(email: str, dns_result: Dict[str, Any]) -> Dict[str, Any]:
    if not email or '@' not in email:
        return {
            "status": "INVALID",
            "confidence": 0.0,
            "reason": "Malformed email format"
        }
        
    local_part, domain = email.split('@', 1)
    
    if not dns_result.get("has_mx"):
        return {
            "status": "INVALID",
            "confidence": 0.95,
            "reason": "No valid MX records found for domain"
        }
        
    disposable_domains = ['tempmail.com', 'throwawaymail.com', '10minutemail.com', 'trashmail.com']
    if domain in disposable_domains:
        return {
            "status": "RISKY",
            "confidence": 0.90,
            "reason": "Disposable/Temporary mail provider"
        }

    return {
        "status": "VERIFIED",
        "confidence": 0.85,
        "reason": "Active MX infrastructure present, syntax valid",
        "mx_servers": dns_result.get("mx_records", [])
    }

def process_engine_03(row: dict) -> dict:
    """Main Execution Function for Engine 03."""
    processed_row = row.copy()
    email = processed_row.get('email', '').strip().lower()
    
    if not email:
        processed_row['verification_status'] = 'EMPTY'
        processed_row['verification_confidence'] = 0.0
        return processed_row
        
    domain = email.split('@')[1] if '@' in email else ''
    dns_data = check_domain_dns(domain)
    verification_result = classify_email_deliverability(email, dns_data)
    
    processed_row['verification_status'] = verification_result['status']
    processed_row['verification_confidence'] = verification_result['confidence']
    processed_row['verification_reason'] = verification_result['reason']
    processed_row['engine_03_processed'] = True
    
    return processed_row
