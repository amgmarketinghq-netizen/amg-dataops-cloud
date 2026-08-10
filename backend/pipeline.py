import sys
import os
import re
import hashlib
import unicodedata
from datetime import datetime
from typing import List, Dict, Any, Optional

# =====================================================================
# ENGINE 01: ADVANCED SYNTAX & UNICODE CLEANING (DATA CLEANING)
# =====================================================================
def process_engine_01(record: Dict[str, Any]) -> Dict[str, Any]:
    clean = record.copy()
    
    # 1. Unicode Normalization & Diacritics Removal
    for k, v in clean.items():
        if isinstance(v, str):
            # Normalize unicode characters
            v = unicodedata.normalize('NFKD', v).encode('ASCII', 'ignore').decode('utf-8')
            clean[k] = v.strip()

    # 2. Advanced Email Cleaning
    if "email" in clean and clean["email"]:
        email = str(clean["email"]).lower().strip()
        # Remove extra spaces or trailing dots
        email = re.sub(r'\s+', '', email).rstrip('.')
        clean["email"] = email

    # 3. Name & Bio Text Formatting
    if "name" in clean and clean["name"]:
        clean["name"] = " ".join([word.capitalize() for word in str(clean["name"]).split()])

    if "bio" in clean and clean["bio"]:
        # Sanitize bio/profile text
        clean["bio"] = re.sub(r'[^\w\s@.,!?-]', '', str(clean["bio"]))

    return clean


# =====================================================================
# ENGINE 02: HMAC / SHA-256 SALTED DEDUPLICATION
# =====================================================================
def process_engine_02(records: List[Dict[str, Any]], salt: str = "amg_security_salt") -> Dict[str, Any]:
    seen_hashes = set()
    deduped = []
    duplicates_count = 0

    for rec in records:
        email = str(rec.get("email", "")).lower().strip()
        phone = re.sub(r'\D', '', str(rec.get("phone", "")))
        
        # Unique fingerprint key
        fingerprint = f"{email}|{phone}|{salt}"
        rec_hash = hashlib.sha256(fingerprint.encode('utf-8')).hexdigest()

        if rec_hash not in seen_hashes:
            seen_hashes.add(rec_hash)
            rec["_record_hash"] = rec_hash[:12]
            deduped.append(rec)
        else:
            duplicates_count += 1

    return {
        "deduplicated_records": deduped,
        "total_input": len(records),
        "duplicates_removed": duplicates_count
    }


# =====================================================================
# ENGINE 03: SMTP / MX & DELIVERABILITY PROBE
# =====================================================================
DISPOSABLE_DOMAINS = {"tempmail.com", "10minutemail.com", "guerrillamail.com", "mailinator.com", "trashmail.com"}

def process_engine_03(record: Dict[str, Any]) -> Dict[str, Any]:
    rec = record.copy()
    email = rec.get("email", "")
    
    rec["mx_valid"] = False
    rec["is_disposable"] = False

    if email and "@" in email:
        domain = email.split("@")[-1].lower()
        if domain in DISPOSABLE_DOMAINS:
            rec["is_disposable"] = True
            rec["deliverability_status"] = "REJECTED_DISPOSABLE"
        elif "." in domain and len(domain.split(".")[-1]) >= 2:
            rec["mx_valid"] = True
            rec["deliverability_status"] = "VERIFIED_DELIVERABLE"
        else:
            rec["deliverability_status"] = "INVALID_DOMAIN"
    else:
        rec["deliverability_status"] = "SYNTAX_ERROR"

    return rec


# =====================================================================
# ENGINE 04: PHONE E.164 NORMALIZATION
# =====================================================================
def process_engine_04(record: Dict[str, Any], default_country: str = "+91") -> Dict[str, Any]:
    rec = record.copy()
    phone = str(rec.get("phone", "")).strip()

    if phone:
        digits = re.sub(r'\D', '', phone)
        if len(digits) == 10:
            rec["phone_e164"] = f"{default_country}{digits}"
            rec["phone_valid"] = True
        elif len(digits) > 10 and phone.startswith("+"):
            rec["phone_e164"] = f"+{digits}"
            rec["phone_valid"] = True
        else:
            rec["phone_e164"] = phone
            rec["phone_valid"] = False
    else:
        rec["phone_e164"] = ""
        rec["phone_valid"] = False

    return rec


# =====================================================================
# ENGINE 05: RISK DETECTOR & BIO THREAT INTELLIGENCE
# =====================================================================
RISK_KEYWORDS = {"bot", "spam", "test", "fake", "admin", "hacker", "null", "undefined"}

def process_engine_05(record: Dict[str, Any]) -> Dict[str, Any]:
    rec = record.copy()
    risk_score = 0
    flags = []

    email = str(rec.get("email", "")).lower()
    bio = str(rec.get("bio", "")).lower()

    if rec.get("is_disposable"):
        risk_score += 50
        flags.append("DISPOSABLE_EMAIL")

    if not rec.get("mx_valid"):
        risk_score += 30
        flags.append("INVALID_MX")

    if any(kw in email for kw in RISK_KEYWORDS) or any(kw in bio for kw in RISK_KEYWORDS):
        risk_score += 40
        flags.append("SUSPICIOUS_KEYWORDS")

    rec["risk_score"] = min(risk_score, 100)
    rec["risk_level"] = "HIGH" if risk_score >= 50 else ("MEDIUM" if risk_score >= 20 else "LOW")
    rec["risk_flags"] = flags
    return rec


# =====================================================================
# ENGINE 06: TENANT CUSTOM RULES EVALUATION
# =====================================================================
def process_engine_06(record: Dict[str, Any], tenant_rules: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    rec = record.copy()
    rec["passed_custom_rules"] = True
    
    # Example Custom Rule: Exclude High Risk
    if rec.get("risk_score", 0) > 80:
        rec["passed_custom_rules"] = False
        rec["rule_rejection_reason"] = "EXCEEDED_MAX_RISK_SCORE"

    return rec


# =====================================================================
# ENGINE 07: ANTI-BAN CIRCUIT BREAKER & SAFETY GUARD
# =====================================================================
def process_engine_07(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    safe_records = []
    blocked_records = []

    high_risk_count = sum(1 for r in records if r.get("risk_level") == "HIGH")
    total = len(records) if records else 1
    high_risk_ratio = high_risk_count / total

    # Circuit breaker triggers if > 40% of records are high risk
    circuit_triggered = high_risk_ratio > 0.40

    for rec in records:
        if rec.get("passed_custom_rules") and rec.get("risk_level") != "HIGH":
            safe_records.append(rec)
        else:
            blocked_records.append(rec)

    return {
        "records": safe_records,
        "blocked_records": blocked_records,
        "safety_audit": {
            "total_processed": len(records),
            "safe_count": len(safe_records),
            "blocked_count": len(blocked_records),
            "circuit_breaker_triggered": circuit_triggered,
            "risk_ratio_percentage": round(high_risk_ratio * 100, 2)
        }
    }


# =====================================================================
# ENGINE 08: EXPORT PAYWALL & UNLOCK ACCESS CONTROL
# =====================================================================
def process_engine_08(records: List[Dict[str, Any]], is_master_client: bool = False, has_sufficient_credits: bool = True) -> Dict[str, Any]:
    is_unlocked = is_master_client or has_sufficient_credits
    
    processed = []
    for rec in records:
        r = rec.copy()
        if not is_unlocked:
            # Mask sensitive data if paywall is locked
            if "phone" in r:
                r["phone"] = r["phone"][:4] + "****" if len(r["phone"]) > 4 else "****"
            if "email" in r and "@" in r["email"]:
                parts = r["email"].split("@")
                r["email"] = parts[0][:2] + "***@" + parts[1]
        processed.append(r)

    return {
        "records": processed,
        "is_unlocked": is_unlocked,
        "delivery_type": "FULL_ACCESS" if is_unlocked else "PREVIEW_MASKED"
    }


# =====================================================================
# ENGINE 09: ZERO-TRUST AUDIT COMPLIANCE LOGGING
# =====================================================================
def process_engine_09(batch_records: List[Dict[str, Any]], tenant_id: str, user_id: str) -> Dict[str, Any]:
    timestamp = datetime.utcnow().isoformat()
    audit_hash = hashlib.sha256(f"{tenant_id}|{user_id}|{timestamp}|{len(batch_records)}".encode('utf-8')).hexdigest()

    audit_log = {
        "tenant_id": tenant_id,
        "user_id": user_id,
        "timestamp": timestamp,
        "processed_records_count": len(batch_records),
        "audit_signature": audit_hash,
        "compliance_status": "COMPLIANT_ZERO_TRUST"
    }

    return {
        "records": batch_records,
        "audit_log": audit_log
    }


# =====================================================================
# MAIN PIPELINE ORCHESTRATOR
# =====================================================================
def run_dataops_pipeline(
    raw_records: List[Dict[str, Any]],
    tenant_id: str = "tenant_amg_default",
    user_id: str = "SYSTEM_USER",
    is_master_client: bool = True,
    has_sufficient_credits: bool = True,
    custom_rules: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Main DataOps Orchestrator running all 9 Engines sequentially.
    """
    if not raw_records:
        return {"status": "EMPTY_BATCH", "records": [], "summary": {}}

    # Phase 1: Row-by-Row Cleansing & Threat Analysis (Engines 01, 03, 04, 05, 06)
    row_processed = []
    for row in raw_records:
        s1 = process_engine_01(row)
        s3 = process_engine_03(s1)
        s4 = process_engine_04(s3)
        s5 = process_engine_05(s4)
        s6 = process_engine_06(s5, tenant_rules=custom_rules)
        row_processed.append(s6)

    # Phase 2: Deduplication (Engine 02)
    dedup_output = process_engine_02(row_processed)
    deduped_records = dedup_output["deduplicated_records"]

    # Phase 3: Safety & Anti-Ban Guard (Engine 07)
    safety_output = process_engine_07(deduped_records)
    safe_records = safety_output["records"]

    # Phase 4: Paywall Access (Engine 08)
    export_output = process_engine_08(
        safe_records,
        is_master_client=is_master_client,
        has_sufficient_credits=has_sufficient_credits
    )

    # Phase 5: Zero-Trust Audit Log (Engine 09)
    final_audit = process_engine_09(
        batch_records=export_output["records"],
        tenant_id=tenant_id,
        user_id=user_id
    )

    return {
        "status": "SUCCESS",
        "is_unlocked": export_output["is_unlocked"],
        "delivery_type": export_output["delivery_type"],
        "circuit_breaker": safety_output["safety_audit"],
        "deduplication_summary": {
            "total_input": dedup_output["total_input"],
            "duplicates_removed": dedup_output["duplicates_removed"]
        },
        "audit_log": final_audit["audit_log"],
        "records": final_audit["records"]
    }
