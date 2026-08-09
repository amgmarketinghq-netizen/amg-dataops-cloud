from typing import List, Dict, Any

# Import all 9 modular engines
from backend.engines.engine_01_syntax.main import process_engine_01
from backend.engines.engine_02_dedup.main import process_engine_02
from backend.engines.engine_03_smtp_verify.main import process_engine_03
from backend.engines.engine_04_phone_norm.main import process_engine_04
from backend.engines.engine_05_risk_detector.main import process_engine_05
from backend.engines.engine_06_custom_rules.main import process_engine_06
from backend.engines.engine_07_antiban_guard.main import process_engine_07
from backend.engines.engine_08_export_paywall.main import process_engine_08
from backend.engines.engine_09_audit_compliance.main import process_engine_09

def run_dataops_pipeline(
    raw_records: List[Dict[str, Any]],
    tenant_id: str,
    user_id: str = "SYSTEM_USER",
    is_master_client: bool = False,
    has_sufficient_credits: bool = False,
    custom_rules: List[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Main DataOps Orchestrator.
    Executes Engines 01 through 09 sequentially on uploaded data batches.
    """
    if not raw_records:
        return {"status": "EMPTY_BATCH", "records": [], "summary": {}}

    processed_batch = []

    # --- PHASE 1: Row-by-Row Cleansing (Engines 01, 03, 04, 05, 06) ---
    for row in raw_records:
        # Engine 01: Syntax Normalization
        step1 = process_engine_01(row)
        
        # Engine 03: DNS/MX Deliverability Verification
        step3 = process_engine_03(step1)
        
        # Engine 04: Phone E.164 Formatting
        step4 = process_engine_04(step3)
        
        # Engine 05: Risk & Spam Trap Detection
        step5 = process_engine_05(step4)
        
        # Engine 06: Tenant Custom Rules Evaluation
        step6 = process_engine_06(step5, tenant_rules=custom_rules)
        
        processed_batch.append(step6)

    # --- PHASE 2: Batch-Level Operations (Engine 02: Deduplication) ---
    dedup_output = process_engine_02(processed_batch)
    deduped_records = dedup_output["deduplicated_records"]

    # --- PHASE 3: Safety Guardrails (Engine 07: Anti-Ban Circuit Breaker) ---
    safety_output = process_engine_07(deduped_records)
    safe_records = safety_output["records"]

    # --- PHASE 4: Paywall & Access Control (Engine 08) ---
    export_output = process_engine_08(
        safe_records, 
        is_master_client=is_master_client, 
        has_sufficient_credits=has_sufficient_credits
    )

    # --- PHASE 5: Audit Logging & Zero-Trust Compliance (Engine 09) ---
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
