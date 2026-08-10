import sys
import os
from typing import List, Dict, Any

# Ensure root import visibility
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

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
    if not raw_records:
        return {"status": "EMPTY_BATCH", "records": [], "summary": {}}

    processed_batch = []

    # PHASE 1: Cleansing
    for row in raw_records:
        step1 = process_engine_01(row)
        step3 = process_engine_03(step1)
        step4 = process_engine_04(step3)
        step5 = process_engine_05(step4)
        step6 = process_engine_06(step5, tenant_rules=custom_rules)
        processed_batch.append(step6)

    # PHASE 2: Deduplication (Engine 02)
    dedup_output = process_engine_02(processed_batch)
    deduped_records = dedup_output["deduplicated_records"]

    # PHASE 3: Anti-Ban (Engine 07)
    safety_output = process_engine_07(deduped_records)
    safe_records = safety_output["records"]

    # PHASE 4: Paywall (Engine 08)
    export_output = process_engine_08(
        safe_records, 
        is_master_client=is_master_client, 
        has_sufficient_credits=has_sufficient_credits
    )

    # PHASE 5: Audit (Engine 09)
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
