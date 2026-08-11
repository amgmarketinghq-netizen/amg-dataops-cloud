import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional

# Multi-environment fallback imports matching exact engine filenames
try:
    from engines.engine_09_orchestrator import run_pipeline_orchestrator, PipelineConfig
    from engines.engine_07_throttling import TenantBucketRegistry
    from engines.engine_10_crm_export import run_engine_10, ExportConfig
    from engines.engine_11_metering import run_engine_11
except ImportError:
    try:
        from backend.engines.engine_09_orchestrator import run_pipeline_orchestrator, PipelineConfig
        from backend.engines.engine_07_throttling import TenantBucketRegistry
        from backend.engines.engine_10_crm_export import run_engine_10, ExportConfig
        from backend.engines.engine_11_metering import run_engine_11
    except ImportError:
        from .engines.engine_09_orchestrator import run_pipeline_orchestrator, PipelineConfig
        from .engines.engine_07_throttling import TenantBucketRegistry
        from .engines.engine_10_crm_export import run_engine_10, ExportConfig
        from .engines.engine_11_metering import run_engine_11

app = FastAPI(title="AMG DataOps Cloud API", version="1.0.0")

# Shared In-Memory Bucket Registry
bucket_registry = TenantBucketRegistry()

class DataProcessRequest(BaseModel):
    tenant_id: str = "default_tenant"
    records: List[Dict[str, Any]]
    tenant_rules: Optional[List[Dict[str, Any]]] = []
    default_phone_region: Optional[str] = "IN"
    do_smtp_probe: Optional[bool] = False
    export_target: Optional[str] = "CSV_DOWNLOAD"

@app.get("/")
def health_check():
    return {"status": "online", "service": "AMG DataOps Cloud API v1.0"}

@app.post("/api/v1/process")
def process_batch(payload: DataProcessRequest):
    try:
        # 1. Billing & Credit Check (Engine 11)
        billing_res = run_engine_11(records_count=len(payload.records), tenant_id=payload.tenant_id)
        if not billing_res.get("billing_approved"):
            raise HTTPException(status_code=402, detail="Insufficient API credits for this tenant.")

        # 2. Main 9-Engine Processing Pipeline Execution
        raw_pepper = os.getenv("SERVER_PEPPER", "AMG_CLOUD_SECURE_PEPPER_KEY_32BYTES_LONG_MIN_SECRET")
        server_pepper = raw_pepper.encode("utf-8")[:32].ljust(32, b"0")

        config = PipelineConfig(
            server_pepper=server_pepper,
            bucket_registry=bucket_registry,
            tenant_rules=payload.tenant_rules or [],
            default_phone_region=payload.default_phone_region,
            do_smtp_probe=payload.do_smtp_probe
        )

        pipeline_result = run_pipeline_orchestrator(
            records=payload.records,
            tenant_id=payload.tenant_id,
            config=config
        )

        # 3. CRM & Webhook Export Formatting (Engine 10)
        export_config = ExportConfig(target=payload.export_target or "CSV_DOWNLOAD")
        export_res = run_engine_10(records=pipeline_result.clean_records, tenant_id=payload.tenant_id, export_config=export_config)

        return {
            "status": "success",
            "clean_records": export_res.get("formatted_payload"),
            "report": pipeline_result.report,
            "billing_summary": billing_res,
            "dlq_count": len(pipeline_result.dlq)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
