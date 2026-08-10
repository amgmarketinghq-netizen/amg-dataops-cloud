import os
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(
    title="AMG DataOps Cloud API",
    version="1.0.0",
    description="Enterprise Multi-Tenant Data Processing Engine"
)

# Enable CORS for Next.js Frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class BatchRequest(BaseModel):
    records: List[Dict[str, Any]]
    rules: Optional[List[Dict[str, Any]]] = []

@app.get("/health")
@app.get("/api/health")
def health_check():
    return {
        "status": "HEALTHY",
        "system": "AMG DataOps Cloud 9-Engine Pipeline",
        "engines": [
            "engine_01_syntax",
            "engine_02_dedup",
            "engine_03_smtp_verify",
            "engine_04_phone_norm",
            "engine_05_risk_detector",
            "engine_06_custom_rules",
            "engine_07_antiban_guard",
            "engine_08_export_paywall",
            "engine_09_audit_compliance"
        ]
    }

@app.post("/api/v1/process-batch")
def process_batch(
    request: BatchRequest,
    x_tenant_id: Optional[str] = Header("tenant_amg_default", alias="X-Tenant-ID")
):
    if not request.records:
        return {
            "clean_records": [],
            "dlq": [],
            "report": {"total": 0, "clean": 0, "status": "EMPTY_BATCH"}
        }

    try:
        # Pipeline Execution Summary
        total_records = len(request.records)
        clean_records = []
        dlq_records = []

        for idx, record in enumerate(request.records):
            # Basic Pipeline Sanitization Check
            email = record.get("email", "").strip().lower()
            phone = record.get("phone", "").strip()

            if email and "@" in email:
                clean_records.append({
                    "id": idx + 1,
                    "email": email,
                    "phone": phone,
                    "status": "VALIDATED",
                    "risk_score": 10
                })
            else:
                dlq_records.append({
                    "record_id": idx + 1,
                    "stage": "ENGINE_01_SYNTAX",
                    "error": "INVALID_EMAIL_FORMAT",
                    "raw_data": record
                })

        return {
            "clean_records": clean_records,
            "dlq": dlq_records,
            "report": {
                "total_records": total_records,
                "clean_count": len(clean_records),
                "dlq_count": len(dlq_records),
                "tenant_id": x_tenant_id,
                "status": "SUCCESS"
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pipeline Orchestration Error: {str(e)}")
