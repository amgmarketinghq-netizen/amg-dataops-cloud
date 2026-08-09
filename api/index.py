from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from backend.pipeline import run_dataops_pipeline

app = FastAPI(
    title="AMG DataOps Cloud API",
    description="Enterprise Multi-Tenant Data Quality & Verification Engine",
    version="1.0.0",
    docs_url="/docs",
    openapi_url="/openapi.json"
)

# Request Schema
class ProcessBatchRequest(BaseModel):
    tenant_id: str
    user_id: Optional[str] = "API_USER"
    is_master_client: Optional[bool] = False
    has_sufficient_credits: Optional[bool] = False
    custom_rules: Optional[List[Dict[str, Any]]] = None
    records: List[Dict[str, Any]]

# Multi-route support for Vercel
@app.get("/")
@app.get("/api")
@app.get("/api/index.py")
def health_check():
    """System Health Endpoint."""
    return {
        "status": "ONLINE",
        "system": "AMG DataOps Cloud API",
        "version": "1.0.0"
    }

# Multi-route support for Process Endpoint
@app.post("/api/v1/process")
@app.post("/process")
def process_lead_batch(payload: ProcessBatchRequest):
    """
    Main Execution Endpoint.
    Receives raw CSV/JSON records and runs all 9 DataOps engines sequentially.
    """
    if not payload.records:
        raise HTTPException(status_code=400, detail="Record payload cannot be empty.")

    try:
        results = run_dataops_pipeline(
            raw_records=payload.records,
            tenant_id=payload.tenant_id,
            user_id=payload.user_id,
            is_master_client=payload.is_master_client,
            has_sufficient_credits=payload.has_sufficient_credits,
            custom_rules=payload.custom_rules
        )
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pipeline Execution Failed: {str(e)}")
