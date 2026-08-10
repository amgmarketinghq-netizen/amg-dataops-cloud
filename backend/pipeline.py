import os
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv

load_dotenv()

# Import main orchestrator pipeline function
from backend.pipeline import run_dataops_pipeline

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
    user_id: Optional[str] = "SYSTEM_USER"
    is_master_client: Optional[bool] = False
    has_sufficient_credits: Optional[bool] = True
    custom_rules: Optional[List[Dict[str, Any]]] = None

@app.get("/health")
@app.get("/api/health")
def health_check():
    return {
        "status": "HEALTHY",
        "system": "AMG DataOps Cloud 9-Engine Pipeline Connected"
    }

@app.post("/api/v1/process-batch")
def process_batch(
    request: BatchRequest,
    x_tenant_id: Optional[str] = Header("tenant_amg_default", alias="X-Tenant-ID")
):
    if not request.records:
        return {"status": "EMPTY_BATCH", "records": [], "summary": {}}

    try:
        # Trigger full 9-engine pipeline from pipeline.py
        pipeline_result = run_dataops_pipeline(
            raw_records=request.records,
            tenant_id=x_tenant_id,
            user_id=request.user_id,
            is_master_client=request.is_master_client,
            has_sufficient_credits=request.has_sufficient_credits,
            custom_rules=request.custom_rules
        )
        return pipeline_result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pipeline Processing Error: {str(e)}")
