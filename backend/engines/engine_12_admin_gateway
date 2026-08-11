"""
Engine 12 — Admin Approval & Workflow Gateway Engine
AMG DataOps Cloud

Design principles:
  - Holds pre-processed payloads in PENDING_ADMIN_APPROVAL state.
  - Admin gateway authorization (Approve / Edit / Reject).
  - Secure job state management before client notification.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Dict, Any, Optional, List

logger = logging.getLogger("engine12")


class JobStatus:
    PENDING_APPROVAL = "PENDING_ADMIN_APPROVAL"
    APPROVED = "APPROVED_WAITING_PAYMENT"
    REJECTED = "REJECTED_BY_ADMIN"
    COMPLETED = "COMPLETED_AND_DELIVERED"


@dataclass
class CleaningJobRequest:
    job_id: str
    tenant_id: str
    records_count: int
    cleaned_payload: List[Dict[str, Any]]
    report: Dict[str, Any]
    status: str = JobStatus.PENDING_APPROVAL
    admin_notes: Optional[str] = None


class AdminGatewayRegistry:
    """In-memory thread-safe registry for jobs awaiting admin approval."""

    def __init__(self):
        self._jobs: Dict[str, CleaningJobRequest] = {}

    def create_job(self, tenant_id: str, records: List[Dict[str, Any]], report: Dict[str, Any]) -> str:
        job_id = f"job_{uuid.uuid4().hex[:10]}"
        job = CleaningJobRequest(
            job_id=job_id,
            tenant_id=tenant_id,
            records_count=len(records),
            cleaned_payload=records,
            report=report,
            status=JobStatus.PENDING_APPROVAL
        )
        self._jobs[job_id] = job
        return job_id

    def get_job(self, job_id: str) -> Optional[CleaningJobRequest]:
        return self._jobs.get(job_id)

    def update_job_payload(self, job_id: str, updated_records: List[Dict[str, Any]]) -> bool:
        job = self._jobs.get(job_id)
        if job:
            job.cleaned_payload = updated_records
            job.records_count = len(updated_records)
            return True
        return False

    def approve_job_by_admin(self, job_id: str, notes: str = "Approved by Admin") -> bool:
        job = self._jobs.get(job_id)
        if job and job.status == JobStatus.PENDING_APPROVAL:
            job.status = JobStatus.APPROVED
            job.admin_notes = notes
            return True
        return False

    def reject_job_by_admin(self, job_id: str, reason: str = "Rejected by Admin") -> bool:
        job = self._jobs.get(job_id)
        if job:
            job.status = JobStatus.REJECTED
            job.admin_notes = reason
            return True
        return False

    def list_pending_jobs(self) -> List[Dict[str, Any]]:
        return [
            {
                "job_id": job.job_id,
                "tenant_id": job.tenant_id,
                "records_count": job.records_count,
                "status": job.status,
                "quality_score": job.report.get("quality_score", 100)
            }
            for job in self._jobs.values()
            if job.status == JobStatus.PENDING_APPROVAL
        ]


_GLOBAL_ADMIN_REGISTRY = AdminGatewayRegistry()


def run_engine_12(
    action: str,
    job_id: Optional[str] = None,
    tenant_id: str = "default_tenant",
    cleaned_records: Optional[List[Dict[str, Any]]] = None,
    report: Optional[Dict[str, Any]] = None,
    notes: Optional[str] = None,
    registry: Optional[AdminGatewayRegistry] = None
) -> Dict[str, Any]:
    """
    Main Pipeline Wrapper for Engine 12.
    Actions: 'CREATE_JOB', 'APPROVE_JOB', 'REJECT_JOB', 'UPDATE_PAYLOAD', 'LIST_PENDING'
    """
    reg = registry or _GLOBAL_ADMIN_REGISTRY

    if action == "CREATE_JOB":
        new_job_id = reg.create_job(tenant_id, cleaned_records or [], report or {})
        return {
            "engine": "Engine 12 - Admin Approval Gateway",
            "action": "CREATE_JOB",
            "job_id": new_job_id,
            "status": JobStatus.PENDING_APPROVAL,
            "message": "Data pre-calculated and sent to Admin Dashboard for review."
        }

    elif action == "APPROVE_JOB" and job_id:
        success = reg.approve_job_by_admin(job_id, notes or "Approved by Admin")
        return {
            "engine": "Engine 12 - Admin Approval Gateway",
            "action": "APPROVE_JOB",
            "job_id": job_id,
            "approved": success,
            "new_status": JobStatus.APPROVED if success else "JOB_NOT_FOUND"
        }

    elif action == "REJECT_JOB" and job_id:
        success = reg.reject_job_by_admin(job_id, notes or "Rejected")
        return {
            "engine": "Engine 12 - Admin Approval Gateway",
            "action": "REJECT_JOB",
            "job_id": job_id,
            "rejected": success,
            "new_status": JobStatus.REJECTED if success else "JOB_NOT_FOUND"
        }

    elif action == "UPDATE_PAYLOAD" and job_id and cleaned_records is not None:
        updated = reg.update_job_payload(job_id, cleaned_records)
        return {
            "engine": "Engine 12 - Admin Approval Gateway",
            "action": "UPDATE_PAYLOAD",
            "job_id": job_id,
            "updated": updated
        }

    elif action == "LIST_PENDING":
        pending_list = reg.list_pending_jobs()
        return {
            "engine": "Engine 12 - Admin Approval Gateway",
            "action": "LIST_PENDING",
            "count": len(pending_list),
            "jobs": pending_list
        }

    return {"error": "Invalid action specified for Engine 12"}
