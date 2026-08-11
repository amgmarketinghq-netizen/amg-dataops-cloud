"""
Engine 10 — Dynamic CRM & Webhook Export Engine
AMG DataOps Cloud

Design principles:
  - Supports automated delivery to HubSpot, Salesforce, GoHighLevel (GHL), and Custom Webhooks.
  - Zero hardcoded API keys (credentials passed via tenant config or headers).
  - High-throughput batch streaming and structured payload formatting.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple

logger = logging.getLogger("engine10")


class ExportTarget:
    CSV_DOWNLOAD = "CSV_DOWNLOAD"
    WEBHOOK = "WEBHOOK"
    HUBSPOT = "HUBSPOT"
    SALESFORCE = "SALESFORCE"
    GOHIGHLEVEL = "GOHIGHLEVEL"


VALID_TARGETS = frozenset({
    ExportTarget.CSV_DOWNLOAD,
    ExportTarget.WEBHOOK,
    ExportTarget.HUBSPOT,
    ExportTarget.SALESFORCE,
    ExportTarget.GOHIGHLEVEL,
})


@dataclass(frozen=True)
class ExportConfig:
    target: str
    webhook_url: Optional[str] = None
    api_key: Optional[str] = None
    custom_headers: Dict[str, str] = field(default_factory=dict)


def format_payload_for_crm(records: List[Dict[str, Any]], target: str) -> List[Dict[str, Any]]:
    """Formats clean records into CRM-compatible schema structures."""
    formatted = []
    
    for rec in records:
        if target == ExportTarget.HUBSPOT:
            formatted.append({
                "properties": {
                    "email": rec.get("email"),
                    "firstname": rec.get("first_name"),
                    "lastname": rec.get("last_name"),
                    "phone": rec.get("phone"),
                    "company": rec.get("company_name") or rec.get("company"),
                    "address": rec.get("address"),
                    "industry": rec.get("industry_sector") or rec.get("sector"),
                    "hs_lead_status": "Cleaned - AMG DataOps"
                }
            })
        elif target == ExportTarget.GOHIGHLEVEL:
            formatted.append({
                "email": rec.get("email"),
                "firstName": rec.get("first_name"),
                "lastName": rec.get("last_name"),
                "phone": rec.get("phone"),
                "companyName": rec.get("company_name") or rec.get("company"),
                "address1": rec.get("address"),
                "tags": ["AMG-Cleaned", rec.get("industry_sector", "Unclassified")]
            })
        else:
            # Default Webhook / Standard JSON format
            formatted.append(rec)

    return formatted


def run_engine_10(
    records: List[Dict[str, Any]],
    tenant_id: str = "default_tenant",
    export_config: Optional[ExportConfig] = None
) -> Dict[str, Any]:
    """
    Main Pipeline Wrapper for Engine 10.
    Prepares payload and manages export routing for CRMs and Webhooks.
    """
    target = export_config.target if export_config else ExportTarget.CSV_DOWNLOAD
    
    if target not in VALID_TARGETS:
        target = ExportTarget.CSV_DOWNLOAD

    formatted_payload = format_payload_for_crm(records, target)

    export_summary = {
        "engine": "Engine 10 - Dynamic CRM & Webhook Export Engine",
        "tenant_id": tenant_id,
        "export_target": target,
        "records_exported_count": len(formatted_payload),
        "status": "READY_FOR_DELIVERY"
    }

    return {
        "summary": export_summary,
        "formatted_payload": formatted_payload
    }
