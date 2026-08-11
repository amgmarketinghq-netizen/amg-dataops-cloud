"""
Engine 08 — Audit Trail, Compliance & Data Anonymization Engine
AMG DataOps Cloud

Design principles:
  - Cryptographic Tamper-Evident Audit Hash Chaining (SHA-256 + Merkle Root).
  - Canonical JSON serialization (sorted keys, fixed separators) preventing boundary-ambiguity collisions.
  - Two-layer HMAC key derivation (server_pepper + tenant_id) for pseudonymization & genesis hash.
  - GDPR/CCPA PII Redaction ([REDACTED] tombstone) & Pseudonymization.
  - Explicit compliance-safe projections preventing raw PII in audit payloads.
"""

from __future__ import annotations

import os
import hmac
import json
import time
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple

logger = logging.getLogger("engine08")


# =========================================================================
# 0. TYPED ERROR CODES & SAFETY CEILINGS
# =========================================================================

class ComplianceTag:
    SUCCESS = "SUCCESS"
    COMPLIANCE_HASH_ERROR = "COMPLIANCE_HASH_ERROR"
    REDACTION_FAILED = "REDACTION_FAILED"
    INVALID_ACTION_TYPE = "INVALID_ACTION_TYPE"
    OVERSIZED_BATCH = "OVERSIZED_BATCH"


MAX_RECORDS_PER_AUDIT_BATCH = 50_000
REDACTION_TOMBSTONE = "[REDACTED]"

VALID_ACTION_TYPES = frozenset({
    "DATA_INGESTION", "DATA_NORMALIZATION", "DATA_ENRICHMENT",
    "DATA_REDACTION", "DATA_EXPORT", "DATA_DELETION", "RULE_EVALUATION",
})

PII_ELIGIBLE_FIELDS: frozenset[str] = frozenset({
    "email", "phone", "contact_name", "first_name", "last_name", "address", "name",
})

# Fully synced metadata fields from Engines 01 to 07
SAFE_METADATA_FIELDS: frozenset[str] = frozenset({
    "sector", "industry_sector", "sector_confidence", "risk_score", "risk_tags",
    "is_disposable", "is_role_based", "is_catch_all", "has_mx_records", "is_duplicate",
    "is_disposable_email", "is_role_based_email", "is_voip_phone", "is_catch_all_domain",
    "line_type", "phone_line_type", "country_code", "phone_country_code", "routed_queue"
})


class ComplianceHashError(ValueError):
    pass


# =========================================================================
# 1. TENANT-SCOPED CRYPTOGRAPHIC CONTEXT
# =========================================================================

@dataclass(frozen=True)
class TenantComplianceContext:
    tenant_id: str
    _derived_key: bytes = field(init=False, repr=False)

    def __init__(self, tenant_id: str, server_pepper: bytes):
        if not tenant_id:
            raise ComplianceHashError("tenant_id is required")
        if not server_pepper or len(server_pepper) < 32:
            raise ComplianceHashError("server_pepper missing or too short (need >=32 bytes)")
        object.__setattr__(self, "tenant_id", tenant_id)
        derived = hmac.new(server_pepper, tenant_id.encode("utf-8"), hashlib.sha256).digest()
        object.__setattr__(self, "_derived_key", derived)

    def pseudonymize(self, value: str) -> str:
        return hmac.new(self._derived_key, value.encode("utf-8"), hashlib.sha256).hexdigest()

    def genesis_hash(self) -> str:
        return hmac.new(self._derived_key, f"GENESIS:{self.tenant_id}".encode("utf-8"), hashlib.sha256).hexdigest()


# =========================================================================
# 2. CANONICAL HASHING & MERKLE TREES
# =========================================================================

def canonical_json(obj: Any) -> bytes:
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str).encode("utf-8")
    except (TypeError, ValueError) as e:
        raise ComplianceHashError(f"payload not serializable: {e}")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_merkle_root(record_hashes: list) -> str:
    if not record_hashes:
        return sha256_hex(b"EMPTY_BATCH")
    level = list(record_hashes)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [sha256_hex((level[i] + level[i + 1]).encode("utf-8")) for i in range(0, len(level), 2)]
    return level[0]


# =========================================================================
# 3. PII REDACTION & PSEUDONYMIZATION
# =========================================================================

@dataclass(frozen=True)
class RedactionOutcome:
    sanitized_record: dict
    redacted_fields: tuple
    pseudonymized_fields: tuple
    failed_fields: tuple


def apply_pii_transformations(
    record: dict,
    ctx: TenantComplianceContext,
    redact_fields: Optional[frozenset] = None,
    pseudonymize_fields: Optional[frozenset] = None,
) -> RedactionOutcome:
    redact_fields = redact_fields or frozenset()
    pseudonymize_fields = pseudonymize_fields or frozenset()

    sanitized = dict(record)
    redacted_ok, pseudo_ok, failed = [], [], []

    for f in redact_fields:
        if f not in PII_ELIGIBLE_FIELDS:
            failed.append(f)
            continue
        if f not in sanitized or not isinstance(sanitized[f], str) or not sanitized[f]:
            failed.append(f)
            continue
        sanitized[f] = REDACTION_TOMBSTONE
        redacted_ok.append(f)

    for f in pseudonymize_fields:
        if f not in PII_ELIGIBLE_FIELDS or f in redacted_ok:
            failed.append(f)
            continue
        if f not in sanitized or not isinstance(sanitized[f], str) or not sanitized[f]:
            failed.append(f)
            continue
        try:
            sanitized[f] = ctx.pseudonymize(sanitized[f].lower().strip())
            pseudo_ok.append(f)
        except Exception:
            logger.exception("apply_pii_transformations: pseudonymization failed for field '%s'", f)
            failed.append(f)

    return RedactionOutcome(sanitized, tuple(redacted_ok), tuple(pseudo_ok), tuple(failed))


# =========================================================================
# 4. COMPLIANCE-SAFE AUDIT PROJECTION
# =========================================================================

def build_compliance_safe_projection(sanitized_record: dict, ctx: TenantComplianceContext) -> dict:
    projection = {}
    for f in PII_ELIGIBLE_FIELDS:
        value = sanitized_record.get(f)
        if isinstance(value, str) and value and value != REDACTION_TOMBSTONE:
            projection[f"{f}_hash"] = ctx.pseudonymize(value.lower().strip())
        elif value == REDACTION_TOMBSTONE:
            projection[f"{f}_hash"] = "REDACTED"
    for f in SAFE_METADATA_FIELDS:
        if f in sanitized_record:
            projection[f] = sanitized_record[f]
    return projection


# =========================================================================
# 5. AUDIT ENTRY SCHEMA & CHAIN COMPUTATION
# =========================================================================

@dataclass(frozen=True)
class AuditEntry:
    schema_version: int
    timestamp: float
    tenant_id: str
    batch_id: str
    action_type: str
    record_count: int
    payload_merkle_root: str
    prev_chain_hash: str
    chain_hash: str


def compute_audit_entry(
    ctx: TenantComplianceContext,
    action_type: str,
    batch_id: str,
    record_projections: list,
    previous_chain_hash: str,
    timestamp: Optional[float] = None,
) -> AuditEntry:
    ts = timestamp if timestamp is not None else time.time()

    record_hashes = [sha256_hex(canonical_json(proj)) for proj in record_projections]
    merkle_root = compute_merkle_root(record_hashes)

    entry_body = {
        "schema_version": 1,
        "timestamp": ts,
        "tenant_id": ctx.tenant_id,
        "batch_id": batch_id,
        "action_type": action_type,
        "record_count": len(record_projections),
        "payload_merkle_root": merkle_root,
        "prev_chain_hash": previous_chain_hash,
    }
    chain_hash = sha256_hex(canonical_json(entry_body) + previous_chain_hash.encode("utf-8"))

    return AuditEntry(
        schema_version=1,
        timestamp=ts,
        tenant_id=ctx.tenant_id,
        batch_id=batch_id,
        action_type=action_type,
        record_count=len(record_projections),
        payload_merkle_root=merkle_root,
        prev_chain_hash=previous_chain_hash,
        chain_hash=chain_hash,
    )


def verify_chain(entries: list, ctx: TenantComplianceContext) -> Tuple[bool, Optional[int]]:
    if not entries:
        return True, None

    if entries[0].prev_chain_hash != ctx.genesis_hash():
        return False, 0

    for i, entry in enumerate(entries):
        entry_body = {
            "schema_version": entry.schema_version,
            "timestamp": entry.timestamp,
            "tenant_id": entry.tenant_id,
            "batch_id": entry.batch_id,
            "action_type": entry.action_type,
            "record_count": entry.record_count,
            "payload_merkle_root": entry.payload_merkle_root,
            "prev_chain_hash": entry.prev_chain_hash,
        }
        try:
            recomputed = sha256_hex(canonical_json(entry_body) + entry.prev_chain_hash.encode("utf-8"))
        except ComplianceHashError:
            return False, i
        if recomputed != entry.chain_hash:
            return False, i
        if i + 1 < len(entries) and entries[i + 1].prev_chain_hash != entry.chain_hash:
            return False, i + 1

    return True, None


# =========================================================================
# 6. PIPELINE WRAPPER
# =========================================================================

@dataclass(frozen=True)
class Engine08Result:
    success: bool
    tag: str
    audit_entry: Optional[AuditEntry]
    sanitized_records: list
    error_detail: Optional[str] = None


def run_engine_08(
    records: List[Dict[str, Any]],
    tenant_id: str = "default_tenant",
    action_type: str = "DATA_NORMALIZATION",
    server_pepper: Optional[bytes] = None,
    previous_chain_hash: Optional[str] = None,
    batch_id: Optional[str] = None,
    redact_fields: Optional[frozenset] = None,
    pseudonymize_fields: Optional[frozenset] = None,
) -> List[Dict[str, Any]]:
    """
    Main Pipeline Wrapper for Engine 08.
    Executes PII Redaction/Pseudonymization and attaches Audit Chain Metadata.
    """
    if not server_pepper:
        raw_pepper = os.getenv("SERVER_PEPPER", "AMG_CLOUD_SECURE_PEPPER_KEY_32BYTES_LONG_MIN_SECRET")
        server_pepper = raw_pepper.encode("utf-8")[:32].ljust(32, b"0")

    try:
        if not tenant_id:
            logger.error("run_engine_08: tenant_id is required")
            return records

        if action_type not in VALID_ACTION_TYPES:
            action_type = "DATA_NORMALIZATION"

        if len(records) > MAX_RECORDS_PER_AUDIT_BATCH:
            logger.error("run_engine_08: batch size exceeds cap")
            return records

        ctx = TenantComplianceContext(tenant_id, server_pepper)
        chain_tip = previous_chain_hash if previous_chain_hash else ctx.genesis_hash()
        resolved_batch_id = batch_id or sha256_hex(f"{tenant_id}:{time.time_ns()}".encode("utf-8"))[:16]

        sanitized_records = []
        projections = []

        for rec in records:
            if not isinstance(rec, dict):
                continue
            outcome = apply_pii_transformations(rec, ctx, redact_fields, pseudonymize_fields)
            sanitized_records.append(outcome.sanitized_record)
            projection = build_compliance_safe_projection(outcome.sanitized_record, ctx)
            projections.append(projection)

        entry = compute_audit_entry(ctx, action_type, resolved_batch_id, projections, chain_tip)

        processed_records = []
        for rec in sanitized_records:
            clean_dict = dict(rec)
            clean_dict["_audit_batch_id"] = entry.batch_id
            clean_dict["_audit_chain_hash"] = entry.chain_hash
            clean_dict["_meta_compliance_audited"] = True
            processed_records.append(clean_dict)

        return processed_records

    except Exception as e:
        logger.exception("run_engine_08: failure generating audit entry for tenant %s: %s", tenant_id, e)
        return records
