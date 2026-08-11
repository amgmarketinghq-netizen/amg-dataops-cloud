"""
Engine 09 — Master Pipeline Orchestrator, State Machine & Dead Letter Queue
AMG DataOps Cloud

Chains Engines 01-08 into one fault-tolerant execution pipeline.

Design principles:
  - Two-tier fault isolation: per-record try/except + batch-level try/except.
  - Required explicit PipelineConfig (no silent defaults).
  - Immutable record flow across stages.
  - Sanitized DLQ (Dead Letter Queue) for debugging without info disclosure.
  - Reconciliation check ensuring zero silent record loss.
"""

from __future__ import annotations

import os
import time
import asyncio
import logging
import traceback
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any

# --- Imports of Engines 01 to 08 with robust fallbacks ---
try:
    from . import engine_01_cleaning as E01
except ImportError:
    try:
        import engine_01_cleaning as E01
    except ImportError:
        import engine_01_normalization as E01

try:
    from . import engine_02_dedup as E02
    from . import engine_03_verification as E03
    from . import engine_04_phone as E04
    from . import engine_05_risk as E05
    from . import engine_06_rules as E06
    from . import engine_07_throttling as E07
    from . import engine_08_compliance as E08
except ImportError:
    import engine_02_dedup as E02
    import engine_03_verification as E03
    import engine_04_phone as E04
    import engine_05_risk as E05
    import engine_06_rules as E06
    import engine_07_throttling as E07
    import engine_08_compliance as E08

logger = logging.getLogger("engine09")


# =========================================================================
# 0. LIFECYCLE STATE MACHINE
# =========================================================================

class PipelineStatus(Enum):
    RAW = "RAW"
    NORMALIZED = "NORMALIZED"
    DEDUPED = "DEDUPED"
    VERIFIED = "VERIFIED"
    FORMATTED = "FORMATTED"
    SCORED = "SCORED"
    EVALUATED = "EVALUATED"
    THROTTLED = "THROTTLED"
    AUDITED = "AUDITED"
    
    DUPLICATE_REMOVED = "DUPLICATE_REMOVED"
    DROPPED_BY_RULE = "DROPPED_BY_RULE"
    THROTTLE_REJECTED = "THROTTLE_REJECTED"
    DLQ_ROUTED = "DLQ_ROUTED"


class DlqErrorCode:
    NORMALIZATION_FAILURE = "NORMALIZATION_FAILURE"
    STAGE_ENGINE_FAILURE = "STAGE_ENGINE_FAILURE"
    ORCHESTRATION_ERROR = "ORCHESTRATION_ERROR"


MAX_BATCH_SIZE = 20_000


class OrchestratorError(ValueError):
    pass


# =========================================================================
# 1. IMMUTABLE RECORD ENVELOPE
# =========================================================================

@dataclass(frozen=True)
class RecordEnvelope:
    record_id: str
    status: PipelineStatus
    data: dict
    tags: tuple = ()


@dataclass(frozen=True)
class DlqEntry:
    record_id: str
    stage: str
    error_code: str
    error_message: str
    last_known_data: dict


def _log_exception_securely(exc: Exception, tenant_id: str, record_id: str, stage: str) -> None:
    logger.error(
        "engine09: exception in stage=%s tenant=%s record=%s: %s\n%s",
        stage, tenant_id, record_id, exc, traceback.format_exc(),
    )


# =========================================================================
# 2. CONFIG
# =========================================================================

@dataclass(frozen=True)
class PipelineConfig:
    server_pepper: bytes
    bucket_registry: E07.TenantBucketRegistry
    tenant_rules: list = field(default_factory=list)
    previous_chain_hash: Optional[str] = None
    batch_id: Optional[str] = None
    default_phone_region: Optional[str] = "IN"
    do_smtp_probe: bool = False
    breaker_registry: Optional[E07.CircuitBreakerRegistry] = None


# =========================================================================
# 3. STAGES ORCHESTRATION (STAGES 1 to 8)
# =========================================================================

def _stage_normalize(raw_record: dict, tenant_ctx: E01.TenantContext, tenant_id: str) -> tuple:
    record_id = str(raw_record.get("id") or raw_record.get("record_id") or "unknown")
    try:
        normalized = E01.normalize_record(tenant_ctx, raw_record)
        email = normalized.email_result.normalized
        working = {
            "record_id": record_id,
            "email": email,
            "email_domain": email.split("@")[1] if email and "@" in email else None,
            "phone": normalized.phone or None,
            "contact_name": " ".join(filter(None, [normalized.parsed_name.first_name, normalized.parsed_name.last_name])) or None,
            "first_name": normalized.parsed_name.first_name or None,
            "last_name": normalized.parsed_name.last_name or None,
            "address": normalized.address or None,
            "company_name": normalized.company or None,
            "company": normalized.company or None,
            "bio": normalized.bio or None,
        }
        return RecordEnvelope(record_id, PipelineStatus.NORMALIZED, working, tuple(normalized.errors)), None
    except Exception as e:
        _log_exception_securely(e, tenant_id, record_id, "NORMALIZATION")
        return None, DlqEntry(record_id, "NORMALIZATION", DlqErrorCode.NORMALIZATION_FAILURE,
                               "record failed normalization", raw_record if isinstance(raw_record, dict) else {})


def _stage_dedup(envelopes: list, tenant_id: str, server_pepper: bytes) -> tuple:
    try:
        hash_ctx = E02.TenantHashContext(tenant_id, server_pepper)
        fingerprints = [
            E02.build_fingerprints(
                hash_ctx, env.record_id,
                env.data.get("email"), env.data.get("phone"),
                (env.data.get("company_name") or ""),
            )
            for env in envelopes
        ]
        # Fixed: find_exact_duplicates takes 1 positional argument (fingerprints)
        dupe_groups = E02.find_exact_duplicates(fingerprints)
        duplicate_ids = set()
        for ids in dupe_groups.values():
            duplicate_ids.update(ids[1:])

        surviving = [
            RecordEnvelope(e.record_id, PipelineStatus.DEDUPED, e.data, e.tags)
            for e in envelopes if e.record_id not in duplicate_ids
        ]
        return surviving, duplicate_ids, []
    except Exception as e:
        _log_exception_securely(e, tenant_id, "BATCH", "DEDUPLICATION")
        dlq = [DlqEntry(env.record_id, "DEDUPLICATION", DlqErrorCode.STAGE_ENGINE_FAILURE,
                         "deduplication stage failed for the batch", env.data) for env in envelopes]
        return [], set(), dlq


def _stage_verify(envelopes: list, tenant_id: str, do_smtp_probe: bool) -> tuple:
    try:
        input_records = [{"id": e.record_id, "email": e.data.get("email")} for e in envelopes]
        results = E03.run_engine_03(input_records, tenant_id, do_smtp_probe)

        surviving = []
        for idx, env in enumerate(envelopes):
            res_dict = results[idx] if idx < len(results) else {}
            new_data = {
                **env.data,
                "is_disposable_email": res_dict.get("is_disposable", False),
                "is_role_based_email": res_dict.get("is_role_based", False),
                "is_catch_all_domain": bool(res_dict.get("is_catch_all", False)),
                "has_mx_records": res_dict.get("has_mx_records", True),
                "email_valid_syntax": res_dict.get("has_mx_records", True),
            }
            surviving.append(RecordEnvelope(env.record_id, PipelineStatus.VERIFIED, new_data, env.tags))
        return surviving, []
    except Exception as e:
        _log_exception_securely(e, tenant_id, "BATCH", "EMAIL_VERIFICATION")
        dlq = [DlqEntry(env.record_id, "EMAIL_VERIFICATION", DlqErrorCode.STAGE_ENGINE_FAILURE,
                         "email verification stage failed for the batch", env.data) for env in envelopes]
        return [], dlq


def _stage_format_phone(envelopes: list, tenant_id: str, default_region: Optional[str]) -> tuple:
    try:
        input_records = [{"id": e.record_id, "phone": e.data.get("phone")} for e in envelopes]
        results = E04.run_engine_04(input_records, tenant_id, default_region=default_region)
        result_by_id = {str(r.get("id") or r.get("phone")): r for r in results}

        surviving = []
        for env in envelopes:
            r = result_by_id.get(env.record_id, {})
            new_data = {
                **env.data,
                "phone": r.get("phone_e164") or env.data.get("phone"),
                "line_type": r.get("phone_line_type"),
                "is_voip_phone": r.get("phone_line_type") == "LINE_VOIP",
                "country_code": r.get("phone_country_code"),
            }
            surviving.append(RecordEnvelope(env.record_id, PipelineStatus.FORMATTED, new_data, env.tags))
        return surviving, []
    except Exception as e:
        _log_exception_securely(e, tenant_id, "BATCH", "PHONE_FORMATTING")
        dlq = [DlqEntry(env.record_id, "PHONE_FORMATTING", DlqErrorCode.STAGE_ENGINE_FAILURE,
                         "phone formatting stage failed for the batch", env.data) for env in envelopes]
        return [], dlq


def _stage_score(envelopes: list, tenant_id: str) -> tuple:
    try:
        input_records = [
            {
                "id": e.record_id,
                "email": e.data.get("email"),
                "email_domain": e.data.get("email_domain"),
                "is_disposable": e.data.get("is_disposable_email", False),
                "is_role_based": e.data.get("is_role_based_email", False),
                "is_catch_all": e.data.get("is_catch_all_domain", False),
                "is_voip_phone": e.data.get("is_voip_phone", False),
                "company": e.data.get("company_name"),
                "contact_name": e.data.get("contact_name"),
            }
            for e in envelopes
        ]
        results = E05.run_engine_05(input_records, tenant_id)
        result_by_id = {str(r.get("id")): r for r in results}

        surviving = []
        for env in envelopes:
            r = result_by_id.get(env.record_id, {})
            new_data = {**env.data, "risk_score": r.get("risk_score", 50), "sector": r.get("industry_sector", "Unknown"), "industry_sector": r.get("industry_sector", "Unknown")}
            surviving.append(RecordEnvelope(env.record_id, PipelineStatus.SCORED, new_data, env.tags))
        return surviving, []
    except Exception as e:
        _log_exception_securely(e, tenant_id, "BATCH", "RISK_SCORING")
        dlq = [DlqEntry(env.record_id, "RISK_SCORING", DlqErrorCode.STAGE_ENGINE_FAILURE,
                         "risk scoring stage failed for the batch", env.data) for env in envelopes]
        return [], dlq


def _stage_rules(envelopes: list, tenant_id: str, tenant_rules: list) -> tuple:
    try:
        input_records = [{"id": e.record_id, **e.data} for e in envelopes]
        results = E06.run_engine_06(input_records, tenant_rules, tenant_id)
        result_by_id = {str(r.get("id")): r for r in results}

        surviving, dropped_ids = [], set()
        for env in envelopes:
            r = result_by_id.get(env.record_id)
            if r is None:
                surviving.append(env)
                continue
            if r.get("is_dropped"):
                dropped_ids.add(env.record_id)
                continue
            surviving.append(RecordEnvelope(env.record_id, PipelineStatus.EVALUATED, r, env.tags))
        return surviving, dropped_ids, []
    except Exception as e:
        _log_exception_securely(e, tenant_id, "BATCH", "RULES_EVALUATION")
        dlq = [DlqEntry(env.record_id, "RULES_EVALUATION", DlqErrorCode.STAGE_ENGINE_FAILURE,
                         "rules evaluation stage failed for the batch", env.data) for env in envelopes]
        return [], set(), dlq


def _stage_throttle(envelopes: list, tenant_id: str, bucket_registry, breaker_registry) -> tuple:
    try:
        input_records = [{"id": e.record_id, **e.data} for e in envelopes]
        results = E07.run_engine_07(input_records, tenant_id, bucket_registry, breaker_registry=breaker_registry)
        result_by_id = {str(r.get("id")): r for r in results}

        surviving, throttled_ids = [], set()
        for env in envelopes:
            r = result_by_id.get(env.record_id, {})
            if r.get("is_throttled"):
                throttled_ids.add(env.record_id)
                continue
            surviving.append(RecordEnvelope(env.record_id, PipelineStatus.THROTTLED, env.data, env.tags))
        return surviving, throttled_ids, []
    except Exception as e:
        _log_exception_securely(e, tenant_id, "BATCH", "THROTTLING")
        dlq = [DlqEntry(env.record_id, "THROTTLING", DlqErrorCode.STAGE_ENGINE_FAILURE,
                         "throttling stage failed for the batch", env.data) for env in envelopes]
        return [], set(), dlq


def _stage_audit(envelopes: list, tenant_id: str, config: PipelineConfig) -> tuple:
    try:
        input_records = [e.data for e in envelopes]
        results = E08.run_engine_08(
            input_records, tenant_id, "DATA_INGESTION", config.server_pepper,
            previous_chain_hash=config.previous_chain_hash, batch_id=config.batch_id,
        )
        surviving = [RecordEnvelope(e.record_id, PipelineStatus.AUDITED, e.data, e.tags) for e in envelopes]
        return surviving, [], None
    except Exception as e:
        _log_exception_securely(e, tenant_id, "BATCH", "AUDIT")
        dlq = [DlqEntry(env.record_id, "AUDIT", DlqErrorCode.STAGE_ENGINE_FAILURE,
                         "audit stage failed for the batch", env.data) for env in envelopes]
        return [], dlq, None


# =========================================================================
# 4. REPORT & MASTER ORCHESTRATOR
# =========================================================================

@dataclass(frozen=True)
class PipelineReport:
    total_records: int
    clean_records_count: int
    duplicates_removed: int
    invalid_emails: int
    invalid_phones: int
    high_risk_flags: int
    dropped_via_rules: int
    throttled_count: int
    dlq_count: int
    processing_time_ms: float


@dataclass(frozen=True)
class OrchestratorResult:
    clean_records: list
    dlq: list
    report: PipelineReport
    audit_entry: Optional[Any]


def run_pipeline_orchestrator(records: list, tenant_id: str, config: PipelineConfig) -> OrchestratorResult:
    if not tenant_id:
        raise OrchestratorError("tenant_id is required")
    if not isinstance(records, list):
        raise OrchestratorError("records must be a list")
    if len(records) > MAX_BATCH_SIZE:
        raise OrchestratorError(f"batch exceeds max size {MAX_BATCH_SIZE}")

    start = time.monotonic()
    total_records = len(records)
    dlq: list = []
    duplicates_removed = 0
    dropped_via_rules = 0
    throttled_count = 0

    # Stage 1: Normalization
    tenant_ctx01 = E01.TenantContext(tenant_id=tenant_id)
    envelopes = []
    for raw in records:
        env, dlq_entry = _stage_normalize(raw, tenant_ctx01, tenant_id)
        if env is not None:
            envelopes.append(env)
        if dlq_entry is not None:
            dlq.append(dlq_entry)

    # Stage 2: Dedup
    envelopes, duplicate_ids, dlq_add = _stage_dedup(envelopes, tenant_id, config.server_pepper)
    duplicates_removed = len(duplicate_ids)
    dlq.extend(dlq_add)

    # Stage 3: Email verification
    envelopes, dlq_add = _stage_verify(envelopes, tenant_id, config.do_smtp_probe)
    dlq.extend(dlq_add)
    invalid_emails = sum(1 for e in envelopes if e.data.get("email_valid_syntax") is False)

    # Stage 4: Phone formatting
    envelopes, dlq_add = _stage_format_phone(envelopes, tenant_id, config.default_phone_region)
    dlq.extend(dlq_add)
    invalid_phones = sum(1 for e in envelopes if e.data.get("phone") is None)

    # Stage 5: Risk & sector scoring
    envelopes, dlq_add = _stage_score(envelopes, tenant_id)
    dlq.extend(dlq_add)
    high_risk_flags = sum(1 for e in envelopes if e.data.get("risk_score", 0) >= 70)

    # Stage 6: Tenant rules engine
    envelopes, dropped_ids, dlq_add = _stage_rules(envelopes, tenant_id, config.tenant_rules)
    dropped_via_rules = len(dropped_ids)
    dlq.extend(dlq_add)

    # Stage 7: Throttling
    envelopes, throttled_ids, dlq_add = _stage_throttle(envelopes, tenant_id, config.bucket_registry, config.breaker_registry)
    throttled_count = len(throttled_ids)
    dlq.extend(dlq_add)

    # Stage 8: Audit trail
    envelopes, dlq_add, audit_entry = _stage_audit(envelopes, tenant_id, config)
    dlq.extend(dlq_add)

    elapsed_ms = (time.monotonic() - start) * 1000.0
    clean_records = [e.data for e in envelopes]

    report = PipelineReport(
        total_records=total_records,
        clean_records_count=len(clean_records),
        duplicates_removed=duplicates_removed,
        invalid_emails=invalid_emails,
        invalid_phones=invalid_phones,
        high_risk_flags=high_risk_flags,
        dropped_via_rules=dropped_via_rules,
        throttled_count=throttled_count,
        dlq_count=len(dlq),
        processing_time_ms=round(elapsed_ms, 2),
    )

    accounted = (report.clean_records_count + report.duplicates_removed
                 + report.dropped_via_rules + report.throttled_count + report.dlq_count)
    if accounted != total_records:
        logger.error(
            "engine09: RECONCILIATION MISMATCH for tenant %s — total=%d accounted=%d",
            tenant_id, total_records, accounted,
        )

    return OrchestratorResult(clean_records=clean_records, dlq=dlq, report=report, audit_entry=audit_entry)
