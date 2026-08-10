
"""
Engine 03 — Deep Email & MX Verification Engine
AMG DataOps Cloud

Design principles:
  - Tenant/Run-Scoped RunState: Circuit breaker, rate limiter, and catch-all
    cache created fresh per batch (zero global state cross-tenant bleed).
  - Hard timeouts on all DNS and SMTP operations.
  - SSRF defense: resolve MX -> validate IP -> connect to VALIDATED IP directly.
  - Non-blocking async execution.
"""

from __future__ import annotations

import re
import time
import random
import socket
import asyncio
import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

try:
    import dns.asyncresolver
    import dns.exception
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False

logger = logging.getLogger("engine03")


# =========================================================================
# 0. TYPED RESULT TAGS & SAFETY CEILINGS
# =========================================================================

class VerificationTag:
    VALID_SYNTAX = "VALID_SYNTAX"
    INVALID_SYNTAX = "INVALID_SYNTAX"
    DISPOSABLE_EMAIL = "DISPOSABLE_EMAIL"
    ROLE_BASED = "ROLE_BASED"
    NO_MX_RECORD = "NO_MX_RECORD"
    DNS_TIMEOUT = "DNS_TIMEOUT"
    DNS_ERROR = "DNS_ERROR"
    SSRF_BLOCKED = "SSRF_BLOCKED"
    SMTP_TIMEOUT = "SMTP_TIMEOUT"
    SMTP_CONNECT_FAILED = "SMTP_CONNECT_FAILED"
    MAILBOX_LIKELY_VALID = "MAILBOX_LIKELY_VALID"
    MAILBOX_LIKELY_INVALID = "MAILBOX_LIKELY_INVALID"
    CATCH_ALL_DOMAIN = "CATCH_ALL_DOMAIN"
    CIRCUIT_OPEN = "CIRCUIT_OPEN"
    UNPARSEABLE = "UNPARSEABLE"


DNS_TIMEOUT_SECONDS = 2.0
SMTP_CONNECT_TIMEOUT_SECONDS = 3.0
SMTP_COMMAND_TIMEOUT_SECONDS = 3.0
MAX_CONCURRENT_LOOKUPS = 25
MAX_EMAIL_LEN = 320
CIRCUIT_BREAKER_FAILURE_THRESHOLD = 5
CIRCUIT_BREAKER_COOLDOWN_SECONDS = 60.0
SMTP_PROBE_MIN_DELAY = 0.15
SMTP_PROBE_MAX_DELAY = 0.45


class MalformedInputError(ValueError):
    pass


# =========================================================================
# 1. SYNTAX VALIDATION (ReDoS-safe)
# =========================================================================

_EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}"
    r"@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?){1,8}$"
)


def validate_syntax(email: str) -> tuple[bool, Optional[str], Optional[str]]:
    if not isinstance(email, str) or not email or len(email) > MAX_EMAIL_LEN:
        return False, None, None
    if "@" not in email or email.count("@") != 1:
        return False, None, None
    if not _EMAIL_PATTERN.match(email):
        return False, None, None
    local, _, domain = email.lower().partition("@")
    return True, local, domain


# =========================================================================
# 2. DISPOSABLE & ROLE-BASED LISTS
# =========================================================================

DISPOSABLE_DOMAINS: frozenset[str] = frozenset({
    "10minutemail.com", "guerrillamail.com", "tempmail.com", "temp-mail.org",
    "mailinator.com", "throwawaymail.com", "yopmail.com", "fakeinbox.com",
    "getnada.com", "trashmail.com", "sharklasers.com", "dispostable.com",
    "maildrop.cc", "mintemail.com", "mohmal.com", "spamgourmet.com",
})

ROLE_BASED_PREFIXES: frozenset[str] = frozenset({
    "admin", "administrator", "info", "sales", "support", "billing", "jobs",
    "careers", "hr", "contact", "help", "office", "noreply", "no-reply",
    "webmaster", "postmaster", "marketing", "abuse", "security",
})


def is_disposable_domain(domain: str) -> bool:
    return domain in DISPOSABLE_DOMAINS


def is_role_based(local_part: str) -> bool:
    return local_part in ROLE_BASED_PREFIXES


# =========================================================================
# 3. SSRF-SAFE IP VALIDATION
# =========================================================================

def is_safe_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    ):
        return False
    return True


# =========================================================================
# 4. RUN-SCOPED CIRCUIT BREAKER & STATE
# =========================================================================

@dataclass
class DomainCircuitState:
    failure_count: int = 0
    opened_at: Optional[float] = None


@dataclass
class RunState:
    tenant_id: str
    circuit_states: dict[str, DomainCircuitState] = field(default_factory=dict)
    catch_all_cache: dict[str, bool] = field(default_factory=dict)
    last_probe_time_by_domain: dict[str, float] = field(default_factory=dict)
    semaphore: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(MAX_CONCURRENT_LOOKUPS))

    def is_circuit_open(self, domain: str) -> bool:
        state = self.circuit_states.get(domain)
        if state is None or state.opened_at is None:
            return False
        if time.monotonic() - state.opened_at > CIRCUIT_BREAKER_COOLDOWN_SECONDS:
            state.opened_at = None
            state.failure_count = 0
            return False
        return True

    def record_failure(self, domain: str) -> None:
        state = self.circuit_states.setdefault(domain, DomainCircuitState())
        state.failure_count += 1
        if state.failure_count >= CIRCUIT_BREAKER_FAILURE_THRESHOLD:
            state.opened_at = time.monotonic()

    def record_success(self, domain: str) -> None:
        if domain in self.circuit_states:
            self.circuit_states[domain].failure_count = 0
            self.circuit_states[domain].opened_at = None


# =========================================================================
# 5. ASYNC DNS RESOLUTION
# =========================================================================

@dataclass(frozen=True)
class MxResolution:
    domain: str
    mx_host: Optional[str]
    validated_ip: Optional[str]
    tag: str


async def resolve_mx_safe(domain: str) -> MxResolution:
    if not _DNS_AVAILABLE:
        # Fallback to standard socket lookup if dnspython is missing
        try:
            loop = asyncio.get_running_loop()
            addr_info = await asyncio.wait_for(
                loop.getaddrinfo(domain, 25, type=socket.SOCK_STREAM), timeout=DNS_TIMEOUT_SECONDS
            )
            if addr_info:
                ip_str = addr_info[0][4][0]
                if is_safe_public_ip(ip_str):
                    return MxResolution(domain, domain, ip_str, VerificationTag.VALID_SYNTAX)
                return MxResolution(domain, domain, None, VerificationTag.SSRF_BLOCKED)
            return MxResolution(domain, None, None, VerificationTag.NO_MX_RECORD)
        except Exception:
            return MxResolution(domain, None, None, VerificationTag.DNS_ERROR)

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = DNS_TIMEOUT_SECONDS
    resolver.lifetime = DNS_TIMEOUT_SECONDS

    try:
        answer = await asyncio.wait_for(
            resolver.resolve(domain, "MX"), timeout=DNS_TIMEOUT_SECONDS
        )
    except asyncio.TimeoutError:
        return MxResolution(domain, None, None, VerificationTag.DNS_TIMEOUT)
    except dns.exception.DNSException:
        return MxResolution(domain, None, None, VerificationTag.NO_MX_RECORD)
    except Exception:
        return MxResolution(domain, None, None, VerificationTag.DNS_ERROR)

    if not answer:
        return MxResolution(domain, None, None, VerificationTag.NO_MX_RECORD)

    mx_records = sorted(answer, key=lambda r: r.preference)
    mx_host = str(mx_records[0].exchange).rstrip(".")

    try:
        a_answer = await asyncio.wait_for(
            resolver.resolve(mx_host, "A"), timeout=DNS_TIMEOUT_SECONDS
        )
    except asyncio.TimeoutError:
        return MxResolution(domain, mx_host, None, VerificationTag.DNS_TIMEOUT)
    except dns.exception.DNSException:
        return MxResolution(domain, mx_host, None, VerificationTag.DNS_ERROR)

    for record in a_answer:
        ip_str = str(record)
        if is_safe_public_ip(ip_str):
            return MxResolution(domain, mx_host, ip_str, VerificationTag.VALID_SYNTAX)

    return MxResolution(domain, mx_host, None, VerificationTag.SSRF_BLOCKED)


# =========================================================================
# 6. NON-INTRUSIVE SMTP HANDSHAKE
# =========================================================================

@dataclass(frozen=True)
class SmtpProbeResult:
    tag: str
    smtp_code: Optional[int] = None


async def _smtp_probe(validated_ip: str, mx_host: str, mail_from: str, rcpt_to: str) -> SmtpProbeResult:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(validated_ip, 25),
            timeout=SMTP_CONNECT_TIMEOUT_SECONDS,
        )
    except (asyncio.TimeoutError, OSError):
        return SmtpProbeResult(VerificationTag.SMTP_CONNECT_FAILED)

    async def _send(cmd: str) -> str:
        writer.write((cmd + "\r\n").encode("ascii", errors="ignore"))
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout=SMTP_COMMAND_TIMEOUT_SECONDS)
        return line.decode("ascii", errors="ignore")

    try:
        await asyncio.wait_for(reader.readline(), timeout=SMTP_COMMAND_TIMEOUT_SECONDS)
        await _send("EHLO verify.amgdataops.local")
        await _send(f"MAIL FROM:<{mail_from}>")
        rcpt_response = await _send(f"RCPT TO:<{rcpt_to}>")
        await _send("QUIT")

        code = int(rcpt_response[:3]) if rcpt_response[:3].isdigit() else None
        if code is not None and 200 <= code < 300:
            return SmtpProbeResult(VerificationTag.MAILBOX_LIKELY_VALID, code)
        elif code is not None:
            return SmtpProbeResult(VerificationTag.MAILBOX_LIKELY_INVALID, code)
        return SmtpProbeResult(VerificationTag.SMTP_CONNECT_FAILED)
    except asyncio.TimeoutError:
        return SmtpProbeResult(VerificationTag.SMTP_TIMEOUT)
    except Exception:
        return SmtpProbeResult(VerificationTag.SMTP_CONNECT_FAILED)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def check_catch_all(run_state: RunState, domain: str, mx_host: str, validated_ip: str) -> bool:
    if domain in run_state.catch_all_cache:
        return run_state.catch_all_cache[domain]

    random_local = f"amgverify-{random.randint(10**9, 10**10 - 1)}"
    probe_addr = f"{random_local}@{domain}"
    result = await _smtp_probe(validated_ip, mx_host, "verify-probe@amgdataops.com", probe_addr)

    is_catch_all = result.tag == VerificationTag.MAILBOX_LIKELY_VALID
    run_state.catch_all_cache[domain] = is_catch_all
    return is_catch_all


async def _respect_domain_rate_limit(run_state: RunState, domain: str) -> None:
    last = run_state.last_probe_time_by_domain.get(domain)
    now = time.monotonic()
    if last is not None:
        elapsed = now - last
        min_gap = random.uniform(SMTP_PROBE_MIN_DELAY, SMTP_PROBE_MAX_DELAY)
        if elapsed < min_gap:
            await asyncio.sleep(min_gap - elapsed)
    run_state.last_probe_time_by_domain[domain] = time.monotonic()


# =========================================================================
# 7. PER-RECORD VERIFICATION PIPELINE
# =========================================================================

@dataclass(frozen=True)
class VerificationResult:
    record_id: str
    email: str
    tags: list
    is_disposable: bool = False
    is_role_based: bool = False
    is_catch_all: Optional[bool] = None
    smtp_code: Optional[int] = None


async def verify_single_email(
    run_state: RunState,
    record_id: str,
    email: str,
    do_smtp_probe: bool = False, # Set default to False for fast non-blocking pipeline run
) -> VerificationResult:
    tags: list[str] = []

    is_valid, local, domain = validate_syntax(email)
    if not is_valid:
        return VerificationResult(record_id, email, [VerificationTag.INVALID_SYNTAX])
    tags.append(VerificationTag.VALID_SYNTAX)

    disposable = is_disposable_domain(domain)
    if disposable:
        tags.append(VerificationTag.DISPOSABLE_EMAIL)

    role_based = is_role_based(local)
    if role_based:
        tags.append(VerificationTag.ROLE_BASED)

    if disposable:
        return VerificationResult(record_id, email, tags, is_disposable=True, is_role_based=role_based)

    if run_state.is_circuit_open(domain):
        tags.append(VerificationTag.CIRCUIT_OPEN)
        return VerificationResult(record_id, email, tags, is_disposable=False, is_role_based=role_based)

    async with run_state.semaphore:
        mx = await resolve_mx_safe(domain)

    if mx.tag != VerificationTag.VALID_SYNTAX or mx.validated_ip is None:
        run_state.record_failure(domain)
        tags.append(mx.tag)
        return VerificationResult(record_id, email, tags, is_disposable=False, is_role_based=role_based)

    run_state.record_success(domain)

    if not do_smtp_probe:
        return VerificationResult(record_id, email, tags, is_disposable=False, is_role_based=role_based)

    await _respect_domain_rate_limit(run_state, domain)

    async with run_state.semaphore:
        catch_all = await check_catch_all(run_state, domain, mx.mx_host, mx.validated_ip)

    if catch_all:
        tags.append(VerificationTag.CATCH_ALL_DOMAIN)
        return VerificationResult(record_id, email, tags, is_disposable=False,
                                   is_role_based=role_based, is_catch_all=True)

    await _respect_domain_rate_limit(run_state, domain)

    async with run_state.semaphore:
        smtp_result = await _smtp_probe(mx.validated_ip, mx.mx_host, "verify-probe@amgdataops.com", email)

    tags.append(smtp_result.tag)
    if smtp_result.tag in (VerificationTag.SMTP_TIMEOUT, VerificationTag.SMTP_CONNECT_FAILED):
        run_state.record_failure(domain)

    return VerificationResult(
        record_id, email, tags, is_disposable=False, is_role_based=role_based,
        is_catch_all=False, smtp_code=smtp_result.smtp_code,
    )


# =========================================================================
# 8. PIPELINE ADAPTER WRAPPER
# =========================================================================

def run_engine_03(
    records: List[Dict[str, Any]],
    tenant_id: str = "default_tenant",
    do_smtp_probe: bool = False
) -> List[Dict[str, Any]]:
    """
    Main Pipeline Wrapper for Engine 03.
    Accepts raw/normalized record dicts and enriches them with verification status.
    """
    if not tenant_id:
        raise MalformedInputError("tenant_id is required")

    run_state = RunState(tenant_id=tenant_id)

    async def _safe_verify_all():
        tasks = []
        for idx, rec in enumerate(records):
            rec_id = str(rec.get("id") or f"rec_{idx}")
            email = rec.get("email", "")
            tasks.append(verify_single_email(run_state, rec_id, email, do_smtp_probe))
        return await asyncio.gather(*tasks)

    try:
        results = asyncio.run(_safe_verify_all())
    except RuntimeError:
        loop = asyncio.get_event_loop()
        results = loop.run_until_complete(_safe_verify_all())

    processed_records = []
    for idx, rec in enumerate(records):
        res = results[idx]
        clean_dict = dict(rec)
        
        clean_dict["is_disposable"] = res.is_disposable
        clean_dict["is_role_based"] = res.is_role_based
        clean_dict["is_catch_all"] = res.is_catch_all
        clean_dict["verification_tags"] = res.tags
        clean_dict["has_mx_records"] = VerificationTag.NO_MX_RECORD not in res.tags and VerificationTag.DNS_ERROR not in res.tags
        clean_dict["_meta_verified"] = True
        
        processed_records.append(clean_dict)

    return processed_records
