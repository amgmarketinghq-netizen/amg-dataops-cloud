"""
Engine 07 — Throttling, Rate Limiting & System Resilience Engine
AMG DataOps Cloud

Design principles:
  - Thread-safe TenantBucketRegistry with bounded capacity and idle eviction.
  - Per-service CircuitBreaker (CLOSED -> OPEN -> HALF_OPEN single-flight probe).
  - Exponential backoff with full jitter for retry storms.
  - Backpressure memory & queue threshold checking.
  - Async-compatible and sync pipeline execution variants.
"""

from __future__ import annotations

import time
import random
import asyncio
import threading
import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Callable, Any, List, Dict

logger = logging.getLogger("engine07")


# =========================================================================
# 0. TYPED TAGS & SAFETY CEILINGS
# =========================================================================

class ResultTag:
    ALLOWED = "ALLOWED"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    CIRCUIT_OPEN_BACKPRESSURE = "CIRCUIT_OPEN_BACKPRESSURE"
    RESOURCE_THROTTLED = "RESOURCE_THROTTLED"
    REGISTRY_CAPACITY_EXCEEDED = "REGISTRY_CAPACITY_EXCEEDED"


MAX_TRACKED_TENANTS = 10_000
IDLE_EVICTION_SECONDS = 3600.0
MAX_TRACKED_SERVICES = 200

DEFAULT_BUCKET_CAPACITY = 60.0
DEFAULT_REFILL_RATE_PER_SEC = 1.0

DEFAULT_FAILURE_THRESHOLD = 5
DEFAULT_RECOVERY_TIMEOUT_SECONDS = 30.0

BACKOFF_BASE_SECONDS = 0.5
BACKOFF_CAP_SECONDS = 30.0
MAX_RETRY_ATTEMPTS = 8


class ThrottleError(ValueError):
    pass


# =========================================================================
# 1. PURE TOKEN BUCKET MATH
# =========================================================================

def compute_bucket_refill(
    current_tokens: float,
    last_refill_at: float,
    now: float,
    capacity: float,
    refill_rate_per_sec: float,
) -> float:
    elapsed = max(0.0, now - last_refill_at)
    replenished = elapsed * refill_rate_per_sec
    return min(capacity, current_tokens + replenished)


# =========================================================================
# 2. THREAD-SAFE PER-TENANT TOKEN BUCKET
# =========================================================================

@dataclass
class _BucketState:
    tokens: float
    last_refill_at: float
    last_seen_at: float
    lock: threading.Lock = field(default_factory=threading.Lock)


class TenantBucketRegistry:
    def __init__(
        self,
        capacity: float = DEFAULT_BUCKET_CAPACITY,
        refill_rate_per_sec: float = DEFAULT_REFILL_RATE_PER_SEC,
        max_tenants: int = MAX_TRACKED_TENANTS,
    ):
        self._capacity = capacity
        self._refill_rate = refill_rate_per_sec
        self._max_tenants = max_tenants
        self._buckets: dict[str, _BucketState] = {}
        self._registry_lock = threading.Lock()

    def _get_or_create_bucket(self, tenant_id: str) -> Optional[_BucketState]:
        with self._registry_lock:
            bucket = self._buckets.get(tenant_id)
            if bucket is not None:
                return bucket

            if len(self._buckets) >= self._max_tenants:
                self._evict_idle_locked()
                if len(self._buckets) >= self._max_tenants:
                    return None

            now = time.monotonic()
            bucket = _BucketState(tokens=self._capacity, last_refill_at=now, last_seen_at=now)
            self._buckets[tenant_id] = bucket
            return bucket

    def _evict_idle_locked(self) -> None:
        now = time.monotonic()
        idle_ids = [
            tid for tid, b in self._buckets.items()
            if (now - b.last_seen_at) > IDLE_EVICTION_SECONDS
        ]
        for tid in idle_ids:
            del self._buckets[tid]
        if idle_ids:
            logger.info("TenantBucketRegistry: evicted %d idle tenant buckets", len(idle_ids))

    def try_consume(self, tenant_id: str, cost: float = 1.0) -> tuple:
        if not tenant_id:
            return False, ResultTag.RATE_LIMIT_EXCEEDED

        bucket = self._get_or_create_bucket(tenant_id)
        if bucket is None:
            return False, ResultTag.REGISTRY_CAPACITY_EXCEEDED

        with bucket.lock:
            now = time.monotonic()
            bucket.tokens = compute_bucket_refill(
                bucket.tokens, bucket.last_refill_at, now, self._capacity, self._refill_rate
            )
            bucket.last_refill_at = now
            bucket.last_seen_at = now

            if bucket.tokens >= cost:
                bucket.tokens -= cost
                return True, ResultTag.ALLOWED
            return False, ResultTag.RATE_LIMIT_EXCEEDED

    def tenant_count(self) -> int:
        with self._registry_lock:
            return len(self._buckets)


_DEFAULT_PROCESS_REGISTRY = TenantBucketRegistry()


# =========================================================================
# 3. CIRCUIT BREAKER
# =========================================================================

class CircuitState(Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class _CircuitBreaker:
    def __init__(
        self,
        failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
        recovery_timeout_seconds: float = DEFAULT_RECOVERY_TIMEOUT_SECONDS,
    ):
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout_seconds
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._opened_at: Optional[float] = None
        self._half_open_probe_in_flight = False
        self._lock = threading.Lock()

    def allow_request(self) -> tuple:
        with self._lock:
            if self._state == CircuitState.CLOSED:
                return True, ResultTag.ALLOWED, False

            if self._state == CircuitState.OPEN:
                if self._opened_at is not None and (time.monotonic() - self._opened_at) >= self._recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
                    self._half_open_probe_in_flight = True
                    return True, ResultTag.ALLOWED, True
                return False, ResultTag.CIRCUIT_OPEN_BACKPRESSURE, False

            if self._state == CircuitState.HALF_OPEN:
                if not self._half_open_probe_in_flight:
                    self._half_open_probe_in_flight = True
                    return True, ResultTag.ALLOWED, True
                return False, ResultTag.CIRCUIT_OPEN_BACKPRESSURE, False

            return False, ResultTag.CIRCUIT_OPEN_BACKPRESSURE, False

    def record_success(self, was_probe: bool) -> None:
        with self._lock:
            if was_probe or self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.CLOSED
                self._failure_count = 0
                self._opened_at = None
                self._half_open_probe_in_flight = False
            else:
                self._failure_count = 0

    def record_failure(self, was_probe: bool) -> None:
        with self._lock:
            if was_probe or self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                self._opened_at = time.monotonic()
                self._half_open_probe_in_flight = False
                return

            self._failure_count += 1
            if self._failure_count >= self._failure_threshold:
                self._state = CircuitState.OPEN
                self._opened_at = time.monotonic()


class CircuitBreakerRegistry:
    def __init__(self, max_services: int = MAX_TRACKED_SERVICES):
        self._breakers: dict[str, _CircuitBreaker] = {}
        self._lock = threading.Lock()
        self._max_services = max_services

    def get_breaker(self, service_name: str) -> Optional[_CircuitBreaker]:
        with self._lock:
            breaker = self._breakers.get(service_name)
            if breaker is not None:
                return breaker
            if len(self._breakers) >= self._max_services:
                return None
            breaker = _CircuitBreaker()
            self._breakers[service_name] = breaker
            return breaker


# =========================================================================
# 4. EXPONENTIAL BACKOFF WITH FULL JITTER
# =========================================================================

def compute_backoff_with_jitter(
    attempt: int,
    base_seconds: float = BACKOFF_BASE_SECONDS,
    cap_seconds: float = BACKOFF_CAP_SECONDS,
) -> float:
    if attempt < 0:
        attempt = 0
    exp_delay = min(cap_seconds, base_seconds * (2 ** attempt))
    return random.uniform(0, exp_delay)


# =========================================================================
# 5. BACKPRESSURE & MEMORY PROTECTION
# =========================================================================

@dataclass(frozen=True)
class BackpressureThresholds:
    max_queue_size: int = 5000
    max_memory_mb: float = 1024.0


def check_backpressure(
    current_queue_size: int,
    current_memory_mb: float,
    thresholds: BackpressureThresholds = BackpressureThresholds(),
) -> tuple:
    try:
        if current_queue_size < 0 or current_memory_mb < 0:
            return False, ResultTag.RESOURCE_THROTTLED
        if current_queue_size >= thresholds.max_queue_size:
            return False, ResultTag.RESOURCE_THROTTLED
        if current_memory_mb >= thresholds.max_memory_mb:
            return False, ResultTag.RESOURCE_THROTTLED
        return True, ResultTag.ALLOWED
    except Exception:
        logger.exception("check_backpressure: unexpected failure, failing closed")
        return False, ResultTag.RESOURCE_THROTTLED


def retry_with_backoff(
    operation: Callable[[], Any],
    max_attempts: int = MAX_RETRY_ATTEMPTS,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> tuple:
    last_exception = None
    for attempt in range(max_attempts):
        try:
            result = operation()
            return True, result, attempt + 1
        except Exception as e:
            last_exception = e
            if attempt < max_attempts - 1:
                delay = compute_backoff_with_jitter(attempt)
                sleep_fn(delay)
    logger.warning("retry_with_backoff: exhausted %d attempts, last error: %s", max_attempts, last_exception)
    return False, None, max_attempts


# =========================================================================
# 6. PIPELINE WRAPPER
# =========================================================================

def run_engine_07(
    records: List[Dict[str, Any]],
    tenant_id: str = "default_tenant",
    bucket_registry: Optional[TenantBucketRegistry] = None,
    breaker_registry: Optional[CircuitBreakerRegistry] = None,
    service_name: str = "default_downstream",
    current_queue_size: int = 0,
    current_memory_mb: float = 0.0,
    backpressure_thresholds: BackpressureThresholds = BackpressureThresholds(),
) -> List[Dict[str, Any]]:
    """
    Main Pipeline Wrapper for Engine 07.
    Applies backpressure checks, rate-limiting, and circuit breaker gates over record batches.
    """
    if not tenant_id:
        raise ThrottleError("tenant_id is required")
    
    registry = bucket_registry or _DEFAULT_PROCESS_REGISTRY

    bp_allowed, bp_tag = check_backpressure(current_queue_size, current_memory_mb, backpressure_thresholds)
    
    breaker = None
    if breaker_registry is not None:
        breaker = breaker_registry.get_breaker(service_name)

    processed_records = []
    for idx, rec in enumerate(records):
        rec_id = str(rec.get("id") or rec.get("record_id") or f"rec_{idx}")
        clean_dict = dict(rec)
        
        if not bp_allowed:
            clean_dict["is_throttled"] = True
            clean_dict["throttle_tag"] = bp_tag
        else:
            try:
                allowed, tag = registry.try_consume(tenant_id)
                if not allowed:
                    clean_dict["is_throttled"] = True
                    clean_dict["throttle_tag"] = tag
                elif breaker is not None:
                    circuit_allowed, circuit_tag, _ = breaker.allow_request()
                    if not circuit_allowed:
                        clean_dict["is_throttled"] = True
                        clean_dict["throttle_tag"] = circuit_tag
                    else:
                        clean_dict["is_throttled"] = False
                        clean_dict["throttle_tag"] = ResultTag.ALLOWED
                else:
                    clean_dict["is_throttled"] = False
                    clean_dict["throttle_tag"] = ResultTag.ALLOWED
            except Exception:
                logger.exception("run_engine_07: error processing record %s", rec_id)
                clean_dict["is_throttled"] = True
                clean_dict["throttle_tag"] = ResultTag.RESOURCE_THROTTLED

        clean_dict["_meta_throttled"] = True
        if not clean_dict.get("is_throttled"):
            processed_records.append(clean_dict)

    return processed_records
