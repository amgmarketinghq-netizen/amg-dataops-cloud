"""
Engine 01 — Data Normalization & Sanitization Engine
AMG DataOps Cloud

Design principles:
  - No module-level mutable state (prevents cross-tenant bleed).
  - Every public function is pure: same input + tenant context -> same output.
  - Hard length ceilings BEFORE any regex/parsing touches attacker-controlled input.
  - No nested-quantifier regex anywhere (ReDoS-safe by construction).
  - Normalize (NFKC) before validate, never the reverse.
  - All parsing wrapped in typed exceptions; nothing unhandled ever escapes.
"""

from __future__ import annotations

import re
import html
import string
import unicodedata
import logging
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from html.parser import HTMLParser
from typing import Optional, List, Dict, Any

logger = logging.getLogger("engine01")


# =========================================================================
# 0. GLOBAL SAFETY CEILINGS — enforced before ANY other processing
# =========================================================================

MAX_FIELD_LENGTHS = {
    "email": 320,        # RFC 5321 hard max
    "name": 100,
    "phone": 32,
    "address": 300,
    "company": 200,
    "generic": 500,
}


class PayloadTooLargeError(ValueError):
    """Raised when a field exceeds its safety ceiling. Reject, never truncate silently."""


class MalformedInputError(ValueError):
    """Raised for structurally invalid input (wrong type, corrupted encoding, etc.)."""


def _enforce_length_ceiling(value: str, field_type: str) -> None:
    limit = MAX_FIELD_LENGTHS.get(field_type, MAX_FIELD_LENGTHS["generic"])
    if len(value) > limit:
        raise PayloadTooLargeError(
            f"{field_type} field exceeds max length {limit} (got {len(value)})"
        )


def _coerce_to_str(value, field_type: str) -> str:
    """Fail closed on unexpected types instead of letting them propagate downstream."""
    if value is None:
        return ""
    if not isinstance(value, str):
        raise MalformedInputError(
            f"{field_type} field expected str, got {type(value).__name__}"
        )
    return value


# =========================================================================
# 1. DEEP STRING SANITIZATION
# =========================================================================

def strip_control_and_hidden_chars(value: str) -> str:
    """
    Removes:
      - Null bytes and all Unicode control chars (category Cc)
      - Format chars often used to hide payloads, e.g. zero-width joiners (Cf)
      - Private-use area chars (Co) sometimes abused for smuggling (Ce)
      - Bidi override characters (used in filename/domain spoofing attacks)
    """
    cleaned_chars = []
    for ch in value:
        category = unicodedata.category(ch)
        if category in ("Cc", "Cf", "Co", "Cs"):
            continue
        if ch in ("\u202a", "\u202b", "\u202c", "\u202d", "\u202e"):
            continue
        cleaned_chars.append(ch)
    return "".join(cleaned_chars)


def strip_html_tags(value: str) -> str:
    """
    Strips HTML/script content using html.parser, NOT regex.
    After stripping tags, remaining text is HTML-escaped.
    """

    class _TagStripper(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.text_parts = []

        def handle_data(self, data):
            self.text_parts.append(data)

    stripper = _TagStripper()
    try:
        stripper.feed(value)
        stripper.close()
    except Exception:
        logger.warning("strip_html_tags: malformed markup encountered, dropping field")
        return ""
    return html.escape("".join(stripper.text_parts), quote=True)


_ALLOWED_NAME_CHARS = set(string.ascii_letters + " '-.")
_ALLOWED_COMPANY_EXTRA = set(string.digits + "&,()/")
_ALLOWED_PHONE_CHARS = set(string.digits + "+()- .")


def sanitize_generic_string(raw_value, field_type: str = "generic") -> str:
    """
    Master sanitizer applied to every field before any specialized parsing.
    """
    value = _coerce_to_str(raw_value, field_type)
    _enforce_length_ceiling(value, field_type)
    value = strip_control_and_hidden_chars(value)
    value = unicodedata.normalize("NFKC", value)
    value = strip_html_tags(value)
    return value.strip()


# =========================================================================
# 2. EMAIL NORMALIZATION & RFC-5322-STYLE VALIDATION
# =========================================================================

_EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}"
    r"@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?){1,8}$"
)


@dataclass(frozen=True)
class EmailNormalizationResult:
    original: str
    normalized: Optional[str]
    is_valid_syntax: bool
    was_typo_corrected: bool
    typo_correction_applied: Optional[str]
    homoglyph_risk_detected: bool
    rejection_reason: Optional[str] = None


def normalize_email(raw_email) -> EmailNormalizationResult:
    original = raw_email if isinstance(raw_email, str) else str(raw_email)

    try:
        value = sanitize_generic_string(raw_email, field_type="email")
    except (PayloadTooLargeError, MalformedInputError) as e:
        return EmailNormalizationResult(
            original=original, normalized=None, is_valid_syntax=False,
            was_typo_corrected=False, typo_correction_applied=None,
            homoglyph_risk_detected=False, rejection_reason=str(e),
        )

    value = value.lower().replace(" ", "")

    if "@" not in value or value.count("@") != 1:
        return EmailNormalizationResult(
            original=original, normalized=None, is_valid_syntax=False,
            was_typo_corrected=False, typo_correction_applied=None,
            homoglyph_risk_detected=False, rejection_reason="malformed_at_symbol",
        )

    local, _, domain = value.partition("@")

    homoglyph_hit = detect_homoglyph_risk(domain)
    domain, corrected, correction_label = autocorrect_domain_typo(domain)
    value = f"{local}@{domain}"

    if not _EMAIL_PATTERN.match(value):
        return EmailNormalizationResult(
            original=original, normalized=None, is_valid_syntax=False,
            was_typo_corrected=corrected, typo_correction_applied=correction_label,
            homoglyph_risk_detected=homoglyph_hit, rejection_reason="failed_syntax_check",
        )

    return EmailNormalizationResult(
        original=original, normalized=value, is_valid_syntax=True,
        was_typo_corrected=corrected, typo_correction_applied=correction_label,
        homoglyph_risk_detected=homoglyph_hit, rejection_reason=None,
    )


# =========================================================================
# 3. TYPOSQUATTING / DOMAIN AUTO-FIX
# =========================================================================

_KNOWN_PROVIDERS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
    "aol.com", "protonmail.com", "live.com", "msn.com", "zoho.com",
]

_COMMON_TYPOS = {
    "gamil.com": "gmail.com", "gmial.com": "gmail.com", "gmai.com": "gmail.com",
    "gmail.co": "gmail.com", "gmail.cm": "gmail.com",
    "yaho.com": "yahoo.com", "yahho.com": "yahoo.com", "yahoo.co": "yahoo.com",
    "hotmal.com": "hotmail.com", "hotmial.com": "hotmail.com",
    "outlok.com": "outlook.com", "outllook.com": "outlook.com",
}


def autocorrect_domain_typo(domain: str) -> tuple[str, bool, Optional[str]]:
    if domain in _COMMON_TYPOS:
        fixed = _COMMON_TYPOS[domain]
        return fixed, True, f"{domain}->{fixed}"

    best_match, best_score = None, 0.0
    for known in _KNOWN_PROVIDERS:
        score = SequenceMatcher(None, domain, known).ratio()
        if score > best_score:
            best_match, best_score = known, score

    if best_match and best_score >= 0.86 and domain != best_match:
        return best_match, True, f"{domain}->{best_match}"

    return domain, False, None


# =========================================================================
# 4. UNICODE / HOMOGLYPH ATTACK DEFENSE
# =========================================================================

_CONFUSABLE_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ѕ": "s", "ј": "j", "ԁ": "d", "ɡ": "g",
    "α": "a", "ο": "o", "ρ": "p", "τ": "t", "υ": "u",
}


def detect_homoglyph_risk(domain: str) -> bool:
    working_domain = domain
    if "xn--" in domain:
        try:
            working_domain = domain.encode("ascii").decode("idna")
        except Exception:
            return True

    scripts_seen = set()
    confusable_hit = False
    for ch in working_domain:
        if ch in _CONFUSABLE_MAP:
            confusable_hit = True
        if ch.isalpha():
            try:
                script_name = unicodedata.name(ch, "").split(" ")[0]
                scripts_seen.add(script_name)
            except Exception:
                pass

    mixed_script = len(scripts_seen) > 1
    return confusable_hit or mixed_script


def strip_diacritics(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    return "".join(ch for ch in normalized if not unicodedata.combining(ch))


# =========================================================================
# 6. SMART NAME & FIELD PARSING
# =========================================================================

_SALUTATIONS = {"mr", "mrs", "ms", "miss", "dr", "prof", "sir", "madam", "rev"}


@dataclass(frozen=True)
class ParsedName:
    salutation: Optional[str]
    first_name: str
    last_name: str
    raw: str


def parse_name(raw_name) -> ParsedName:
    value = sanitize_generic_string(raw_name, field_type="name")
    value = strip_diacritics(value)

    value = "".join(ch for ch in value if ch in _ALLOWED_NAME_CHARS)
    value = re.sub(r" {2,}", " ", value).strip()

    if not value:
        return ParsedName(salutation=None, first_name="", last_name="", raw=raw_name if isinstance(raw_name, str) else "")

    tokens = value.split(" ")
    salutation = None
    if tokens and tokens[0].rstrip(".").lower() in _SALUTATIONS:
        salutation = tokens.pop(0).rstrip(".").capitalize()

    if not tokens:
        return ParsedName(salutation=salutation, first_name="", last_name="", raw=value)
    if len(tokens) == 1:
        return ParsedName(salutation=salutation, first_name=tokens[0].capitalize(), last_name="", raw=value)

    first = tokens[0].capitalize()
    last = " ".join(t.capitalize() for t in tokens[1:])
    return ParsedName(salutation=salutation, first_name=first, last_name=last, raw=value)


# =========================================================================
# 7. PHONE / ADDRESS / COMPANY BASIC SANITIZATION
# =========================================================================

def sanitize_phone(raw_phone) -> str:
    value = sanitize_generic_string(raw_phone, field_type="phone")
    return "".join(ch for ch in value if ch in _ALLOWED_PHONE_CHARS).strip()


def sanitize_address(raw_address) -> str:
    value = sanitize_generic_string(raw_address, field_type="address")
    disallowed = set("<>;{}\\`")
    return "".join(ch for ch in value if ch not in disallowed).strip()


def sanitize_company(raw_company) -> str:
    value = sanitize_generic_string(raw_company, field_type="company")
    allowed = _ALLOWED_NAME_CHARS | _ALLOWED_COMPANY_EXTRA
    return "".join(ch for ch in value if ch in allowed).strip()


# =========================================================================
# TENANT-SCOPED ORCHESTRATION & PIPELINE ADAPTER LAYER
# =========================================================================

@dataclass(frozen=True)
class TenantContext:
    tenant_id: str


@dataclass(frozen=True)
class NormalizedRecord:
    tenant_id: str
    email_result: EmailNormalizationResult
    parsed_name: ParsedName
    phone: str
    address: str
    company: str
    errors: list = field(default_factory=list)


def normalize_record(tenant_ctx: TenantContext, raw_record: dict) -> NormalizedRecord:
    errors = []

    def _safe(fn, *args):
        try:
            return fn(*args)
        except (PayloadTooLargeError, MalformedInputError) as e:
            errors.append(f"{fn.__name__}: {e}")
            return None
        except Exception as e:
            logger.exception("normalize_record: unexpected failure in %s", fn.__name__)
            errors.append(f"{fn.__name__}: unexpected_error")
            return None

    email_result = _safe(normalize_email, raw_record.get("email")) or EmailNormalizationResult(
        original="", normalized=None, is_valid_syntax=False, was_typo_corrected=False,
        typo_correction_applied=None, homoglyph_risk_detected=False, rejection_reason="processing_failed",
    )
    
    # Check both 'name' or separate 'first_name'/'last_name' fields
    raw_name_input = raw_record.get("name") or f"{raw_record.get('first_name', '')} {raw_record.get('last_name', '')}".strip()
    parsed_name = _safe(parse_name, raw_name_input) or ParsedName(None, "", "", "")
    
    phone = _safe(sanitize_phone, raw_record.get("phone")) or ""
    address = _safe(sanitize_address, raw_record.get("address")) or ""
    company = _safe(sanitize_company, raw_record.get("company")) or ""

    return NormalizedRecord(
        tenant_id=tenant_ctx.tenant_id,
        email_result=email_result,
        parsed_name=parsed_name,
        phone=phone,
        address=address,
        company=company,
        errors=errors,
    )


def run_engine_01(records: List[Dict[str, Any]], tenant_id: str = "default_tenant") -> List[Dict[str, Any]]:
    """
    Main Pipeline Wrapper for Engine 01.
    Converts raw record list into securely normalized dicts for downstream engines.
    """
    tenant_ctx = TenantContext(tenant_id=tenant_id)
    processed_records = []

    for raw in records:
        norm_obj = normalize_record(tenant_ctx, raw)
        
        # Build clean output record while retaining unhandled metadata
        clean_dict = dict(raw)
        clean_dict["email"] = norm_obj.email_result.normalized or norm_obj.email_result.original
        clean_dict["email_syntax_valid"] = norm_obj.email_result.is_valid_syntax
        clean_dict["email_typo_corrected"] = norm_obj.email_result.was_typo_corrected
        clean_dict["homoglyph_risk"] = norm_obj.email_result.homoglyph_risk_detected
        
        clean_dict["salutation"] = norm_obj.parsed_name.salutation or ""
        clean_dict["first_name"] = norm_obj.parsed_name.first_name
        clean_dict["last_name"] = norm_obj.parsed_name.last_name
        
        clean_dict["phone"] = norm_obj.phone
        clean_dict["address"] = norm_obj.address
        clean_dict["company"] = norm_obj.company
        
        clean_dict["_engine_01_errors"] = norm_obj.errors
        clean_dict["_meta_normalized"] = True
        
        processed_records.append(clean_dict)

    return processed_records
