"""
Engine 04 — Global Phone Formatting & Carrier Intelligence Engine
AMG DataOps Cloud

Design principles:
  - Built on Google's `phonenumbers` library (libphonenumber Python port).
  - Explicit tenant default_region (never cached globally).
  - ReDoS-safe digit extraction & NFKC Unicode digit normalization.
  - Fraud/Dummy sequence detection (sequential, repeating numbers).
  - VoIP, Landline, Mobile, Toll-Free, and Premium Rate classification.
"""

from __future__ import annotations

import re
import unicodedata
import logging
from dataclasses import dataclass
from typing import Optional, List, Dict, Any

try:
    import phonenumbers
    from phonenumbers import PhoneNumberFormat, NumberParseException
    from phonenumbers.phonenumberutil import PhoneNumberType
    _PHONENUMBERS_AVAILABLE = True
except ImportError:
    _PHONENUMBERS_AVAILABLE = False

logger = logging.getLogger("engine04")


# =========================================================================
# 0. TYPED RESULT TAGS & SAFETY CEILINGS
# =========================================================================

class PhoneTag:
    VALID_E164 = "VALID_E164"
    INVALID_PHONE_LENGTH = "INVALID_PHONE_LENGTH"
    EMPTY_INPUT = "EMPTY_INPUT"
    OVERSIZED_INPUT = "OVERSIZED_INPUT"
    AMBIGUOUS_REGION = "AMBIGUOUS_REGION"
    UNPARSEABLE = "UNPARSEABLE"
    DUMMY_SEQUENCE = "DUMMY_SEQUENCE"
    REPEATING_DIGITS = "REPEATING_DIGITS"
    DEPENDENCY_MISSING = "DEPENDENCY_MISSING"

    LINE_MOBILE = "LINE_MOBILE"
    LINE_LANDLINE = "LINE_LANDLINE"
    LINE_TOLL_FREE = "LINE_TOLL_FREE"
    LINE_PREMIUM_RATE = "LINE_PREMIUM_RATE"
    LINE_VOIP = "LINE_VOIP"
    LINE_UNKNOWN = "LINE_UNKNOWN"

    VOIP_RISK = "VOIP_RISK"
    PREMIUM_RATE_RISK = "PREMIUM_RATE_RISK"


MAX_RAW_INPUT_LEN = 40
MIN_NATIONAL_DIGITS = 4
MAX_NATIONAL_DIGITS = 15


class MalformedInputError(ValueError):
    pass


# =========================================================================
# 1. REDOS-SAFE EXTRACTION
# =========================================================================

_ALLOWED_CHARS_PATTERN = re.compile(r"[^0-9+]")


def extract_raw_digits(value: str) -> str:
    if not isinstance(value, str):
        return ""
    if len(value) > MAX_RAW_INPUT_LEN:
        return ""
    cleaned = _ALLOWED_CHARS_PATTERN.sub("", value)
    if cleaned.startswith("+"):
        cleaned = "+" + cleaned[1:].replace("+", "")
    else:
        cleaned = cleaned.replace("+", "")
    return cleaned


# =========================================================================
# 2. NON-ASCII DIGIT NORMALIZATION
# =========================================================================

def normalize_unicode_digits(value: str) -> str:
    out_chars = []
    for ch in value:
        if ch in ("+",):
            out_chars.append(ch)
            continue
        try:
            digit_val = unicodedata.digit(ch)
            out_chars.append(str(digit_val))
        except (TypeError, ValueError):
            out_chars.append(ch)
    return "".join(out_chars)


# =========================================================================
# 3. FRAUD / DUMMY PATTERN DETECTION
# =========================================================================

def is_repeating_digit_sequence(digits: str) -> bool:
    if not digits:
        return False
    return len(set(digits)) == 1


def is_sequential_digit_pattern(digits: str) -> bool:
    if len(digits) < 4:
        return False

    ascending = all(
        int(digits[i + 1]) == (int(digits[i]) + 1) % 10 for i in range(len(digits) - 1)
    )
    descending = all(
        int(digits[i + 1]) == (int(digits[i]) - 1) % 10 for i in range(len(digits) - 1)
    )
    alternating = len(set(digits)) == 2 and all(
        digits[i] == digits[i % 2] for i in range(len(digits))
    )
    return ascending or descending or alternating


def detect_dummy_pattern(national_digits: str) -> Optional[str]:
    if is_repeating_digit_sequence(national_digits):
        return PhoneTag.REPEATING_DIGITS
    if is_sequential_digit_pattern(national_digits):
        return PhoneTag.DUMMY_SEQUENCE
    return None


# =========================================================================
# 4. PARSING & LINE-TYPE CLASSIFICATION
# =========================================================================

_LINE_TYPE_MAP = {}
if _PHONENUMBERS_AVAILABLE:
    _LINE_TYPE_MAP = {
        PhoneNumberType.MOBILE: PhoneTag.LINE_MOBILE,
        PhoneNumberType.FIXED_LINE: PhoneTag.LINE_LANDLINE,
        PhoneNumberType.FIXED_LINE_OR_MOBILE: PhoneTag.LINE_MOBILE,
        PhoneNumberType.TOLL_FREE: PhoneTag.LINE_TOLL_FREE,
        PhoneNumberType.PREMIUM_RATE: PhoneTag.LINE_PREMIUM_RATE,
        PhoneNumberType.VOIP: PhoneTag.LINE_VOIP,
        PhoneNumberType.PERSONAL_NUMBER: PhoneTag.LINE_UNKNOWN,
        PhoneNumberType.PAGER: PhoneTag.LINE_UNKNOWN,
        PhoneNumberType.UAN: PhoneTag.LINE_UNKNOWN,
        PhoneNumberType.VOICEMAIL: PhoneTag.LINE_UNKNOWN,
        PhoneNumberType.UNKNOWN: PhoneTag.LINE_UNKNOWN,
    }


@dataclass(frozen=True)
class PhoneParseResult:
    record_id: str
    raw_input: str
    e164: Optional[str]
    national_number: Optional[str]
    country_code: Optional[int]
    region_used: Optional[str]
    line_type_tag: str
    tags: list


def parse_and_classify_phone(
    record_id: str,
    raw_phone,
    default_region: Optional[str],
) -> PhoneParseResult:
    tags: list[str] = []

    if raw_phone is None or (isinstance(raw_phone, str) and raw_phone.strip() == ""):
        return PhoneParseResult(record_id, "", None, None, None, None, PhoneTag.LINE_UNKNOWN, [PhoneTag.EMPTY_INPUT])

    if not isinstance(raw_phone, str):
        return PhoneParseResult(record_id, str(raw_phone), None, None, None, None,
                                 PhoneTag.LINE_UNKNOWN, [PhoneTag.UNPARSEABLE])

    if len(raw_phone) > MAX_RAW_INPUT_LEN:
        return PhoneParseResult(record_id, raw_phone[:MAX_RAW_INPUT_LEN], None, None, None, None,
                                 PhoneTag.LINE_UNKNOWN, [PhoneTag.OVERSIZED_INPUT])

    normalized = normalize_unicode_digits(raw_phone)
    digits_only = extract_raw_digits(normalized)

    if not digits_only or len(digits_only.lstrip("+")) < MIN_NATIONAL_DIGITS:
        return PhoneParseResult(record_id, raw_phone, None, None, None, None,
                                 PhoneTag.LINE_UNKNOWN, [PhoneTag.INVALID_PHONE_LENGTH])

    if len(digits_only.lstrip("+")) > MAX_NATIONAL_DIGITS:
        return PhoneParseResult(record_id, raw_phone, None, None, None, None,
                                 PhoneTag.LINE_UNKNOWN, [PhoneTag.INVALID_PHONE_LENGTH])

    if not _PHONENUMBERS_AVAILABLE:
        return PhoneParseResult(record_id, raw_phone, None, None, None, None,
                                 PhoneTag.LINE_UNKNOWN, [PhoneTag.DEPENDENCY_MISSING])

    if not digits_only.startswith("+") and not default_region:
        return PhoneParseResult(record_id, raw_phone, None, None, None, None,
                                 PhoneTag.LINE_UNKNOWN, [PhoneTag.AMBIGUOUS_REGION])

    try:
        parsed = phonenumbers.parse(digits_only, default_region)
    except NumberParseException:
        return PhoneParseResult(record_id, raw_phone, None, None, None, None,
                                 PhoneTag.LINE_UNKNOWN, [PhoneTag.UNPARSEABLE])
    except Exception:
        logger.exception("parse_and_classify_phone: unexpected failure for record %s", record_id)
        return PhoneParseResult(record_id, raw_phone, None, None, None, None,
                                 PhoneTag.LINE_UNKNOWN, [PhoneTag.UNPARSEABLE])

    if not phonenumbers.is_valid_number(parsed):
        return PhoneParseResult(record_id, raw_phone, None, None, parsed.country_code, default_region,
                                 PhoneTag.LINE_UNKNOWN, [PhoneTag.UNPARSEABLE])

    e164 = phonenumbers.format_number(parsed, PhoneNumberFormat.E164)
    national_digits = str(parsed.national_number)
    region_used = phonenumbers.region_code_for_number(parsed) or default_region

    number_type = phonenumbers.number_type(parsed)
    line_type_tag = _LINE_TYPE_MAP.get(number_type, PhoneTag.LINE_UNKNOWN)
    tags.append(PhoneTag.VALID_E164)
    tags.append(line_type_tag)

    dummy_tag = detect_dummy_pattern(national_digits)
    if dummy_tag:
        tags.append(dummy_tag)

    if line_type_tag == PhoneTag.LINE_VOIP:
        tags.append(PhoneTag.VOIP_RISK)
    if line_type_tag == PhoneTag.LINE_PREMIUM_RATE:
        tags.append(PhoneTag.PREMIUM_RATE_RISK)

    return PhoneParseResult(
        record_id=record_id,
        raw_input=raw_phone,
        e164=e164,
        national_number=national_digits,
        country_code=parsed.country_code,
        region_used=region_used,
        line_type_tag=line_type_tag,
        tags=tags,
    )


# =========================================================================
# 5. PIPELINE WRAPPER
# =========================================================================

def run_engine_04(
    records: List[Dict[str, Any]],
    tenant_id: str = "default_tenant",
    default_region: Optional[str] = "IN",
) -> List[Dict[str, Any]]:
    """
    Main Pipeline Wrapper for Engine 04.
    Standardizes raw phone numbers to E.164 and adds carrier intelligence metadata.
    """
    if not tenant_id:
        raise MalformedInputError("tenant_id is required")

    processed_records = []
    for idx, rec in enumerate(records):
        rec_id = str(rec.get("id") or f"rec_{idx}")
        raw_phone = rec.get("phone")
        try:
            result = parse_and_classify_phone(rec_id, raw_phone, default_region)
        except Exception:
            logger.exception("run_engine_04: unexpected failure for record %s", rec_id)
            result = PhoneParseResult(rec_id, str(raw_phone), None, None, None, None,
                                     PhoneTag.LINE_UNKNOWN, [PhoneTag.UNPARSEABLE])

        clean_dict = dict(rec)
        clean_dict["phone"] = result.e164 or result.raw_input
        clean_dict["phone_e164"] = result.e164
        clean_dict["phone_country_code"] = result.country_code
        clean_dict["phone_line_type"] = result.line_type_tag
        clean_dict["phone_tags"] = result.tags
        clean_dict["_meta_phone_processed"] = True

        processed_records.append(clean_dict)

    return processed_records
