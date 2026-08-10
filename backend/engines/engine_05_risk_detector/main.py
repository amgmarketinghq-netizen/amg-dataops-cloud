"""
Engine 05 — Risk Engine, Threat Intelligence & 20 B2B Industry Sector
Classification Engine
AMG DataOps Cloud

Design principles:
  - Immutable threat-intel sets & 20 B2B sector keyword dictionaries.
  - Zero ReDoS surface: tokenize -> bounded token list -> O(1) set lookups.
  - Fail closed: malformed input produces neutral score (50) and UNKNOWN_SECTOR.
  - Multi-vector risk scoring (0-100).
"""

from __future__ import annotations

import re
import math
import unicodedata
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

logger = logging.getLogger("engine05")


# =========================================================================
# 0. TYPED TAGS & SAFETY CEILINGS
# =========================================================================

class RiskTag:
    SPAM_TRAP_MATCH = "SPAM_TRAP_MATCH"
    HIGH_RISK_TLD = "HIGH_RISK_TLD"
    DISPOSABLE_SIGNAL = "DISPOSABLE_SIGNAL"
    ROLE_BASED_SIGNAL = "ROLE_BASED_SIGNAL"
    CATCH_ALL_SIGNAL = "CATCH_ALL_SIGNAL"
    VOIP_PHONE_SIGNAL = "VOIP_PHONE_SIGNAL"
    DUMMY_PHONE_SIGNAL = "DUMMY_PHONE_SIGNAL"
    BOT_GENERATED_PATTERN = "BOT_GENERATED_PATTERN"
    UNKNOWN_RISK = "UNKNOWN_RISK"
    UNKNOWN_SECTOR = "UNKNOWN_SECTOR"
    OVERSIZED_INPUT = "OVERSIZED_INPUT"


MAX_FIELD_LEN = 300
MAX_TOKENS = 60
MAX_PHRASE_WINDOW = 3
NEUTRAL_SCORE_DEFAULT = 50
MIN_SCORE, MAX_SCORE = 0, 100

ENTROPY_HIGH_THRESHOLD = 3.8
MIN_LEN_FOR_ENTROPY_CHECK = 6


class MalformedInputError(ValueError):
    pass


# =========================================================================
# 1. NORMALIZATION & TOKENIZATION
# =========================================================================

def _strip_diacritics(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    return "".join(ch for ch in normalized if not unicodedata.combining(ch))


_ALLOWED_CLASSIFY_CHARS_PATTERN = re.compile(r"[^a-z0-9 ]")


def normalize_for_classification(value) -> str:
    if not isinstance(value, str) or not value:
        return ""
    if len(value) > MAX_FIELD_LEN:
        value = value[:MAX_FIELD_LEN]
    value = unicodedata.normalize("NFKC", value)
    value = _strip_diacritics(value)
    value = value.lower()
    value = _ALLOWED_CLASSIFY_CHARS_PATTERN.sub(" ", value)
    return re.sub(r" {2,}", " ", value).strip()


def tokenize(value: str) -> list[str]:
    if not value:
        return []
    return value.split(" ")[:MAX_TOKENS]


# =========================================================================
# 2. THREAT DATASETS
# =========================================================================

HIGH_RISK_TLDS: frozenset[str] = frozenset({
    "xyz", "top", "tk", "work", "click", "gq", "cf", "ml", "loan",
    "racing", "review", "download", "stream", "win", "bid", "party",
})

SPAM_TRAP_DOMAINS: frozenset[str] = frozenset({
    "spamtrap-example.com", "honeypot-test.net", "trap-domain.org",
})


def get_tld(domain: str) -> Optional[str]:
    if not domain or "." not in domain:
        return None
    parts = domain.rsplit(".", 1)
    return parts[-1].lower() if len(parts) == 2 else None


def check_domain_threat_signals(domain: Optional[str]) -> tuple[list[str], int]:
    if not domain or not isinstance(domain, str):
        return [], 0

    domain_lower = domain.lower().strip()
    tags: list[str] = []
    points = 0

    if domain_lower in SPAM_TRAP_DOMAINS:
        tags.append(RiskTag.SPAM_TRAP_MATCH)
        points += 60

    tld = get_tld(domain_lower)
    if tld and tld in HIGH_RISK_TLDS:
        tags.append(RiskTag.HIGH_RISK_TLD)
        points += 20

    return tags, points


# =========================================================================
# 3. BOT-GENERATED PATTERN DETECTION
# =========================================================================

_KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]
_KEYBOARD_SUBSTRINGS: frozenset[str] = frozenset(
    row[i:i + 4] for row in _KEYBOARD_ROWS + [r[::-1] for r in _KEYBOARD_ROWS]
    for i in range(len(row) - 3)
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(value)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def contains_keyboard_mash(value: str) -> bool:
    cleaned = "".join(ch for ch in value.lower() if ch.isalpha())
    if len(cleaned) < 4:
        return False
    for i in range(len(cleaned) - 3):
        if cleaned[i:i + 4] in _KEYBOARD_SUBSTRINGS:
            return True
    return False


def detect_bot_generated_pattern(value: Optional[str]) -> bool:
    try:
        if not value or not isinstance(value, str):
            return False
        cleaned = value.strip()
        if len(cleaned) < MIN_LEN_FOR_ENTROPY_CHECK:
            return contains_keyboard_mash(cleaned)
        alpha_only = "".join(ch for ch in cleaned.lower() if ch.isalpha())
        if not alpha_only:
            return False
        entropy = shannon_entropy(alpha_only)
        high_entropy = entropy >= ENTROPY_HIGH_THRESHOLD and len(set(alpha_only)) >= 5
        return high_entropy or contains_keyboard_mash(cleaned)
    except Exception:
        logger.exception("detect_bot_generated_pattern: unexpected failure, failing closed")
        return False


# =========================================================================
# 4. 20 B2B SECTOR CLASSIFICATION
# =========================================================================

SECTOR_KEYWORDS: dict[str, frozenset[str]] = {
    "IT & SaaS / Software": frozenset({"software", "saas", "cloud", "api", "tech", "app", "platform", "data", "ai", "digital", "systems", "solutions", "labs"}),
    "Healthcare & Pharma": frozenset({"health", "medical", "pharma", "clinic", "hospital", "care", "diagnostics", "biotech", "wellness", "therapeutics"}),
    "BFSI (Banking & Finance)": frozenset({"bank", "finance", "capital", "invest", "insurance", "credit", "wealth", "fintech", "lending", "asset"}),
    "E-Commerce & Retail": frozenset({"shop", "store", "retail", "ecommerce", "commerce", "mart", "market", "boutique", "goods"}),
    "Real Estate & Property": frozenset({"realty", "property", "estate", "realtor", "housing", "homes", "land", "developers"}),
    "Manufacturing & Heavy Industry": frozenset({"manufacturing", "industries", "factory", "steel", "machinery", "industrial", "fabrication", "engineering"}),
    "Education & EdTech": frozenset({"school", "university", "college", "academy", "edtech", "learning", "education", "institute", "training"}),
    "Marketing & Advertising": frozenset({"marketing", "advertising", "agency", "media", "branding", "creative", "digital", "campaigns", "pr"}),
    "Media & Entertainment": frozenset({"media", "entertainment", "studio", "films", "music", "gaming", "broadcast", "production"}),
    "Logistics & Supply Chain": frozenset({"logistics", "supply", "freight", "shipping", "cargo", "transport", "warehouse", "fleet"}),
    "Automotive & EV": frozenset({"auto", "automotive", "motors", "vehicle", "ev", "cars", "mobility", "garage"}),
    "Energy & Renewable Utilities": frozenset({"energy", "solar", "power", "utilities", "renewable", "electric", "grid", "wind"}),
    "Telecommunications": frozenset({"telecom", "wireless", "network", "communications", "broadband", "mobile", "carrier"}),
    "Hospitality & Tourism": frozenset({"hotel", "hospitality", "travel", "tourism", "resort", "restaurant", "leisure"}),
    "Professional Services": frozenset({"consulting", "advisory", "legal", "law", "accounting", "audit", "services", "partners"}),
    "Agriculture & FoodTech": frozenset({"agriculture", "farm", "food", "agritech", "crop", "dairy", "harvest"}),
    "Consumer Goods (FMCG)": frozenset({"fmcg", "consumer", "goods", "brands", "products", "packaged"}),
    "Aerospace & Defense": frozenset({"aerospace", "defense", "aviation", "aircraft", "military", "space"}),
    "Government & Public Services": frozenset({"government", "municipal", "public", "federal", "state", "gov", "administration"}),
    "NGO & Non-Profit": frozenset({"foundation", "nonprofit", "ngo", "charity", "trust", "relief", "welfare"}),
}

SECTOR_PHRASES: dict[str, frozenset[str]] = {
    "IT & SaaS / Software": frozenset({"machine learning", "web development"}),
    "BFSI (Banking & Finance)": frozenset({"venture capital", "private equity"}),
    "Real Estate & Property": frozenset({"real estate"}),
    "Energy & Renewable Utilities": frozenset({"renewable energy", "solar power"}),
    "Government & Public Services": frozenset({"public sector"}),
}


def classify_sector(company_name: Optional[str], domain: Optional[str]) -> tuple[str, int]:
    combined_raw = " ".join(filter(None, [
        company_name if isinstance(company_name, str) else "",
        (domain.split(".")[0] if isinstance(domain, str) and domain else ""),
    ]))
    normalized = normalize_for_classification(combined_raw)
    if not normalized:
        return "Unknown / Unclassified", 0

    tokens = tokenize(normalized)
    if not tokens:
        return "Unknown / Unclassified", 0

    scores: dict[str, int] = {sector: 0 for sector in SECTOR_KEYWORDS}

    for token in tokens:
        for sector, keywords in SECTOR_KEYWORDS.items():
            if token in keywords:
                scores[sector] += 1

    window_limit = min(len(tokens), MAX_TOKENS)
    for window_size in range(2, MAX_PHRASE_WINDOW + 1):
        for i in range(window_limit - window_size + 1):
            phrase = " ".join(tokens[i:i + window_size])
            for sector, phrases in SECTOR_PHRASES.items():
                if phrase in phrases:
                    scores[sector] += 2

    best_sector = max(scores, key=lambda s: scores[s])
    best_score = scores[best_sector]

    if best_score == 0:
        return "Unknown / Unclassified", 0

    confidence = min(100, best_score * 25)
    return best_sector, confidence


# =========================================================================
# 5. COMPOSITE RISK SCORING
# =========================================================================

@dataclass(frozen=True)
class RiskInput:
    record_id: str
    email_domain: Optional[str] = None
    is_disposable_email: bool = False
    is_role_based_email: bool = False
    is_catch_all_domain: bool = False
    is_voip_phone: bool = False
    is_dummy_phone_pattern: bool = False
    company_name: Optional[str] = None
    contact_name: Optional[str] = None


@dataclass(frozen=True)
class RiskResult:
    record_id: str
    risk_score: int
    risk_tags: list
    sector: str
    sector_confidence: int


def compute_risk_score(risk_input: RiskInput) -> RiskResult:
    try:
        tags: list[str] = []
        score = 0

        domain_tags, domain_points = check_domain_threat_signals(risk_input.email_domain)
        tags.extend(domain_tags)
        score += domain_points

        if risk_input.is_disposable_email:
            tags.append(RiskTag.DISPOSABLE_SIGNAL)
            score += 25
        if risk_input.is_role_based_email:
            tags.append(RiskTag.ROLE_BASED_SIGNAL)
            score += 5
        if risk_input.is_catch_all_domain:
            tags.append(RiskTag.CATCH_ALL_SIGNAL)
            score += 10
        if risk_input.is_voip_phone:
            tags.append(RiskTag.VOIP_PHONE_SIGNAL)
            score += 15
        if risk_input.is_dummy_phone_pattern:
            tags.append(RiskTag.DUMMY_PHONE_SIGNAL)
            score += 20

        if detect_bot_generated_pattern(risk_input.contact_name) or detect_bot_generated_pattern(risk_input.company_name):
            tags.append(RiskTag.BOT_GENERATED_PATTERN)
            score += 30

        final_score = max(MIN_SCORE, min(MAX_SCORE, score))

        sector, sector_confidence = classify_sector(risk_input.company_name, risk_input.email_domain)

        return RiskResult(
            record_id=risk_input.record_id,
            risk_score=final_score,
            risk_tags=tags,
            sector=sector,
            sector_confidence=sector_confidence,
        )
    except Exception:
        logger.exception("compute_risk_score: unexpected failure for record %s, failing to neutral", risk_input.record_id)
        return RiskResult(
            record_id=risk_input.record_id,
            risk_score=NEUTRAL_SCORE_DEFAULT,
            risk_tags=[RiskTag.UNKNOWN_RISK],
            sector="Unknown / Unclassified",
            sector_confidence=0,
        )


# =========================================================================
# 6. PIPELINE ADAPTER WRAPPER
# =========================================================================

def run_engine_05(records: List[Dict[str, Any]], tenant_id: str = "default_tenant") -> List[Dict[str, Any]]:
    """
    Main Pipeline Wrapper for Engine 05.
    Evaluates risk score (0-100) & classifies into 20 B2B Industry Sectors.
    """
    if not tenant_id:
        raise MalformedInputError("tenant_id is required")

    processed_records = []
    for idx, rec in enumerate(records):
        rec_id = str(rec.get("id") or f"rec_{idx}")
        
        # Extract email domain if not directly provided
        email = rec.get("email", "")
        email_domain = rec.get("email_domain") or (email.split("@")[1] if "@" in email else None)
        
        # Check phone dummy tags from Engine 04
        phone_tags = rec.get("phone_tags", [])
        is_dummy_phone = "DUMMY_SEQUENCE" in phone_tags or "REPEATING_DIGITS" in phone_tags
        is_voip = rec.get("phone_line_type") == "LINE_VOIP" or "LINE_VOIP" in phone_tags

        contact_name = f"{rec.get('first_name', '')} {rec.get('last_name', '')}".strip() or rec.get("name") or rec.get("contact_name")

        try:
            risk_input = RiskInput(
                record_id=rec_id,
                email_domain=email_domain,
                is_disposable_email=bool(rec.get("is_disposable", False)),
                is_role_based_email=bool(rec.get("is_role_based", False)),
                is_catch_all_domain=bool(rec.get("is_catch_all", False)),
                is_voip_phone=is_voip,
                is_dummy_phone_pattern=is_dummy_phone,
                company_name=rec.get("company"),
                contact_name=contact_name,
            )
            result = compute_risk_score(risk_input)
        except Exception:
            logger.exception("run_engine_05: unexpected failure for record %s", rec_id)
            result = RiskResult(rec_id, NEUTRAL_SCORE_DEFAULT, [RiskTag.UNKNOWN_RISK], "Unknown / Unclassified", 0)

        clean_dict = dict(rec)
        clean_dict["risk_score"] = result.risk_score
        clean_dict["risk_tags"] = result.risk_tags
        clean_dict["industry_sector"] = result.sector
        clean_dict["sector_confidence"] = result.sector_confidence
        clean_dict["_meta_risk_evaluated"] = True

        processed_records.append(clean_dict)

    return processed_records
