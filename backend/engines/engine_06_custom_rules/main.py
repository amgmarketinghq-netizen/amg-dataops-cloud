"""
Engine 06 — Dynamic Rules Evaluator Engine
AMG DataOps Cloud

Design principles:
  - ABSOLUTE BAN on eval(), exec(), or getattr()-based field access.
  - Dict lookup restricted to ALLOWED_RECORD_FIELDS whitelist.
  - Zero mutable global state across tenant calls.
  - Immutable record transformations (returns new dicts).
  - ReDoS linter & AST tree depth caps.
"""

from __future__ import annotations

import re
import signal
import logging
import numbers
from dataclasses import dataclass, field as dc_field
from typing import Optional, Union, List, Dict, Any

logger = logging.getLogger("engine06")


# =========================================================================
# 0. SAFETY CEILINGS & ALLOW-LISTS
# =========================================================================

MAX_TREE_DEPTH = 15
MAX_NODES_PER_RULE = 300
MAX_RULES_PER_TENANT = 100
MAX_IN_LIST_SIZE = 500
MAX_REGEX_PATTERN_LEN = 200
MAX_SUBJECT_STRING_LEN = 1000
MAX_QUANTIFIERS_IN_PATTERN = 4
REGEX_TIMEOUT_SECONDS = 1

# Synced with Engine 01 through Engine 05 outputs
ALLOWED_RECORD_FIELDS: frozenset[str] = frozenset({
    "email", "email_domain", "phone", "phone_e164", "phone_country_code",
    "phone_line_type", "phone_national", "company_name", "company",
    "contact_name", "name", "first_name", "last_name", "address", "sector",
    "industry_sector", "sector_confidence", "risk_score", "line_type",
    "is_disposable", "is_role_based", "is_catch_all", "has_mx_records",
    "is_duplicate", "is_disposable_email", "is_role_based_email",
    "is_voip_phone", "is_catch_all_domain", "country_code"
})

ALLOWED_MASK_FIELDS = ALLOWED_RECORD_FIELDS
ALLOWED_OVERWRITE_FIELDS = ALLOWED_RECORD_FIELDS

_QUEUE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class RuleParseError(ValueError):
    pass


class RuleEvalError(ValueError):
    pass


# =========================================================================
# 1. OPERATORS & ACTIONS
# =========================================================================

class Operator:
    EQUALS = "EQUALS"
    NOT_EQUALS = "NOT_EQUALS"
    CONTAINS = "CONTAINS"
    NOT_CONTAINS = "NOT_CONTAINS"
    GREATER_THAN = "GREATER_THAN"
    LESS_THAN = "LESS_THAN"
    IN_LIST = "IN_LIST"
    REGEX_MATCH = "REGEX_MATCH"


VALID_OPERATORS = frozenset({
    Operator.EQUALS, Operator.NOT_EQUALS, Operator.CONTAINS, Operator.NOT_CONTAINS,
    Operator.GREATER_THAN, Operator.LESS_THAN, Operator.IN_LIST, Operator.REGEX_MATCH,
})


class ActionType:
    DROP_RECORD = "DROP_RECORD"
    FLAG_RECORD = "FLAG_RECORD"
    MASK_FIELD = "MASK_FIELD"
    OVERWRITE_FIELD = "OVERWRITE_FIELD"
    ROUTE_TO_QUEUE = "ROUTE_TO_QUEUE"


VALID_ACTIONS = frozenset({
    ActionType.DROP_RECORD, ActionType.FLAG_RECORD, ActionType.MASK_FIELD,
    ActionType.OVERWRITE_FIELD, ActionType.ROUTE_TO_QUEUE,
})


# =========================================================================
# 2. TYPED AST NODES
# =========================================================================

@dataclass(frozen=True)
class ConditionNode:
    field: str
    operator: str
    value: object


@dataclass(frozen=True)
class LogicalNode:
    logic_type: str
    children: tuple


RuleNode = Union[ConditionNode, LogicalNode]


@dataclass(frozen=True)
class RuleAction:
    action_type: str
    field: Optional[str] = None
    value: Optional[object] = None
    mask_char: str = "*"
    queue_name: Optional[str] = None


@dataclass(frozen=True)
class CompiledRule:
    rule_id: str
    root: RuleNode
    actions: tuple


# =========================================================================
# 3. REGEX SAFETY LINTER
# =========================================================================

_NESTED_QUANTIFIER_HINTS = ("+)+", "+)*", "*)*", "*)+", "{2,}){2,}")


def is_regex_pattern_safe(pattern: str) -> bool:
    if not isinstance(pattern, str) or not pattern:
        return False
    if len(pattern) > MAX_REGEX_PATTERN_LEN:
        return False
    if pattern.count("(") != pattern.count(")"):
        return False
    for hint in _NESTED_QUANTIFIER_HINTS:
        if hint in pattern:
            return False
    quantifier_count = sum(pattern.count(q) for q in ("*", "+", "{"))
    if quantifier_count > MAX_QUANTIFIERS_IN_PATTERN:
        return False
    try:
        re.compile(pattern)
    except re.error:
        return False
    return True


class _RegexTimeoutError(Exception):
    pass


def _safe_regex_match(pattern: str, subject: str) -> Optional[bool]:
    if not is_regex_pattern_safe(pattern):
        return None
    if not isinstance(subject, str):
        return None
    subject = subject[:MAX_SUBJECT_STRING_LEN]

    def _handler(signum, frame):
        raise _RegexTimeoutError()

    use_alarm = hasattr(signal, "SIGALRM")
    old_handler = None
    try:
        if use_alarm:
            old_handler = signal.signal(signal.SIGALRM, _handler)
            signal.alarm(REGEX_TIMEOUT_SECONDS)
        result = re.search(pattern, subject) is not None
        return result
    except _RegexTimeoutError:
        logger.warning("safe_regex_match: pattern exceeded timeout, treating as no-match")
        return None
    except re.error:
        return None
    finally:
        if use_alarm:
            signal.alarm(0)
            if old_handler is not None and use_alarm:
                signal.signal(signal.SIGALRM, old_handler)


# =========================================================================
# 4. AST RULE PARSING
# =========================================================================

def _parse_condition(raw: dict) -> ConditionNode:
    field_name = raw.get("field")
    operator = raw.get("operator")
    value = raw.get("value")

    if not isinstance(field_name, str) or field_name not in ALLOWED_RECORD_FIELDS:
        raise RuleParseError(f"field '{field_name}' is not in the allowed field list")
    if operator not in VALID_OPERATORS:
        raise RuleParseError(f"operator '{operator}' is not a recognized operator")

    if operator == Operator.IN_LIST:
        if not isinstance(value, list) or len(value) > MAX_IN_LIST_SIZE:
            raise RuleParseError("IN_LIST value must be a list within the size cap")
    if operator == Operator.REGEX_MATCH:
        if not is_regex_pattern_safe(value):
            raise RuleParseError("REGEX_MATCH pattern failed the safety linter")

    return ConditionNode(field=field_name, operator=operator, value=value)


def _parse_node(raw: dict, depth: int, node_counter: list) -> RuleNode:
    node_counter[0] += 1
    if node_counter[0] > MAX_NODES_PER_RULE:
        raise RuleParseError(f"rule exceeds max node count {MAX_NODES_PER_RULE}")
    if depth > MAX_TREE_DEPTH:
        raise RuleParseError(f"rule exceeds max tree depth {MAX_TREE_DEPTH}")
    if not isinstance(raw, dict):
        raise RuleParseError("rule node must be an object")

    node_type = raw.get("type")

    if node_type in ("AND", "OR"):
        children_raw = raw.get("children")
        if not isinstance(children_raw, list) or not children_raw:
            raise RuleParseError(f"{node_type} requires a non-empty 'children' list")
        children = tuple(_parse_node(c, depth + 1, node_counter) for c in children_raw)
        return LogicalNode(logic_type=node_type, children=children)

    if node_type == "NOT":
        child_raw = raw.get("child")
        if not isinstance(child_raw, dict):
            raise RuleParseError("NOT requires a single 'child' object")
        child = _parse_node(child_raw, depth + 1, node_counter)
        return LogicalNode(logic_type="NOT", children=(child,))

    if node_type == "CONDITION":
        return _parse_condition(raw)

    raise RuleParseError(f"unrecognized node type '{node_type}'")


def _parse_action(raw: dict) -> RuleAction:
    action_type = raw.get("action_type")
    if action_type not in VALID_ACTIONS:
        raise RuleParseError(f"unrecognized action_type '{action_type}'")

    field_name = raw.get("field")
    if action_type in (ActionType.MASK_FIELD, ActionType.OVERWRITE_FIELD):
        if field_name not in ALLOWED_RECORD_FIELDS:
            raise RuleParseError(f"action field '{field_name}' is not in the allowed field list")

    queue_name = raw.get("queue_name")
    if action_type == ActionType.ROUTE_TO_QUEUE:
        if not isinstance(queue_name, str) or not _QUEUE_NAME_PATTERN.match(queue_name):
            raise RuleParseError("queue_name must match the allowed charset/length")

    mask_char = raw.get("mask_char", "*")
    if not isinstance(mask_char, str) or len(mask_char) != 1:
        mask_char = "*"

    return RuleAction(
        action_type=action_type,
        field=field_name if isinstance(field_name, str) else None,
        value=raw.get("value"),
        mask_char=mask_char,
        queue_name=queue_name if isinstance(queue_name, str) else None,
    )


def parse_tenant_rules(tenant_rules: list) -> tuple:
    if not isinstance(tenant_rules, list):
        return ()
    if len(tenant_rules) > MAX_RULES_PER_TENANT:
        logger.warning("parse_tenant_rules: rule count exceeds cap, truncating to %d", MAX_RULES_PER_TENANT)
        tenant_rules = tenant_rules[:MAX_RULES_PER_TENANT]

    compiled = []
    for i, raw_rule in enumerate(tenant_rules):
        rule_id = raw_rule.get("rule_id", f"rule_{i}") if isinstance(raw_rule, dict) else f"rule_{i}"
        try:
            if not isinstance(raw_rule, dict):
                raise RuleParseError("rule must be an object")
            root_raw = raw_rule.get("condition")
            actions_raw = raw_rule.get("actions")
            if not isinstance(root_raw, dict):
                raise RuleParseError("rule missing 'condition'")
            if not isinstance(actions_raw, list) or not actions_raw:
                raise RuleParseError("rule missing non-empty 'actions'")

            node_counter = [0]
            root = _parse_node(root_raw, depth=0, node_counter=node_counter)
            actions = tuple(_parse_action(a) for a in actions_raw)
            compiled.append(CompiledRule(rule_id=rule_id, root=root, actions=actions))
        except RuleParseError as e:
            logger.warning("parse_tenant_rules: dropping malformed rule '%s': %s", rule_id, e)
            continue
        except Exception:
            logger.exception("parse_tenant_rules: unexpected failure parsing rule '%s'", rule_id)
            continue

    return tuple(compiled)


# =========================================================================
# 5. AST EVALUATION
# =========================================================================

def _coerce_numeric(value) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, numbers.Number):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _evaluate_condition(node: ConditionNode, record: dict) -> bool:
    try:
        actual = record.get(node.field)

        if node.operator == Operator.EQUALS:
            return actual == node.value
        if node.operator == Operator.NOT_EQUALS:
            return actual != node.value

        if node.operator == Operator.CONTAINS:
            if not isinstance(actual, str) or not isinstance(node.value, str):
                return False
            return node.value.lower() in actual.lower()
        if node.operator == Operator.NOT_CONTAINS:
            if not isinstance(actual, str) or not isinstance(node.value, str):
                return True
            return node.value.lower() not in actual.lower()

        if node.operator in (Operator.GREATER_THAN, Operator.LESS_THAN):
            actual_num = _coerce_numeric(actual)
            target_num = _coerce_numeric(node.value)
            if actual_num is None or target_num is None:
                return False
            return actual_num > target_num if node.operator == Operator.GREATER_THAN else actual_num < target_num

        if node.operator == Operator.IN_LIST:
            if not isinstance(node.value, list):
                return False
            return actual in node.value

        if node.operator == Operator.REGEX_MATCH:
            if not isinstance(actual, str):
                return False
            result = _safe_regex_match(node.value, actual)
            return bool(result)

        return False
    except Exception:
        logger.exception("_evaluate_condition: unexpected failure on field '%s'", node.field)
        return False


def evaluate_node(node: RuleNode, record: dict) -> bool:
    try:
        if isinstance(node, ConditionNode):
            return _evaluate_condition(node, record)

        if isinstance(node, LogicalNode):
            if node.logic_type == "AND":
                return all(evaluate_node(c, record) for c in node.children)
            if node.logic_type == "OR":
                return any(evaluate_node(c, record) for c in node.children)
            if node.logic_type == "NOT":
                return not evaluate_node(node.children[0], record)

        return False
    except Exception:
        logger.exception("evaluate_node: unexpected failure, treating as non-match")
        return False


# =========================================================================
# 6. ACTION EXECUTION
# =========================================================================

@dataclass(frozen=True)
class ActionOutcome:
    record: dict
    dropped: bool
    flags: tuple
    routed_queue: Optional[str]


def apply_actions(record: dict, actions: tuple) -> ActionOutcome:
    working_record = dict(record)
    dropped = False
    flags: list[str] = []
    routed_queue = None

    for action in actions:
        try:
            if action.action_type == ActionType.DROP_RECORD:
                dropped = True
            elif action.action_type == ActionType.FLAG_RECORD:
                flags.append(action.value if isinstance(action.value, str) else "FLAGGED")
            elif action.action_type == ActionType.MASK_FIELD:
                if action.field in ALLOWED_MASK_FIELDS and action.field in working_record:
                    original = working_record[action.field]
                    if isinstance(original, str) and original:
                        working_record[action.field] = action.mask_char * len(original)
            elif action.action_type == ActionType.OVERWRITE_FIELD:
                if action.field in ALLOWED_OVERWRITE_FIELDS:
                    working_record[action.field] = action.value
            elif action.action_type == ActionType.ROUTE_TO_QUEUE:
                routed_queue = action.queue_name
        except Exception:
            logger.exception("apply_actions: unexpected failure applying action '%s'", action.action_type)
            continue

    return ActionOutcome(record=working_record, dropped=dropped, flags=tuple(flags), routed_queue=routed_queue)


# =========================================================================
# 7. PIPELINE ADAPTER WRAPPER
# =========================================================================

def run_engine_06(
    records: List[Dict[str, Any]], 
    tenant_rules: List[Dict[str, Any]], 
    tenant_id: str = "default_tenant"
) -> List[Dict[str, Any]]:
    """
    Main Pipeline Wrapper for Engine 06.
    Evaluates AST rules over records, modifies/masks fields, flags, or drops records.
    """
    if not tenant_id:
        raise RuleEvalError("tenant_id is required")

    compiled_rules = parse_tenant_rules(tenant_rules)
    processed_records = []

    for idx, rec in enumerate(records):
        rec_id = str(rec.get("id") or f"rec_{idx}")
        working = dict(rec)
        dropped = False
        all_flags: list[str] = []
        routed_queue = None
        matched_ids: list[str] = []

        for rule in compiled_rules:
            if dropped:
                break
            try:
                if evaluate_node(rule.root, working):
                    matched_ids.append(rule.rule_id)
                    outcome = apply_actions(working, rule.actions)
                    working = outcome.record
                    all_flags.extend(outcome.flags)
                    if outcome.routed_queue:
                        routed_queue = outcome.routed_queue
                    if outcome.dropped:
                        dropped = True
            except Exception:
                logger.exception("run_engine_06: error evaluating rule '%s' for record %s", rule.rule_id, rec_id)
                continue

        clean_dict = dict(working)
        clean_dict["is_dropped"] = dropped
        clean_dict["rule_flags"] = all_flags
        clean_dict["routed_queue"] = routed_queue
        clean_dict["matched_rule_ids"] = matched_ids
        clean_dict["_meta_rules_evaluated"] = True

        if not dropped:
            processed_records.append(clean_dict)

    return processed_records
