from typing import Dict, Any, List

def evaluate_condition(field_value: Any, operator: str, target_value: Any) -> bool:
    """Evaluates a single condition against a row field value."""
    if field_value is None:
        return False
    
    val_str = str(field_value).strip().lower()
    target_str = str(target_value).strip().lower()

    if operator == "equals":
        return val_str == target_str
    elif operator == "not_equals":
        return val_str != target_str
    elif operator == "contains":
        return target_str in val_str
    elif operator == "starts_with":
        return val_str.startswith(target_str)
    elif operator == "ends_with":
        return val_str.endswith(target_str)
    return False

def apply_custom_rules(row: Dict[str, Any], rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Executes a list of tenant-defined rules on a lead row.
    Rule structure example:
    {
        "field": "country",
        "operator": "equals",
        "value": "US",
        "action_field": "custom_tag",
        "action_value": "US_DOMESTIC"
    }
    """
    modified_row = row.copy()
    applied_rules_count = 0

    for rule in rules:
        field = rule.get("field")
        operator = rule.get("operator")
        target_val = rule.get("value")
        action_field = rule.get("action_field")
        action_val = rule.get("action_value")

        if field and operator and field in modified_row:
            if evaluate_condition(modified_row[field], operator, target_val):
                if action_field and action_val:
                    modified_row[action_field] = action_val
                    applied_rules_count += 1

    modified_row["custom_rules_applied_count"] = applied_rules_count
    return modified_row

def process_engine_06(row: dict, tenant_rules: List[Dict[str, Any]] = None) -> dict:
    """
    Main Execution Function for Engine 06.
    Applies custom visual logic rules per tenant.
    """
    processed_row = row.copy()
    
    # Default to empty list if no rules supplied
    rules_to_apply = tenant_rules if tenant_rules else []
    
    if rules_to_apply:
        processed_row = apply_custom_rules(processed_row, rules_to_apply)
    else:
        processed_row["custom_rules_applied_count"] = 0

    processed_row["engine_06_processed"] = True
    return processed_row
