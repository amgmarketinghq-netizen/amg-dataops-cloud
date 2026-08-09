from typing import List, Dict, Any

DEFAULT_MAX_INVALID_RATE = 0.05  # 5% Max allowed invalid rate
DEFAULT_MAX_RISKY_RATE = 0.15    # 15% Max allowed risky rate

def evaluate_batch_circuit_breaker(
    batch_records: List[Dict[str, Any]], 
    max_invalid_rate: float = DEFAULT_MAX_INVALID_RATE,
    max_risky_rate: float = DEFAULT_MAX_RISKY_RATE
) -> Dict[str, Any]:
    """
    Evaluates an entire batch of processed leads against security & deliverability thresholds.
    Triggers circuit breaker if bounce/invalid risk is dangerously high.
    """
    total_records = len(batch_records)
    if total_records == 0:
        return {
            "circuit_breaker_triggered": False,
            "reason": "EMPTY_BATCH",
            "invalid_rate": 0.0,
            "risky_rate": 0.0
        }

    invalid_count = 0
    risky_count = 0

    for record in batch_records:
        status = record.get('verification_status', 'UNKNOWN')
        is_high_risk = record.get('is_high_risk', False)

        if status == 'INVALID':
            invalid_count += 1
        elif status == 'RISKY' or is_high_risk:
            risky_count += 1

    invalid_rate = round(invalid_count / total_records, 4)
    risky_rate = round(risky_count / total_records, 4)

    # Circuit breaker trigger conditions
    circuit_triggered = False
    trigger_reasons = []

    if invalid_rate > max_invalid_rate:
        circuit_triggered = True
        trigger_reasons.append(f"Invalid rate {invalid_rate*100:.1f}% exceeds max threshold {max_invalid_rate*100:.1f}%")

    if risky_rate > max_risky_rate:
        circuit_triggered = True
        trigger_reasons.append(f"Risky rate {risky_rate*100:.1f}% exceeds max threshold {max_risky_rate*100:.1f}%")

    return {
        "circuit_breaker_triggered": circuit_triggered,
        "trigger_reasons": trigger_reasons,
        "invalid_rate": invalid_rate,
        "risky_rate": risky_rate,
        "total_evaluated": total_records,
        "invalid_count": invalid_count,
        "risky_count": risky_count
    }

def process_engine_07(batch_records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Main Execution Function for Engine 07.
    Scans entire processed batch for deliverability risks and safety circuit trip.
    """
    safety_audit = evaluate_batch_circuit_breaker(batch_records)

    # Tag each record with engine 07 audit outcome
    for record in batch_records:
        record['engine_07_processed'] = True
        record['circuit_breaker_status'] = "TRIPPED" if safety_audit['circuit_breaker_triggered'] else "SAFE"

    return {
        "records": batch_records,
        "safety_audit": safety_audit,
        "engine_07_processed": True
    }
