"""
Engine 13 — Multi-Currency Dynamic Pricing & Paywall Engine
AMG DataOps Cloud

Design principles:
  - Multi-Currency Support (USD $, EUR €, GBP £, INR ₹, AED, CAD, AUD, etc.).
  - Custom Admin Price Overrides with custom service descriptions.
  - Zero hardcoded credentials (Dynamic UPI, Razorpay, PayPal, Stripe configuration).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict, Any, List, Optional

logger = logging.getLogger("engine13")

# Multi-Currency Symbol Map
CURRENCY_SYMBOLS: Dict[str, str] = {
    "INR": "₹",
    "USD": "$",
    "EUR": "€",
    "GBP": "£",
    "AED": "AED ",
    "CAD": "CA$",
    "AUD": "A$",
    "SGD": "S$",
    "SAR": "SAR "
}


@dataclass
class PaymentGatewayConfig:
    upi_id: str = "haidar@upi"
    upi_qr_url: Optional[str] = None
    razorpay_key_id: Optional[str] = None
    paypal_client_id: Optional[str] = None
    stripe_publishable_key: Optional[str] = None
    active_gateway: str = "UPI"  # 'UPI', 'RAZORPAY', 'PAYPAL', 'STRIPE'
    currency: str = "USD"        # Default Global Currency
    rate_per_1000_records: float = 5.0  # $5 per 1,000 records
    minimum_fee: float = 2.0            # $2 minimum fee


class PaymentConfigRegistry:
    def __init__(self):
        self._config = PaymentGatewayConfig()

    def update_config(self, **kwargs) -> PaymentGatewayConfig:
        for key, value in kwargs.items():
            if hasattr(self._config, key) and value is not None:
                setattr(self._config, key, value)
        return self._config

    def get_config(self) -> PaymentGatewayConfig:
        return self._config


_GLOBAL_PAYMENT_CONFIG = PaymentConfigRegistry()


def calculate_invoice(
    record_count: int,
    config: PaymentGatewayConfig,
    custom_amount: Optional[float] = None,
    custom_currency: Optional[str] = None,
    custom_notes: Optional[str] = None
) -> Dict[str, Any]:
    active_currency = (custom_currency or config.currency).upper()
    symbol = CURRENCY_SYMBOLS.get(active_currency, f"{active_currency} ")

    # Custom Admin Manual Override
    if custom_amount is not None and custom_amount >= 0:
        final_amount = round(custom_amount, 2)
        pricing_type = "CUSTOM_ADMIN_OVERRIDE"
    else:
        if record_count <= 0:
            final_amount = 0.0
        else:
            raw_price = (record_count / 1000.0) * config.rate_per_1000_records
            final_amount = round(max(raw_price, config.minimum_fee), 2)
        pricing_type = "AUTOMATED_PER_RECORD"

    return {
        "record_count": record_count,
        "rate_per_1k": config.rate_per_1000_records,
        "base_minimum": config.minimum_fee,
        "total_amount": final_amount,
        "currency": active_currency,
        "currency_symbol": symbol,
        "formatted_price": f"{symbol}{final_amount:,.2f}",
        "pricing_type": pricing_type,
        "service_notes": custom_notes or "Enterprise Data Cleaning & Verification Fee",
        "active_gateway": config.active_gateway,
        "payment_details": {
            "upi_id": config.upi_id if config.active_gateway == "UPI" else None,
            "razorpay_key": config.razorpay_key_id if config.active_gateway == "RAZORPAY" else None,
            "paypal_client": config.paypal_client_id if config.active_gateway == "PAYPAL" else None,
            "stripe_key": config.stripe_publishable_key if config.active_gateway == "STRIPE" else None
        }
    }


def run_engine_13(
    job_id: str,
    records_count: int,
    payment_verified: bool = False,
    raw_payload: Optional[List[Dict[str, Any]]] = None,
    custom_amount: Optional[float] = None,
    custom_currency: Optional[str] = None,
    custom_notes: Optional[str] = None,
    admin_config_update: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    
    if admin_config_update:
        _GLOBAL_PAYMENT_CONFIG.update_config(**admin_config_update)

    current_config = _GLOBAL_PAYMENT_CONFIG.get_config()
    invoice = calculate_invoice(records_count, current_config, custom_amount, custom_currency, custom_notes)

    if not payment_verified:
        return {
            "engine": "Engine 13 - Dynamic Pricing & Multi-Currency Paywall",
            "job_id": job_id,
            "payment_status": "UNPAID",
            "invoice": invoice,
            "data_locked": True,
            "preview_sample": raw_payload[:2] if raw_payload else [],
            "message": f"Payment of {invoice['formatted_price']} required via {invoice['active_gateway']} to unlock data."
        }

    return {
        "engine": "Engine 13 - Dynamic Pricing & Multi-Currency Paywall",
        "job_id": job_id,
        "payment_status": "PAID_AND_VERIFIED",
        "invoice": invoice,
        "data_locked": False,
        "unlocked_payload": raw_payload or [],
        "message": "Payment verified. Full dataset unlocked for delivery."
    }
