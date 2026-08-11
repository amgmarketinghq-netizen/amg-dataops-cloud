import sys
import os

# Add root and backend directory to Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "backend")))

import streamlit as st
import json
import pandas as pd

# Import Engines cleanly
from backend.engines.engine_12_admin_gateway import run_engine_12
from backend.engines.engine_13_paywall import run_engine_13
from backend.engines.engine_14_bi_dashboard import run_engine_14

st.set_page_config(page_title="AMG DataOps Cloud — Interactive Workbench", layout="wide")

st.title("⚡ AMG DataOps Cloud — 14-Engine SaaS Workbench")

st.sidebar.header("⚙️ Admin & White-Label Config")
brand_name = st.sidebar.text_input("Brand Name", "AMG Marketing Global")
logo_url = st.sidebar.text_input("Logo Image URL", "")
primary_color = st.sidebar.color_picker("Brand Color", "#4f46e5")

st.sidebar.subheader("💳 Payment Gateway & Multi-Currency")
active_gateway = st.sidebar.selectbox("Gateway", ["UPI", "RAZORPAY", "PAYPAL", "STRIPE"])
currency = st.sidebar.selectbox("Currency", ["INR", "USD", "EUR", "GBP", "AED", "CAD", "AUD"])
upi_id = st.sidebar.text_input("UPI ID / Gateway Key", "haidar@upi")
rate_per_1k = st.sidebar.number_input("Rate / 1000 Records", value=5.0 if currency != "INR" else 250.0)

tab1, tab2, tab3 = st.tabs(["📁 Client File & Auto BI Dashboard", "👑 Admin Approval & Data Editor", "🔒 Paywall & Custom Invoicing"])

uploaded_file = st.sidebar.file_uploader("Upload CSV / Excel", type=["csv", "xlsx"])

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file) if uploaded_file.name.endswith(".csv") else pd.read_excel(uploaded_file)
    records = df.to_dict(orient="records")

    with tab1:
        st.subheader("📊 Interactive PowerBI-Style HTML Dashboard (Engine 14)")
        if st.button("Generate White-Label BI Dashboard"):
            res14 = run_engine_14(
                records=records,
                brand_name=brand_name,
                logo_url=logo_url,
                primary_color=primary_color,
                currency_symbol="$" if currency == "USD" else "₹"
            )
            html_code = res14["generated_html_dashboard"]
            
            st.success("BI Interactive Dashboard Generated!")
            st.components.v1.html(html_code, height=600, scrolling=True)
            
            st.download_button(
                label="📥 Download Standalone Interactive HTML Dashboard",
                data=html_code,
                file_name="BI_Analytics_Dashboard.html",
                mime="text/html"
            )

    with tab2:
        st.subheader("👑 Admin Review & Data Editor (Engine 12)")
        st.info("Admin can review, edit client records, and manage delivery approval.")
        edited_df = st.data_editor(df, num_rows="dynamic")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Approve & Trigger Client Delivery"):
                edited_records = edited_df.to_dict(orient="records")
                job_res = run_engine_12(
                    action="CREATE_JOB",
                    tenant_id="client_tenant",
                    cleaned_records=edited_records,
                    report={"quality_score": 99.2}
                )
                st.session_state["active_job_id"] = job_res["job_id"]
                st.session_state["edited_records"] = edited_records
                st.success(f"Job Approved! Created ID: {job_res['job_id']}")

        with col2:
            if st.button("Reject Request"):
                st.error("Request Rejected by Admin.")

    with tab3:
        st.subheader("🔒 Client Paywall & Dynamic Invoicing (Engine 13)")
        job_id = st.session_state.get("active_job_id", "job_demo_001")
        unlocked_data = st.session_state.get("edited_records", records)

        st.markdown("### Admin Manual Price Override (Optional)")
        use_custom_price = st.checkbox("Set Manual Custom Price for this Client?")
        custom_amount = None
        custom_notes = None

        if use_custom_price:
            custom_amount = st.number_input("Enter Custom Invoice Amount", value=499.0 if currency == "INR" else 49.0)
            custom_notes = st.text_input("Invoice Service Description", "Data Cleaning + BI Interactive Analytics Dashboard")

        paywall_res = run_engine_13(
            job_id=job_id,
            records_count=len(unlocked_data),
            payment_verified=False,
            raw_payload=unlocked_data,
            custom_amount=custom_amount,
            custom_currency=currency,
            custom_notes=custom_notes,
            admin_config_update={
                "upi_id": upi_id,
                "active_gateway": active_gateway,
                "currency": currency,
                "rate_per_1000_records": rate_per_1k
            }
        )

        st.json(paywall_res["invoice"])
        st.warning(f"Client Pop-Up: Payment of {paywall_res['invoice']['formatted_price']} required via {active_gateway} to unlock data.")

        if st.button("Simulate Client Payment Received"):
            paid_res = run_engine_13(
                job_id=job_id,
                records_count=len(unlocked_data),
                payment_verified=True,
                raw_payload=unlocked_data,
                custom_amount=custom_amount,
                custom_currency=currency,
                custom_notes=custom_notes
            )
            st.balloons()
            st.success("Payment Verified! Data Unlocked.")
            st.dataframe(pd.DataFrame(paid_res["unlocked_payload"]))
else:
    st.info("Sidebar se CSV ya Excel file upload karke local testing shuru karein!")
