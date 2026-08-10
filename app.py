import streamlit as st
import pandas as pd
from backend.pipeline import run_dataops_pipeline

st.set_page_config(
    page_title="AMG DataOps Cloud",
    page_icon="⚡",
    layout="wide"
)

# Custom Styling
st.markdown("""
    <style>
    .main { background-color: #080C14; }
    h1, h2, h3 { color: #00F2FE !important; }
    </style>
""", unsafe_allow_html=True)

st.title("⚡ AMG DataOps Cloud — 9-Engine Data Pipeline")
st.caption("Production-Ready Zero-Trust Data Cleaning, Deduplication & Threat Intelligence")

st.divider()

# File Upload Section
uploaded_file = st.file_uploader("📁 Drag and drop your CSV file here", type=["csv"])

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    st.subheader("📋 Raw Data Preview")
    st.dataframe(df.head(10), use_container_width=True)

    if st.button("🚀 Process Batch Through 9 Engines", type="primary"):
        raw_records = df.to_dict(orient="records")
        
        with st.spinner("Processing through 9 Engines (Syntax ➔ Dedup ➔ MX Probe ➔ Phone E.164 ➔ Risk Score ➔ Rules ➔ Anti-Ban ➔ Audit)..."):
            result = run_dataops_pipeline(
                raw_records=raw_records,
                tenant_id="tenant_amg_default"
            )

        if result.get("status") == "SUCCESS":
            st.success("✅ Batch Processed Successfully!")
            
            # Metrics Display
            m1, m2, m3 = st.columns(3)
            m1.metric("Total Records Input", result["deduplication_summary"]["total_input"])
            m2.metric("Duplicates Removed", result["deduplication_summary"]["duplicates_removed"])
            m3.metric("Clean Records Output", len(result["records"]))

            # Cleaned Data Table
            clean_df = pd.DataFrame(result["records"])
            st.subheader("✨ Processed Clean Records")
            st.dataframe(clean_df, use_container_width=True)

            # Download CSV Button
            csv_data = clean_df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Download Clean CSV Data",
                data=csv_data,
                file_name="clean_amg_data.csv",
                mime="text/csv"
            )
