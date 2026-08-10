import sys
import os

# Streamlit Cloud path resolution
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

import streamlit as st
import pandas as pd

st.set_page_config(
    page_title="AMG DataOps Cloud",
    page_icon="⚡",
    layout="wide"
)

# Safe Dynamic Import to catch redacted errors
try:
    from backend.pipeline import run_dataops_pipeline
except Exception as e:
    st.error(f"❌ Engine Import Error Details: {str(e)}")
    st.info("💡 Yeh error kisi missing library ya module path ki wajah se hai.")
    st.stop()

st.markdown("""
    <style>
    .main { background-color: #080C14; }
    h1, h2, h3 { color: #00F2FE !important; }
    </style>
""", unsafe_allow_html=True)

st.title("⚡ AMG DataOps Cloud — 9-Engine Data Pipeline")
st.caption("Production-Ready Zero-Trust Data Cleaning, Deduplication & Threat Intelligence")

st.divider()

uploaded_file = st.file_uploader("📁 Drag and drop your CSV file here", type=["csv"])

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    st.subheader("📋 Raw Data Preview")
    st.dataframe(df.head(10), use_container_width=True)

    if st.button("🚀 Process Batch Through 9 Engines", type="primary"):
        raw_records = df.to_dict(orient="records")
        
        with st.spinner("Processing through 9 Engines..."):
            result = run_dataops_pipeline(
                raw_records=raw_records,
                tenant_id="tenant_amg_default"
            )

        if result.get("status") == "SUCCESS":
            st.success("✅ Batch Processed Successfully!")
            
            m1, m2, m3 = st.columns(3)
            m1.metric("Total Records Input", result["deduplication_summary"]["total_input"])
            m2.metric("Duplicates Removed", result["deduplication_summary"]["duplicates_removed"])
            m3.metric("Clean Records Output", len(result["records"]))

            clean_df = pd.DataFrame(result["records"])
            st.subheader("✨ Processed Clean Records")
            st.dataframe(clean_df, use_container_width=True)

            csv_data = clean_df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Download Clean CSV Data",
                data=csv_data,
                file_name="clean_amg_data.csv",
                mime="text/csv"
            )
