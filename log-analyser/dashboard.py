import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt

st.title("Security Log Analysis Dashboard")

uploaded_file = st.file_uploader("Upload Authentication Log CSV", type=["csv"])

if uploaded_file:
    df = pd.read_csv(uploaded_file)
    
    total_events = len(df)
    failed = df[df["status"].str.lower() == "failed"]
    total_failed = len(failed)
    unique_attackers = failed["source_ip"].nunique()
    top_username = failed["username"].value_counts().idxmax() if not failed.empty else "N/A"
    
    # Metrics panel
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Events", total_events)
    col2.metric("Failed Logins", total_failed)
    col3.metric("Unique Attackers", unique_attackers)
    col4.metric("Most Targeted User", top_username)
    
    st.subheader("Active Security Alerts")
    alerts = failed["source_ip"].value_counts()
    suspicious = alerts[alerts > 10]
    
    if not suspicious.empty:
        st.warning("⚠️ Potential brute-force activity detected")
        st.dataframe(suspicious.reset_index().rename(
            columns={"index": "Source IP", "source_ip": "Failed Attempts"}
        ))
    else:
        st.success("No high-risk attack patterns detected")

    st.subheader("Top Attacking IPs (Threat Ranking)")

    ip_counts = failed["source_ip"].value_counts().head(10)

    threat_table = ip_counts.reset_index()
    threat_table.columns = ["Source IP", "Failed Attempts"]

    def classify_risk(attempts):

        if attempts >= 20:
            return "HIGH"
        elif attempts >= 10:
            return "MEDIUM"
        else:
            return "LOW"

    threat_table["Risk Level"] = threat_table["Failed Attempts"].apply(classify_risk)

    st.dataframe(threat_table)
    
    # Only show these visualizations if there are failed logins
    if not failed.empty:
        # Top attackers
        st.subheader("Top Attacking IP Addresses")
        top_ips = failed["source_ip"].value_counts().head(10)
        fig, ax = plt.subplots()
        top_ips.plot(kind="bar", ax=ax)
        ax.set_xlabel("Source IP")
        ax.set_ylabel("Failed Attempts")
        plt.xticks(rotation=45, ha='right')
        st.pyplot(fig)
        
        # Top cities (if city column exists)
        st.subheader("Top Attack Locations")
        if "city" in failed.columns:
            top_cities = failed["city"].value_counts().head(10)
            fig2, ax2 = plt.subplots()
            top_cities.plot(kind="bar", ax=ax2)
            ax2.set_xlabel("City")
            ax2.set_ylabel("Failed Attempts")
            plt.xticks(rotation=45, ha='right')
            st.pyplot(fig2)
        else:
            st.info("City information not available in the data")
        
        # Timeline
        st.subheader("Attack Timeline")
        if "timestamp" in failed.columns:
            failed_copy = failed.copy()
            failed_copy["hour"] = pd.to_datetime(failed_copy["timestamp"]).dt.hour
            timeline = failed_copy["hour"].value_counts().sort_index()
            fig3, ax3 = plt.subplots()
            timeline.plot(kind="bar", ax=ax3)  # Changed to bar for better hour display
            ax3.set_xlabel("Hour of Day")
            ax3.set_ylabel("Failed Attempts")
            st.pyplot(fig3)
        else:
            st.info("Timestamp information not available in the data")
    else:
        st.info("No failed login attempts to visualize")