import streamlit as st
import requests
import socket
import pandas as pd

VT_API_KEY = st.secrets["VT_API_KEY"]
ABUSE_API_KEY = st.secrets["ABUSE_API_KEY"]

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except:
        return False

def get_vt_info(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        data = r.json()["data"]["attributes"]
        return {
            "Source": "VirusTotal",
            "Reputation Score": data.get("reputation", 0),
            "Malicious Detections": data["last_analysis_stats"].get("malicious", 0),
            "Country": data.get("country", "Unknown"),
            "ISP": data.get("as_owner", "Unknown")
        }
    return None

def get_abuse_info(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSE_API_KEY,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    r = requests.get(url, headers=headers, params=params)
    if r.status_code == 200:
        data = r.json()["data"]
        return {
            "Source": "AbuseIPDB",
            "Reputation Score": -(data.get("abuseConfidenceScore", 0)),
            "Malicious Detections": data.get("totalReports", 0),
            "Country": data.get("countryCode", "Unknown"),
            "ISP": data.get("isp", "Unknown")
        }
    return None

def get_ipapi_info(ip):
    url = f"https://ipapi.co/{ip}/json/"
    r = requests.get(url)
    if r.status_code == 200:
        data = r.json()
        return {
            "IP": ip,
            "City": data.get("city", "N/A"),
            "Region": data.get("region", "N/A"),
            "Country": data.get("country_name", "N/A"),
            "Org": data.get("org", "N/A"),
            "Timezone": data.get("timezone", "N/A"),
        }
    return None

st.set_page_config(page_title="IP Intel Tool", page_icon="🛡", layout="centered")

st.markdown("""
    <style>
    .main {
        background-color: #f9f9f9;
    }
    .stButton > button {
        background-color: #007bff;
        color: white;
        font-weight: bold;
        border-radius: 6px;
        padding: 0.5em 1em;
    }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ Threat Intel IP Checker")
st.markdown("Check reputation & geo data from VirusTotal, AbuseIPDB & IPAPI")

ip_input = st.text_input("🔍 Enter an IP address")

if st.button("Check Reputation 🔎"):
    if is_valid_ip(ip_input):
        with st.spinner("Fetching data..."):
            vt_info = get_vt_info(ip_input)
            abuse_info = get_abuse_info(ip_input)
            geo_info = get_ipapi_info(ip_input)

        if vt_info and abuse_info:
            df = pd.DataFrame([vt_info, abuse_info]).set_index("Source")
            st.markdown("### 📊 Reputation Comparison")
            st.dataframe(df)

            score = vt_info['Reputation Score']
            if score > 0:
                rep_color = "🟥 Malicious"
            elif score == 0:
                rep_color = "🟨 Neutral"
            else:
                rep_color = "🟩 Clean"

            st.markdown(f"### ✅ Overall Reputation: **{rep_color}**")

            if geo_info:
                st.markdown("### 🌍 IP Location Details")
                st.write(pd.DataFrame([geo_info]).T.rename(columns={0: "Details"}))
        else:
            st.error("One or more sources failed. Please check API keys or rate limits.")
    else:
        st.warning("Please enter a valid IP address.")
