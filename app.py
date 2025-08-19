
# app.py
import streamlit as st
from pathlib import Path
from src.pdf_parser import parse_qualys_report
from src.storage import init_db, save_scan, get_scans
import pandas as pd
import plotly.express as px
import json
import io
import datetime

st.set_page_config(layout="wide", page_title="Server Compliance Dashboard")

# init DB
init_db()

st.title("🔒 Server Vulnerability & Patch Dashboard")

# Upload area
st.sidebar.header("Upload Reports")
uploaded_files = st.sidebar.file_uploader("Upload Qualys / Patch PDFs", type=["pdf"], accept_multiple_files=True)
if uploaded_files:
    for f in uploaded_files:
        bytes_io = io.BytesIO(f.read())
        # write temp file to parse (pdfplumber needs path) - but pdfplumber can accept file-like object
        tmp_path = f"data/raw_reports/{f.name}"
        Path("data/raw_reports").mkdir(parents=True, exist_ok=True)
        with open(tmp_path, "wb") as fh:
            fh.write(bytes_io.getbuffer())
        parsed = parse_qualys_report(tmp_path)
        # pick server IP if found else 'unknown'
        server_ip = parsed.get('ips', ['unknown'])[0]
        scan_date = parsed.get('scan_time', datetime.datetime.utcnow().isoformat())
        total_vulns = len(parsed.get('vulnerabilities', []))
        save_scan(server_ip, "qualys", str(scan_date), total_vulns, parsed)
    st.sidebar.success("Uploaded and parsed!")

# Load scans for dashboard
rows = get_scans(limit=500)
if not rows:
    st.info("No scans yet. Upload a Qualys PDF to get started.")
else:
    df = pd.DataFrame(rows, columns=["id","server_ip","scanner","scan_date","total_vulns"])
    # KPIs
    col1, col2, col3 = st.columns(3)
    col1.metric("Servers scanned", df['server_ip'].nunique())
    col2.metric("Total scans", len(df))
    col3.metric("Total vulnerabilities (sum)", int(df['total_vulns'].sum()))

    # severity fake - for demo we parse severity_summary in raw_json if present
    # For simplicity show top servers by vuln count
    top = df.groupby('server_ip')['total_vulns'].sum().reset_index().sort_values('total_vulns', ascending=False).head(10)
    fig = px.bar(top, x='server_ip', y='total_vulns', title="Top servers by vulnerability count")
    st.plotly_chart(fig, use_container_width=True)

    # Table of recent scans
    st.subheader("Recent scans")
    st.dataframe(df.sort_values('scan_date', ascending=False).head(50))

    # Drilldown: choose server
    st.sidebar.header("Explore")
    sel_ip = st.sidebar.selectbox("Select server IP", options=['All'] + sorted(df['server_ip'].unique().tolist()))
    if sel_ip != 'All':
        # fetch raw JSON for that ip
        import sqlite3, json
        conn = sqlite3.connect("data/scan_store.db")
        cur = conn.cursor()
        cur.execute("SELECT id, scan_date, raw_json FROM scans WHERE server_ip = ? ORDER BY scan_date DESC", (sel_ip,))
        r = cur.fetchall()
        conn.close()
        st.header(f"Server: {sel_ip}")
        for rid, sdate, raw in r:
            st.markdown(f"**Scan {rid} @ {sdate}**")
            parsed = json.loads(raw)
            st.write("OS:", parsed.get('os'))
            st.write("Installed KBs (sample):", parsed.get('installed_kbs')[:10])
            st.write("Vulnerabilities (sample titles):")
            for v in parsed.get('vulnerabilities', [])[:8]:
                st.write("-", v.get('qid_or_cve'), "…", v.get('context')[:200])

            # button to export CSV of vulns
            if st.button(f"Export vulnerabilities CSV for scan {rid}"):
                import csv, tempfile
                tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".csv")
                keys = ['qid_or_cve','context']
                with open(tmp.name,'w', newline='', encoding='utf-8') as csvf:
                    w = csv.writer(csvf)
                    w.writerow(keys)
                    for v in parsed.get('vulnerabilities', []):
                        w.writerow([v.get('qid_or_cve'), v.get('context')])
                st.download_button("Download CSV", data=open(tmp.name,'rb'), file_name=f"vulns_scan_{rid}.csv")
