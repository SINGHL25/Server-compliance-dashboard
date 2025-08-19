# Server-compliance-dashboard
centralized Vulnerability &amp; Patch Management web app (Python + Streamlit) that unifies Qualys scan PDFs, patch reports
# 🔒 Centralized Vulnerability & Patch Management Dashboard

A modern **Streamlit-based dashboard** that unifies data from multiple sources 
(Qualys scans, patch compliance reports, lifecycle databases) into **one view** 
for **engineers** and **management**.

## ✨ Features
- ✅ **Engineer Drilldown** → per-server details (OS, vulnerabilities, missing patches, lifecycle).
- 📊 **Management KPIs** → compliance %, end-of-support risks, vulnerable servers by severity.
- 🎨 Modern, colorful, user-friendly dashboard (Streamlit + Plotly).
- 🔄 Supports multiple report sources (Qualys, WSUS, SCCM, etc.).

## 📂 Project Structure
See folder structure in repo.

## 🚀 Setup
```bash
git clone https://github.com/YOURNAME/vuln_patch_dashboard.git
cd vuln_patch_dashboard
pip install -r requirements.txt


▶️ Run Streamlit
streamlit run streamlit_app.py

🛠️ Data Sources

qualys_scan.csv → Vulnerability details

patch_report.csv → Installed/missing patches

lifecycle.csv → OS version & end-of-support info

📊 Example Visuals

Compliance % donut chart

Vulnerable servers heatmap

Drilldown tables with filters (server, OS, severity)


---

## 🐍 `scripts/transform.py`

```python
import pandas as pd

def load_and_transform():
    # Load raw data
    qualys = pd.read_csv("data/raw/qualys_scan.csv")
    patches = pd.read_csv("data/raw/patch_report.csv")
    lifecycle = pd.read_csv("data/raw/lifecycle.csv")

    # Merge datasets
    df = qualys.merge(patches, on="ServerID", how="left")
    df = df.merge(lifecycle, on="OS_Version", how="left")

    # Example: Add compliance status
    df["Compliance"] = df["Missing_Patches"].apply(lambda x: "Compliant" if x == 0 else "Non-Compliant")

    # Save unified dataset
    df.to_csv("data/processed/unified_data.csv", index=False)
    return df

if __name__ == "__main__":
    final_df = load_and_transform()
    print("Unified dataset created with", len(final_df), "rows")


✅ Next Steps:

I can create sample engineer view (engineer_view.py) and management view (management_view.py) with Streamlit + Plotly charts.

Then integrate both into streamlit_app.py with a sidebar toggle.
