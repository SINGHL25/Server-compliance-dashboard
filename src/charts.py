
# src/charts.py
import plotly.express as px
import pandas as pd

def vuln_trend(df_scans):
    # df_scans: DataFrame with scan_date (datetime) and total_vulns
    s = df_scans.groupby(pd.Grouper(key='scan_date', freq='7D'))['total_vulns'].sum().reset_index()
    return px.line(s, x='scan_date', y='total_vulns', title="Vulnerability trend (7d)")

def vuln_by_severity(df_vulns):
    # df_vulns has column 'severity' values 1..5
    counts = df_vulns['severity'].value_counts().reset_index()
    counts.columns = ['severity','count']
    return px.bar(counts, x='severity', y='count', title="Vulnerabilities by Severity")
