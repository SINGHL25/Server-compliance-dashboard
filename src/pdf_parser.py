# src/pdf_parser.py
import pdfplumber
import re
from datetime import datetime

IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
OS_RE = re.compile(r'Windows Server\s*\d{4}|\bWindows\s*10\b|\bWindows\s*2012 R2\b', re.I)
SEV_LINE_RE = re.compile(r'Severity.*?Total', re.I)
QID_RE = re.compile(r'QID:\s*(\d+)|CVE-?(?:\d{4}-\d+)', re.I)
KB_RE = re.compile(r'KB\d{6,7}')

def extract_text_from_pdf(path):
    texts = []
    with pdfplumber.open(path) as pdf:
        for p in pdf.pages:
            texts.append(p.extract_text() or "")
    return "\n".join(texts)

def parse_qualys_report(path):
    txt = extract_text_from_pdf(path)
    out = {}
    # IP
    ips = IP_RE.findall(txt)
    out['ips'] = list(dict.fromkeys(ips))  # unique order-preserving
    # OS
    os_match = OS_RE.search(txt)
    out['os'] = os_match.group(0) if os_match else None
    # Scan metadata
    # naive scan date: look for "Launch Date: 05/09/2024 at 03:14:37 AM"
    ld = re.search(r'Launch Date:\s*(.+)', txt)
    if ld:
        try:
            out['scan_time'] = datetime.strptime(ld.group(1).strip(), "%d/%m/%Y at %I:%M:%S %p (%Z)")
        except Exception:
            out['scan_time'] = ld.group(1).strip()
    # Severity counts (simple)
    # find lines like "Severity Confirmed Potential Information Gathered Total\n5 2 3 0 5"
    sev_counts = {}
    # look for table line blocks with numbers
    lines = txt.splitlines()
    for i, line in enumerate(lines):
        if re.search(r'5\s+\d+\s+\d+\s+\d+\s+\d+', line):
            parts = re.findall(r'\d+', line)
            if parts:
                # crude map: severity 5..1
                sev_counts['5'] = int(parts[0])
                # try to capture next lines for 4,3,2,1 if present
                # (this requires more robust parsing; simplified here)
    out['severity_summary'] = sev_counts

    # vulnerabilities list: find QIDs or CVEs and lines around them
    vulns = []
    for m in QID_RE.finditer(txt):
        start = max(0, m.start()-120)
        chunk = txt[start:m.end()+120]
        title_lines = chunk.splitlines()
        vulns.append({
            'qid_or_cve': m.group(0),
            'context': " ".join(title_lines[:2])
        })
    out['vulnerabilities'] = vulns

    # patches: list KB numbers installed
    kbs = KB_RE.findall(txt)
    out['installed_kbs'] = list(dict.fromkeys(kbs))
    out['raw_text'] = txt
    return out

