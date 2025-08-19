
# src/storage.py
import sqlite3
import json
from pathlib import Path

DB = Path("data/scan_store.db")

def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS servers (
      id INTEGER PRIMARY KEY,
      hostname TEXT, ip TEXT UNIQUE, os_name TEXT, os_version TEXT, location TEXT, owner TEXT, last_seen TEXT
    );
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY, server_ip TEXT, scanner TEXT, scan_date TEXT, total_vulns INTEGER, raw_json TEXT
    );
    """)
    conn.commit(); conn.close()

def save_scan(server_ip, scanner, scan_date, total_vulns, parsed_json):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("INSERT INTO scans (server_ip, scanner, scan_date, total_vulns, raw_json) VALUES (?, ?, ?, ?, ?)",
                (server_ip, scanner, scan_date, total_vulns, json.dumps(parsed_json)))
    conn.commit(); conn.close()

def get_scans(limit=100):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT id, server_ip, scanner, scan_date, total_vulns FROM scans ORDER BY scan_date DESC LIMIT ?", (limit,))
    rows = cur.fetchall(); conn.close()
    return rows
