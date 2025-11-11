import os
import psycopg2
import psycopg2.extras
import json
import re
import nmap
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import requests
import time
from datetime import datetime, timezone

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# --- Database Connection ---
def get_db_connection():
    try:
        conn = psycopg2.connect(
            dbname=os.environ.get("PG_DBNAME"),
            user=os.environ.get("PG_USER"),
            password=os.environ.get("PG_PASSWORD"),
            host=os.environ.get("PG_HOST"),
            port=os.environ.get("PG_PORT")
        )
        return conn
    except Exception as e:
        print(f"Error: Unable to connect to the database. {e}")
        return None

# --- Gemini API Call (Unchanged) ---
def call_gemini_api(system_prompt, augmented_prompt, retry_count=3):
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key: raise ValueError("GEMINI_API_KEY not set.")
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key={api_key}"
    headers = {'Content-Type': 'application/json'}
    json_schema = {
        "type": "ARRAY",
        "items": {
            "type": "OBJECT",
            "properties": {
                "priority": {"type": "NUMBER"},
                "asset_hostname": {"type": "STRING"},
                "cve": {"type": "STRING"},
                "cvss_score": {"type": "NUMBER"},
                "justification": {"type": "STRING"},
                "recommendation": {"type": "STRING"}
            }
        }
    }
    payload = {
        "contents": [{"parts": [{"text": augmented_prompt}]}],
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "generationConfig": {"responseMimeType": "application/json", "responseSchema": json_schema}
    }
    delay = 1
    for i in range(retry_count):
        try:
            response = requests.post(url, headers=headers, data=json.dumps(payload))
            response.raise_for_status()
            raw_text = response.json()['candidates'][0]['content']['parts'][0]['text']
            clean_text = re.sub(r'^```json\s*|```\s*$', '', raw_text, flags=re.MULTILINE)
            return json.loads(clean_text)
        except Exception as e:
            if i == retry_count - 1: raise e
            time.sleep(delay)
            delay *= 2

# --- Dashboard Queries (Unchanged) ---
def get_dashboard_stats(conn):
    stats = {}
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cursor.execute("""
            SELECT a.hostname, a.ip_address, v.cve, v.cvss_score, (ck.cve_id IS NOT NULL) as is_cisa_kev
            FROM assets a JOIN vulnerabilities v ON a.asset_id = v.asset_id
            LEFT JOIN cisa_kev ck ON v.cve = ck.cve_id
            WHERE a.is_public = TRUE AND v.status = 'Open'
            ORDER BY (ck.cve_id IS NOT NULL) DESC, v.cvss_score DESC LIMIT 5;
        """)
        stats['top_risks'] = cursor.fetchall()
        cursor.execute("""
            SELECT hostname, ip_address, vt_ip_score, vt_domain_score FROM assets
            WHERE vt_ip_score > 0 OR vt_domain_score > 0 ORDER BY GREATEST(vt_ip_score, vt_domain_score) DESC LIMIT 5;
        """)
        stats['vt_threats'] = cursor.fetchall()
        cursor.execute("""
            SELECT a.owner, COUNT(v.vuln_id) as vuln_count FROM assets a JOIN vulnerabilities v ON a.asset_id = v.asset_id
            WHERE v.status = 'Open' GROUP BY a.owner ORDER BY vuln_count DESC LIMIT 5;
        """)
        stats['owner_stats'] = cursor.fetchall()
        cursor.execute("SELECT COUNT(*) as count FROM assets;")
        stats['total_assets'] = cursor.fetchone()['count']
        cursor.execute("SELECT COUNT(*) as count FROM vulnerabilities WHERE status='Open';")
        stats['total_open_vulns'] = cursor.fetchone()['count']
    finally: cursor.close()
    return stats

def get_assets_by_owner(conn, owner_name):
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cursor.execute("""
            SELECT a.asset_id, a.hostname, a.ip_address, a.environment, a.is_public,
                COUNT(v.vuln_id) as open_vulns, MAX(v.cvss_score) as max_cvss
            FROM assets a LEFT JOIN vulnerabilities v ON a.asset_id = v.asset_id AND v.status = 'Open'
            WHERE a.owner = %s GROUP BY a.asset_id ORDER BY max_cvss DESC NULLS LAST, open_vulns DESC;
        """, (owner_name,))
        return cursor.fetchall()
    finally: cursor.close()

# --- Analysis Helpers (Unchanged) ---
def fetch_top_vulnerabilities(conn):
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute("""
        SELECT a.asset_id, a.hostname, a.ip_address, a.environment, a.description, a.owner, a.is_public,
               a.vt_ip_score, a.vt_domain_score, v.cve, v.cvss_score, v.port AS vuln_port,
               nmap.status AS nmap_port_status, nmap.service_banner AS nmap_service_banner,
               (ck.cve_id IS NOT NULL) AS is_cisa_kev
        FROM vulnerabilities v JOIN assets a ON v.asset_id = a.asset_id
        LEFT JOIN cisa_kev ck ON v.cve = ck.cve_id
        LEFT JOIN nmap_scan_results nmap ON a.asset_id = nmap.asset_id AND v.port = nmap.port
        WHERE v.cvss_score >= 4.0 AND v.status = 'Open'
        ORDER BY is_cisa_kev DESC, v.cvss_score DESC, a.is_public DESC;
    """)
    res = cursor.fetchall()
    cursor.close()
    return res

def find_firewall_exposure(conn, ip_address, port):
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute("""
        SELECT rule_name, source_address FROM firewall_rules
        WHERE action = 'Allow' AND (service_port = %s OR service_port = 0)
          AND %s::inet <<= ANY(dest_address);
    """, (port, ip_address))
    rules = cursor.fetchall()
    cursor.close()
    if not rules: return "Not Reachable (No 'Allow' rules found)"
    exposure_rules = []
    for rule in rules:
        sources_str = [str(s) for s in rule['source_address']]
        if '0.0.0.0/0' in sources_str: exposure_rules.append(f"INTERNET EXPOSED via rule '{rule['rule_name']}'")
        else: exposure_rules.append(f"Internally exposed via rule '{rule['rule_name']}'")
    return "; ".join(exposure_rules)

# --- NEW: On-Demand Nmap Scan ---
def run_single_nmap_scan(ip, port):
    nm = nmap.PortScanner()
    try:
        print(f"Starting on-demand scan for {ip}:{port}...")
        # -sV for service version, -Pn to skip ping, -p to specify port
        nm.scan(ip, arguments=f'-sV -Pn -p {port}')
        
        if ip not in nm.all_hosts():
            return {'status': 'down', 'banner': None}

        tcp_info = nm[ip].get('tcp', {}).get(int(port))
        if not tcp_info:
            return {'status': 'closed', 'banner': None}

        return {
            'status': tcp_info['state'],
            'banner': f"{tcp_info.get('product', '')} {tcp_info.get('version', '')}".strip() or None
        }
    except Exception as e:
        print(f"Nmap scan error: {e}")
        return {'status': 'error', 'banner': str(e)}

# --- Routes ---
@app.route('/dashboard-stats', methods=['GET'])
def dashboard_stats():
    conn = get_db_connection()
    if not conn: return jsonify({"error": "DB failed"}), 500
    stats = get_dashboard_stats(conn)
    conn.close()
    return jsonify(stats)

@app.route('/owner-assets', methods=['GET'])
def owner_assets():
    owner = request.args.get('owner')
    if not owner: return jsonify({"error": "Owner required"}), 400
    conn = get_db_connection()
    if not conn: return jsonify({"error": "DB failed"}), 500
    assets = get_assets_by_owner(conn, owner)
    conn.close()
    return jsonify(assets)

@app.route('/analyze', methods=['GET'])
def analyze_vulnerabilities():
    SYSTEM_PROMPT = """
    You are an expert-level cybersecurity risk analyst. Determine *true business criticality*.
    Input JSON has: Asset Context, Vulnerability Data, CISA KEV status, Threat Intel, Network Exposure, Live Verification.
    Task: Return prioritized JSON array. 'priority' field must be sequential (1, 2, 3...).
    CRITICALITY RULES:
    1. **CISA KEV & EXPOSED:** PRIORITY #1 if 'is_cisa_kev: True' AND NOT 'Not Reachable'.
    2. **Internet Exposed Critical:** 'is_public: True' AND 'INTERNET EXPOSED' AND CVSS >= 9.0.
    3. **Compromised Asset:** VirusTotal score >= 70 indicates active compromise.
    4. **Verified internal risk:** 'Production' asset AND 'Internally exposed' AND 'Nmap Verification: open'.
    5. **Mitigating Factors:** 'Not Reachable' OR 'Nmap Verification: closed' lowers risk.
    Provide concise 'justification' and actionable 'recommendation'.
    """
    conn = get_db_connection()
    if not conn: return jsonify({"error": "DB failed"}), 500
    try:
        vulnerabilities = fetch_top_vulnerabilities(conn)
        if not vulnerabilities: return jsonify({"error": "No vulns found."}), 404
        augmented_data = []
        for vuln in vulnerabilities:
            vuln_dict = dict(vuln)
            vuln_dict['network_exposure'] = find_firewall_exposure(conn, vuln['ip_address'], vuln['vuln_port'])
            # Add asset_id and port to the response so the frontend can use them for scanning
            vuln_dict['asset_id'] = vuln['asset_id']
            vuln_dict['vuln_port'] = vuln['vuln_port'] 
            vuln_dict['cvss_score'] = float(vuln['cvss_score'])
            vuln_dict['vt_ip_score'] = int(vuln['vt_ip_score'] or 0)
            vuln_dict['vt_domain_score'] = int(vuln['vt_domain_score'] or 0)
            augmented_data.append(vuln_dict)
        analysis_result = call_gemini_api(SYSTEM_PROMPT, json.dumps(augmented_data))
        
        # Inject the asset_id/port back into the AI result for the "Verify" button
        # We do this by matching the hostname/cve from the AI result back to our data
        # (A bit hacky, but keeps the AI response clean. A better way is to ask AI to return IDs).
        # For simplicity in this demo, we'll just rely on the frontend having the data it needs.
        # ACTUALLY, let's just pass the raw data to the frontend too, hidden, if needed.
        # Better approach: The AI result doesn't need asset_id to DISPLAY, but the button does.
        # We will add asset_id and port to the AI output schema in a future refactor if needed.
        # For now, we will just add a 'scan_params' object to each result item by matching.
        for res_item in analysis_result:
             for orig_item in augmented_data:
                 if res_item['asset_hostname'] == orig_item['hostname'] and res_item['cve'] == orig_item['cve']:
                     res_item['scan_params'] = {'asset_id': orig_item['asset_id'], 'ip': orig_item['ip_address'], 'port': orig_item['vuln_port']}
                     break

        return jsonify(analysis_result)
    except Exception as e:
        print(f"Error in /analyze: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn: conn.close()

# --- NEW ENDPOINT ---
@app.route('/scan-asset', methods=['POST'])
def scan_asset():
    data = request.json
    asset_id = data.get('asset_id')
    ip_address = data.get('ip')
    port = data.get('port')

    if not all([asset_id, ip_address, port]):
        return jsonify({'error': 'Missing required parameters'}), 400

    # 1. Run the actual scan
    scan_result = run_single_nmap_scan(ip_address, port)

    # 2. Save result to database
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            query = """
                INSERT INTO nmap_scan_results (scan_id, asset_id, ip_address, port, protocol, status, service_banner, scan_timestamp)
                VALUES (gen_random_uuid(), %s, %s, %s, 'TCP', %s, %s, %s)
                ON CONFLICT (asset_id, port, protocol) 
                DO UPDATE SET status = EXCLUDED.status, service_banner = EXCLUDED.service_banner, scan_timestamp = EXCLUDED.scan_timestamp;
            """
            cursor.execute(query, (asset_id, ip_address, port, scan_result['status'], scan_result['banner'], datetime.now(timezone.utc)))
            conn.commit()
            cursor.close()
        except Exception as e:
            print(f"DB Error saving scan: {e}")
            # We still return the scan result to the user even if DB save fails temporarily
        finally:
            conn.close()

    return jsonify(scan_result)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5555, debug=True)