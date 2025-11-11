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
import logging # <-- NEW: Import logging module

# Load environment variables
load_dotenv()

# --- NEW: Configure basic logging ---
# Set the log level (e.g., INFO, DEBUG) and format
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')
# ------------------------------------

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
        # UPDATED: Use logging.error
        logging.error(f"Error: Unable to connect to the database. {e}")
        return None

# --- Gemini API Call ---
def call_gemini_api(system_prompt, augmented_prompt, retry_count=3):
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key: raise ValueError("GEMINI_API_KEY not set.")
    
    # UPDATED: Use logging.info before API call
    logging.info("Calling Gemini API for risk analysis...")
    
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
            
            # UPDATED: Log successful response
            logging.info(f"Gemini API call successful after {i+1} attempt(s).")
            
            raw_text = response.json()['candidates'][0]['content']['parts'][0]['text']
            clean_text = re.sub(r'^```json\s*|```\s*$', '', raw_text, flags=re.MULTILINE)
            return json.loads(clean_text)
        except Exception as e:
            # UPDATED: Log the failed attempt
            logging.warning(f"Gemini API attempt {i+1} failed: {e}. Retrying in {delay}s.")
            if i == retry_count - 1: 
                logging.error("Gemini API call failed permanently after retries.")
                raise e
            time.sleep(delay)
            delay *= 2

# --- Dashboard Queries (No Change to Logic, but logging is now used) ---
def get_dashboard_stats(conn):
    stats = {}
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        logging.info("Fetching dashboard statistics...")
        # ... SQL queries ...
        
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
        
        logging.info("Dashboard statistics fetched successfully.")
    except Exception as e:
        logging.error(f"Error fetching dashboard stats: {e}")
        raise e
    finally: 
        cursor.close()
    return stats

def get_assets_by_owner(conn, owner_name):
    # ... logic (add logging for start/success/error) ...
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        logging.info(f"Fetching assets for owner: {owner_name}")
        cursor.execute("""
            SELECT a.asset_id, a.hostname, a.ip_address, a.environment, a.is_public,
                COUNT(v.vuln_id) as open_vulns, MAX(v.cvss_score) as max_cvss
            FROM assets a LEFT JOIN vulnerabilities v ON a.asset_id = v.asset_id AND v.status = 'Open'
            WHERE a.owner = %s GROUP BY a.asset_id ORDER BY max_cvss DESC NULLS LAST, open_vulns DESC;
        """, (owner_name,))
        assets = cursor.fetchall()
        logging.info(f"Found {len(assets)} assets for owner {owner_name}.")
        return assets
    except Exception as e:
        logging.error(f"Error fetching assets by owner {owner_name}: {e}")
        raise e
    finally: 
        cursor.close()

# --- Analysis Helpers ---
def fetch_top_vulnerabilities(conn):
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        logging.info("Fetching top vulnerabilities for AI correlation...")
        cursor.execute("""
            SELECT a.asset_id, a.hostname, a.ip_address, a.environment, a.description, a.owner, a.is_public,
                   a.vt_ip_score, a.vt_domain_score, v.cve, v.cvss_score, v.port AS vuln_port,
                   nmap.status AS nmap_port_status, nmap.service_banner AS nmap_service_banner,
                   (ck.cve_id IS NOT NULL) AS is_cisa_kev
            FROM vulnerabilities v JOIN assets a ON v.asset_id = a.asset_id
            LEFT JOIN cisa_kev ck ON v.cve = ck.cve_id
            LEFT JOIN nmap_scan_results nmap ON a.asset_id = nmap.asset_id AND v.port = nmap.port AND v.protocol = nmap.protocol -- Added protocol match
            WHERE v.cvss_score >= 4.0 AND v.status = 'Open'
            ORDER BY is_cisa_kev DESC, v.cvss_score DESC, a.is_public DESC;
        """)
        res = cursor.fetchall()
        logging.info(f"Found {len(res)} vulnerabilities for correlation.")
        return res
    except Exception as e:
        logging.error(f"Error fetching vulnerabilities: {e}")
        raise e
    finally:
        cursor.close()

def find_firewall_exposure(conn, ip_address, port):
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
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
    except Exception as e:
        logging.error(f"Error checking firewall exposure for {ip_address}:{port}: {e}")
        return "Error checking firewall rules"

# --- Nmap Scan Function (Slightly improved logging) ---
def run_single_nmap_scan(ip, port):
    nm = nmap.PortScanner()
    try:
        logging.info(f"Starting on-demand scan for {ip}:{port}...")
        # -sV for service version, -Pn to skip ping, -p to specify port
        nm.scan(ip, arguments=f'-sV -Pn -p {port}')
        
        if ip not in nm.all_hosts():
            logging.warning(f"Host {ip} did not respond to scan.")
            return {'status': 'down', 'banner': None, 'name': None, 'version': None}

        tcp_info = nm[ip].get('tcp', {}).get(int(port))
        if not tcp_info:
            logging.info(f"Port {port} on {ip} is closed/filtered.")
            return {'status': 'closed', 'banner': None, 'name': None, 'version': None}

        # UPDATED: Return separate fields for database saving
        status = tcp_info['state']
        service_name = tcp_info.get('name')
        service_product = tcp_info.get('product', '')
        service_version = tcp_info.get('version', '')
        
        banner = f"{service_product} {service_version}".strip() or None
        
        logging.info(f"Scan complete for {ip}:{port}. Status: {status}")
        
        return {
            'status': status,
            'banner': banner,
            'name': service_name,
            'version': service_version
        }
    except Exception as e:
        logging.error(f"Nmap scan error for {ip}:{port}: {e}")
        return {'status': 'error', 'banner': str(e), 'name': None, 'version': None}

# --- Routes ---
@app.route('/dashboard-stats', methods=['GET'])
def dashboard_stats():
    conn = get_db_connection()
    if not conn: return jsonify({"error": "DB failed"}), 500
    try:
        stats = get_dashboard_stats(conn)
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if conn: conn.close()

@app.route('/owner-assets', methods=['GET'])
def owner_assets():
    owner = request.args.get('owner')
    if not owner: return jsonify({"error": "Owner required"}), 400
    conn = get_db_connection()
    if not conn: return jsonify({"error": "DB failed"}), 500
    try:
        assets = get_assets_by_owner(conn, owner)
        return jsonify(assets)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if conn: conn.close()

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
        if not vulnerabilities: 
            logging.info("No vulnerabilities found for analysis.")
            return jsonify({"error": "No vulns found."}), 404
        
        augmented_data = []
        for vuln in vulnerabilities:
            vuln_dict = dict(vuln)
            vuln_dict['network_exposure'] = find_firewall_exposure(conn, vuln['ip_address'], vuln['vuln_port'])
            vuln_dict['asset_id'] = vuln['asset_id']
            vuln_dict['vuln_port'] = vuln['vuln_port'] 
            vuln_dict['cvss_score'] = float(vuln['cvss_score'])
            vuln_dict['vt_ip_score'] = int(vuln['vt_ip_score'] or 0)
            vuln_dict['vt_domain_score'] = int(vuln['vt_domain_score'] or 0)
            augmented_data.append(vuln_dict)
        
        analysis_result = call_gemini_api(SYSTEM_PROMPT, json.dumps(augmented_data))
        
        # Inject scan parameters for the frontend 'Verify' button
        for res_item in analysis_result:
             for orig_item in augmented_data:
                 if res_item['asset_hostname'] == orig_item['hostname'] and res_item['cve'] == orig_item['cve']:
                     res_item['scan_params'] = {
                        'asset_id': orig_item['asset_id'], 
                        'ip': orig_item['ip_address'], 
                        'port': orig_item['vuln_port']
                    }
                     break
                     
        logging.info("Analysis complete. Returning results.")
        return jsonify(analysis_result)
    except Exception as e:
        logging.error(f"Error in /analyze endpoint: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn: conn.close()

# --- NEW ENDPOINT (Improved) ---
@app.route('/scan-asset', methods=['POST'])
def scan_asset():
    data = request.json
    asset_id = data.get('asset_id')
    ip_address = data.get('ip')
    port = data.get('port')
    
    # Input validation
    if not all([asset_id, ip_address, port]):
        logging.error(f"Missing scan parameters: asset_id={asset_id}, ip={ip_address}, port={port}")
        return jsonify({'error': 'Missing required parameters'}), 400

    logging.info(f"Received request for on-demand scan: {ip_address}:{port}")
    
    # 1. Run the actual scan
    scan_result = run_single_nmap_scan(ip_address, port)

    # 2. Save result to database
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            # FIX: Added service_name and service_version to the query
            query = """
                INSERT INTO nmap_scan_results (
                    scan_id, asset_id, ip_address, port, protocol, 
                    status, service_name, service_banner, service_version, scan_timestamp
                )
                VALUES (gen_random_uuid(), %s, %s, %s, 'TCP', %s, %s, %s, %s, %s)
                ON CONFLICT (asset_id, port, protocol) 
                DO UPDATE SET 
                    status = EXCLUDED.status, 
                    service_name = EXCLUDED.service_name,
                    service_banner = EXCLUDED.service_banner, 
                    service_version = EXCLUDED.service_version,
                    scan_timestamp = EXCLUDED.scan_timestamp;
            """
            # FIX: Mapping the new fields from scan_result to the query
            cursor.execute(query, (
                asset_id, 
                ip_address, 
                port, 
                scan_result['status'], 
                scan_result['name'], # <-- NEW: service_name
                scan_result['banner'], 
                scan_result['version'], # <-- NEW: service_version
                datetime.now(timezone.utc)
            ))
            conn.commit()
            logging.info(f"Successfully saved Nmap scan result for {ip_address}:{port}.")
            cursor.close()
        except Exception as e:
            logging.error(f"DB Error saving scan for {ip_address}:{port}: {e}")
            conn.rollback()
        finally:
            conn.close()

    # Return the clean result back to the frontend
    return jsonify({'status': scan_result['status'], 'banner': scan_result['banner']})

if __name__ == '__main__':
    logging.info("Starting Flask application...")
    app.run(host='127.0.0.1', port=5555, debug=True)