import os
import psycopg2
import psycopg2.extras
import json
import re
import nmap
from flask import Flask, request, jsonify, send_file # <-- Added send_file
from flask_cors import CORS
from dotenv import load_dotenv
import requests
import time
from datetime import datetime, timezone
import logging 

# Load environment variables
load_dotenv()

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')

app = Flask(__name__)
# FIX: Use the most permissive setting for testing across different IPs/ports
CORS(app, resources={r"/*": {"origins": "*"}}) 

# --- Database Connection ---
def get_db_connection():
    """Establishes and returns a connection to the PostgreSQL database."""
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
        logging.error(f"Error: Unable to connect to the database. {e}")
        return None

# --- Gemini API Call (UPDATED SCHEMA) ---
def call_gemini_api(system_prompt, augmented_prompt, retry_count=3):
    """Handles communication with the Gemini API with structured JSON output."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key: raise ValueError("GEMINI_API_KEY not set.")
    
    logging.info("Calling Gemini API for risk analysis...")
    
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key={api_key}"
    headers = {'Content-Type': 'application/json'}
    
    # Required fields for LLM output and frontend linking
    json_schema = {
        "type": "ARRAY",
        "items": {
            "type": "OBJECT",
            "properties": {
                "priority": {"type": "NUMBER"},
                "asset_id": {"type": "STRING"},      
                "asset_hostname": {"type": "STRING"},
                "cve": {"type": "STRING"},
                "vuln_port": {"type": "NUMBER"},     
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
            logging.info(f"Gemini API call successful after {i+1} attempt(s).")
            raw_text = response.json()['candidates'][0]['content']['parts'][0]['text']
            clean_text = re.sub(r'^```json\s*|```\s*$', '', raw_text, flags=re.MULTILINE)
            return json.loads(clean_text)
        except Exception as e:
            logging.warning(f"Gemini API attempt {i+1} failed: {e}. Retrying in {delay}s.")
            if i == retry_count - 1: 
                logging.error("Gemini API call failed permanently after retries.")
                raise e
            time.sleep(delay)
            delay *= 2

# --- Analysis Helper (USES CORRELATED VIEW) ---
def fetch_correlated_risks(conn):
    """
    Fetches all correlated data directly from the correlated_vulnerability_risk view.
    """
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        logging.info("Fetching correlated risk data from view...")
        # Query the view directly—all correlation is pre-calculated!
        cursor.execute("""
            SELECT 
                * FROM 
                correlated_vulnerability_risk;
        """)
        res = cursor.fetchall()
        logging.info(f"Retrieved {len(res)} correlated risks.")
        return res
    except Exception as e:
        logging.error(f"Error fetching data from view: {e}")
        raise e
    finally:
        cursor.close()

# --- Nmap Scan Function (No Change) ---
def run_single_nmap_scan(ip, port):
    """Runs an immediate Nmap scan for on-demand verification."""
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

# --- Dashboard & Owner Queries (Retained) ---

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
    finally: cursor.close()


# --- Routes ---

# NEW: Route to serve the HTML file
@app.route('/')
def index():
    """Serves the main HTML file when accessing the root URL."""
    return send_file('ai_vuln_analyst.html')

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
    Input JSON has: Asset Context, Vulnerability Data, CISA KEV status, Threat Intel, Network Exposure, Live Verification, and **GreyNoise Classification**.
    Task: Return prioritized JSON array. 'priority' field must be sequential (1, 2, 3...).
    CRITICALITY RULES:
    1. **CISA KEV & EXPOSED:** PRIORITY #1 if 'is_cisa_kev: True' AND 'is_internet_exposed_via_fw: True'.
    2. **Active Threat:** PRIORITY #2 if 'gn_classification: malicious' or VirusTotal score >= 70.
    3. **Deprioritize Noise:** Decrease priority by 2 points if 'gn_classification: benign'.
    4. **Verified Internal Risk:** 'Production' asset AND 'nmap_port_status: open'.
    5. **Mitigating Factors:** 'nmap_port_status: closed' or low CVSS lowers risk.
    You MUST return the 'asset_id' and 'vuln_port' from the input in your output JSON for functional linking.
    Provide concise 'justification' and actionable 'recommendation'.
    """
    conn = get_db_connection()
    if not conn: return jsonify({"error": "DB failed"}), 500
    try:
        # Calls the view, which now includes the gn_classification field
        vulnerabilities = fetch_correlated_risks(conn)
        
        if not vulnerabilities: 
            logging.info("No vulnerabilities found for analysis.")
            return jsonify({"error": "No vulns found."}), 404
        
        # Prepare the input data for the LLM
        augmented_data = []
        ip_map = {}
        
        for vuln in vulnerabilities:
            vuln_dict = dict(vuln)
            
            # Determine network exposure based on the pre-calculated view field
            if vuln_dict['is_internet_exposed_via_fw']:
                vuln_dict['network_exposure'] = "INTERNET EXPOSED via Firewall Rule"
            elif vuln_dict['is_public']:
                vuln_dict['network_exposure'] = "Public IP (No explicit Internet Allow Rule found)"
            else:
                vuln_dict['network_exposure'] = "Internally Exposed"
            
            # Populate map and clean types for JSON 
            ip_map[str(vuln_dict['asset_id'])] = vuln_dict['ip_address']
            
            # Clean and ensure required fields are present in the AI input
            vuln_dict['asset_id'] = str(vuln_dict['asset_id'])
            vuln_dict['vuln_port'] = int(vuln_dict['vuln_port'])
            vuln_dict['cvss_score'] = float(vuln_dict['cvss_score'])
            vuln_dict['vt_ip_score'] = int(vuln_dict['vt_ip_score'] or 0)
            vuln_dict['vt_domain_score'] = int(vuln_dict['vt_domain_score'] or 0)
            
            # Ensure GreyNoise field is included in the AI's input
            vuln_dict['gn_classification'] = vuln_dict.get('gn_classification', 'unknown') or 'unknown'
            
            augmented_data.append(vuln_dict)
        
        analysis_result = call_gemini_api(SYSTEM_PROMPT, json.dumps(augmented_data))
        
        # Use the asset_id and vuln_port returned by the AI for the final result
        final_result = []
        for res_item in analysis_result:
            asset_id_str = res_item.get('asset_id')
            ip_address = ip_map.get(asset_id_str)
            
            if ip_address:
                 # Re-inject scan_params using the IDs returned by the AI
                 res_item['scan_params'] = {
                    'asset_id': asset_id_str, 
                    'ip': ip_address, 
                    'port': res_item.get('vuln_port')
                }
                 final_result.append(res_item)
            else:
                 logging.warning(f"AI returned unknown asset_id: {asset_id_str}. Skipping result.")
                 
        logging.info("Analysis complete. Returning results.")
        return jsonify(final_result)
    except Exception as e:
        logging.error(f"Error in /analyze endpoint: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn: conn.close()

# --- Nmap Scan Endpoint (No Change) ---
@app.route('/scan-asset', methods=['POST'])
def scan_asset():
    data = request.json
    asset_id = data.get('asset_id')
    ip_address = data.get('ip')
    port = data.get('port')
    
    if not all([asset_id, ip_address, port]):
        logging.error(f"Missing scan parameters: asset_id={asset_id}, ip={ip_address}, port={port}")
        return jsonify({'error': 'Missing required parameters'}), 400

    logging.info(f"Received request for on-demand scan: {ip_address}:{port}")
    
    scan_result = run_single_nmap_scan(ip_address, port)

    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
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
            cursor.execute(query, (
                asset_id, 
                ip_address, 
                port, 
                scan_result['status'], 
                scan_result['name'],
                scan_result['banner'], 
                scan_result['version'],
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

    return jsonify({'status': scan_result['status'], 'banner': scan_result['banner']})

if __name__ == '__main__':
    logging.info("Starting Flask application...")
    # FIX: Bind to all interfaces (0.0.0.0) so it's accessible via LAN IP
    app.run(host='0.0.0.0', port=5555, debug=True)