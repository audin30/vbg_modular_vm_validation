import os
import psycopg2
import psycopg2.extras
import json
import re
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import requests
import time

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
CORS(app)  # This enables Cross-Origin Resource Sharing for your frontend

# --- Database Connection ---

def get_db_connection():
    """Establishes a connection to the PostgreSQL database."""
    try:
        conn = psycopg2.connect(
            dbname=os.environ.get("PG_DBNAME"),
            user=os.environ.get("PG_USER"),
            password=os.environ.get("PG_PASSWORD"),
            host=os.environ.get("PG_HOST"),
            port=os.environ.get("PG_PORT")
        )
        print("Database connection successful.")
        return conn
    except Exception as e:
        print(f"Error: Unable to connect to the database. {e}")
        return None

# --- Gemini API Call ---

def call_gemini_api(system_prompt, augmented_prompt, retry_count=3):
    """
    Calls the Gemini API with the provided prompt and structured JSON schema.
    Implements exponential backoff for retries.
    """
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY not set in environment.")

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key={api_key}"
    
    headers = {'Content-Type': 'application/json'}

    # Define the JSON schema for the *output* we want from the LLM
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
            },
            "propertyOrdering": ["priority", "asset_hostname", "cve", "cvss_score", "justification", "recommendation"]
        }
    }

    payload = {
        "contents": [{
            "parts": [{"text": augmented_prompt}]
        }],
        "systemInstruction": {
            "parts": [{"text": system_prompt}]
        },
        "generationConfig": {
            "responseMimeType": "application/json",
            "responseSchema": json_schema
        }
    }

    # Exponential backoff logic
    delay = 1
    for i in range(retry_count):
        try:
            response = requests.post(url, headers=headers, data=json.dumps(payload))
            
            # Check for HTTP errors
            response.raise_for_status() 

            # Try to parse the JSON response
            result = response.json()

            # Check for API-level errors in the response body
            if 'candidates' not in result or not result['candidates']:
                api_error_message = result.get('promptFeedback', {}).get('blockReason', 'Unknown API Error')
                raise Exception(f"API Error: {api_error_message} - Response: {result}")

            # Extract the text, clean it, and parse the JSON
            raw_text = result['candidates'][0]['content']['parts'][0]['text']
            # Clean any potential markdown ```json ... ``` wrappers
            clean_text = re.sub(r'^```json\s*|```\s*$', '', raw_text, flags=re.MULTILINE)
            
            return json.loads(clean_text)

        except requests.exceptions.RequestException as http_err:
            print(f"HTTP Error on attempt {i+1}: {http_err}")
            if i == retry_count - 1:
                raise
        except json.JSONDecodeError as json_err:
            print(f"JSON Decode Error on attempt {i+1}: {json_err}. Raw text: {raw_text}")
            if i == retry_count - 1:
                raise
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            if i == retry_count - 1:
                raise
        
        # Wait before retrying
        time.sleep(delay)
        delay *= 2 # Exponential backoff

    raise Exception("Failed to get a valid response from Gemini API after all retries.")


# --- Data Correlation Logic ---

def fetch_top_vulnerabilities(conn):
    """
    Fetches high-priority vulnerabilities and correlates them with
    asset, firewall, and Nmap data.
    """
    
    # --- CHANGE 1: Lowered CVSS score to 4.0 to include Medium priority ---
    # This query joins all our tables together.
    # It finds assets with high-CVSS vulnerabilities.
    query = """
    SELECT 
        a.hostname,
        a.ip_address,
        a.environment,
        a.description,
        a.owner,
        a.is_public,
        a.vt_ip_score,
        a.vt_domain_score,
        v.cve,
        v.cvss_score,
        v.port AS vuln_port,
        nmap.status AS nmap_port_status,
        nmap.service_banner AS nmap_service_banner
    FROM 
        vulnerabilities v
    JOIN 
        assets a ON v.asset_id = a.asset_id
    LEFT JOIN
        nmap_scan_results nmap ON a.asset_id = nmap.asset_id AND v.port = nmap.port
    WHERE 
        v.cvss_score >= 4.0
        AND v.status = 'Open'
    ORDER BY 
        v.cvss_score DESC, a.is_public DESC;
    """
    # -----------------------------------------------------------------------

    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query)
        vulnerabilities = cursor.fetchall()
        cursor.close()
        return vulnerabilities
    except Exception as e:
        print(f"Error querying vulnerabilities: {e}")
        conn.rollback()
        raise

def find_firewall_exposure(conn, ip_address, port):
    """
    Checks if a specific IP/port combination is exposed by any
    'Allow' rules in the firewall.
    """
    
    # This query uses the `&&` (overlaps) operator to check if the IP
    # is contained within any 'dest_address' CIDR arrays.
    # It uses the GIN index for performance.
    query = """
    SELECT 
        rule_name,
        source_address
    FROM 
        firewall_rules
    WHERE
        action = 'Allow'
        AND (service_port = %s OR service_port = 0)
        AND dest_address && ARRAY[%s::inet];
    """
    
    exposure_rules = []
    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute(query, (port, ip_address))
        rules = cursor.fetchall()
        cursor.close()
        
        for rule in rules:
            # Check for '0.0.0.0/0' (Any) in the source addresses
            is_internet_exposed = any(src == '0.0.0.0/0' for src in rule['source_address'])
            if is_internet_exposed:
                exposure_rules.append(f"INTERNET EXPOSED via rule '{rule['rule_name']}'")
            else:
                sources = ', '.join(rule['source_address'])
                exposure_rules.append(f"Internally exposed to '{sources}' via rule '{rule['rule_name']}'")

    except Exception as e:
        print(f"Error checking firewall exposure for {ip_address}:{port} : {e}")
        conn.rollback()
        # Don't raise, just return no exposure
    
    if not exposure_rules:
        return "Not Reachable (No 'Allow' rules found)"
    
    return "; ".join(exposure_rules)


# --- Main Application Route ---

@app.route('/analyze', methods=['GET'])
def analyze_vulnerabilities():
    
    # --- CHANGE 2: Updated prompt to rank all items, not just top 5-7 ---
    SYSTEM_PROMPT = """
    You are an expert-level cybersecurity risk analyst. Your job is to determine the *true business criticality* of vulnerabilities by correlating multiple data points.

    You will be given a list of vulnerabilities in JSON format. Each item contains:
    - **Asset Context (from phpIPAM/Wiz):** Hostname, Environment (Prod/Dev), Owner, and if it's 'is_public'.
    - **Vulnerability Data (from Tenable/Wiz):** The CVE and its CVSS score.
    - **Threat Intelligence (from VirusTotal):** 'vt_ip_score' and 'vt_domain_score'.
    - **Network Exposure (from Palo Alto):** Firewall rules showing if the port is exposed to the 'INTERNET' or 'Internally'.
    - **Live Verification (from Nmap):** The 'nmap_port_status' (e.g., 'open', 'closed', 'filtered') and the 'service_banner'.

    Your task is to analyze all this data and return a prioritized JSON array.
    The `priority` field you generate should be a sequential number (1, 2, 3, etc.).
    
    CRITICALITY RULES:
    1.  **Highest Criticality:** A public-facing ('is_public: True') asset with a 'Network Exposure: INTERNET EXPOSED' rule AND a 'Nmap Verification: open' status. This is a confirmed, exploitable, public-facing vulnerability.
    2.  **High Criticality:** A vulnerability on a 'Production' asset that is 'Internally exposed'.
    3.  **VirusTotal Rule:** A VirusTotal score (vt_ip_score or vt_domain_score) of 70 or higher is a major threat indicator and *dramatically* increases the criticality. Mention this in the justification.
    4.  **Nmap Rule:** 'Nmap Verification: open' confirms the risk. 'Nmap Verification: closed' or 'filtered' significantly *lowers* the risk, as the port is not live.
    5.  **Network Rule:** 'Not Reachable (No 'Allow' rules found)' means the vulnerability is 'Low' priority, regardless of CVSS score, as it is firewalled off.

    Provide a concise `justification` for each priority, explaining *why* it's ranked that way, and a short, actionable `recommendation`.
    Return *only* the JSON array based on the schema.
    """
    # -----------------------------------------------------------------------
    
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Failed to connect to the database."}), 500
        
        # 1. Fetch top vulnerabilities from the database
        vulnerabilities = fetch_top_vulnerabilities(conn)
        
        if not vulnerabilities:
            return jsonify({"error": "No vulnerabilities found meeting the criteria."}), 404

        # 2. Augment data with firewall exposure
        augmented_data = []
        for vuln in vulnerabilities:
            ip = vuln['ip_address']
            port = vuln['vuln_port']
            
            # Find firewall rules for each vulnerability
            exposure_info = find_firewall_exposure(conn, ip, port)
            
            # Create a dictionary from the row
            vuln_dict = dict(vuln)
            vuln_dict['network_exposure'] = exposure_info
            
            # Clean up types for JSON serialization
            vuln_dict['cvss_score'] = float(vuln['cvss_score'])
            vuln_dict['vt_ip_score'] = int(vuln['vt_ip_score'] or 0)
            vuln_dict['vt_domain_score'] = int(vuln['vt_domain_score'] or 0)
            
            augmented_data.append(vuln_dict)

        # 3. Create the final prompt for the LLM
        augmented_prompt = json.dumps(augmented_data, indent=2)

        # 4. Call the Gemini API
        analysis_result = call_gemini_api(SYSTEM_PROMPT, augmented_prompt)
        
        return jsonify(analysis_result)

    except Exception as e:
        print(f"An error occurred in /analyze: {e}")
        return jsonify({"error": f"An internal error occurred: {str(e)}"}), 500
    finally:
        if conn:
            conn.close()
            print("Database connection closed.")

if __name__ == '__main__':
    # Set host to '0.0.0.0' to make it accessible on your network
    # (or keep '127.0.0.1' for local-only access)
    app.run(host='127.0.0.1', port=5555, debug=True)