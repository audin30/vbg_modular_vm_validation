import nmap
import psycopg2
import uuid
import os
import pandas as pd
from datetime import datetime
from dotenv import load_dotenv
from psycopg2.extras import RealDictCursor, execute_values

# Load environment variables
load_dotenv()

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
        print("Database connection successful.")
        return conn
    except Exception as e:
        print(f"Error: Unable to connect to the database. {e}")
        return None

def get_targets_to_scan(conn):
    """
    Finds public-facing assets with open vulnerabilities
    to create a list of scan targets (IPs and ports).
    """
    print("Fetching scan targets from database...")
    query = """
    SELECT
        a.asset_id,
        a.ip_address,
        STRING_AGG(DISTINCT v.port::text, ',') AS ports_to_scan
    FROM
        assets a
    JOIN
        vulnerabilities v ON a.asset_id = v.asset_id
    WHERE
        a.is_public = TRUE  -- Only scan assets marked as 'is_public'
        AND v.status = 'Open'
    GROUP BY
        a.asset_id, a.ip_address;
    """
    df = pd.read_sql(query, conn)
    print(f"Found {len(df)} public assets with open vulnerabilities.")
    return df

def run_nmap_scan(ip_address, ports_string):
    """
    Runs an Nmap scan on a single IP for a list of specific ports.
    
    WARNING: THIS IS AN ACTIVE SCAN.
    Only run this on IPs you have explicit permission to scan.
    """
    if not ip_address or not ports_string:
        return None

    print(f"--- WARNING: Actively scanning {ip_address} on ports {ports_string} ---")
    
    nm = nmap.PortScanner()
    scan_results = {}
    
    try:
        # -sV: Probe open ports to determine service/version info
        # -T4: Aggressive timing (faster)
        # We scan the specific ports reported as vulnerable
        nm.scan(ip_address, ports=ports_string, arguments='-sV -T4')

        if ip_address not in nm.all_hosts():
            print(f"Scan failed or host {ip_address} is down.")
            return {}

        scan_data = nm[ip_address]

        # Iterate over all protocols (e.g., 'tcp', 'udp')
        for proto in scan_data.all_protocols():
            ports = scan_data[proto].keys()
            for port in ports:
                port_data = scan_data[proto][port]
                scan_results[port] = {
                    "protocol": proto,
                    "state": port_data.get('state'),
                    "service_name": port_data.get('name'),
                    # --- FIX: 'product' is the banner, not 'banner' ---
                    "service_banner": port_data.get('product', ''), 
                    "service_version": port_data.get('version', '')
                }
        
        print(f"Scan complete for {ip_address}.")
        return scan_results

    except Exception as e:
        print(f"Error during Nmap scan for {ip_address}: {e}")
        return {}

def update_db_with_scan_results(conn, asset_id, ip_address, scan_results):
    """
    Upserts the Nmap scan results into the nmap_scan_results table.
    """
    if not scan_results:
        return

    cursor = conn.cursor()
    data_to_upsert = []
    scan_time = datetime.now(datetime.timezone.utc)

    for port, details in scan_results.items():
        data_to_upsert.append((
            str(uuid.uuid4()),  # scan_id
            asset_id,
            ip_address,
            port,
            details['protocol'],
            details['state'],
            details['service_name'],
            details['service_banner'],
            details['service_version'],
            scan_time
        ))

    # Define the UPSERT query
    query = """
    INSERT INTO nmap_scan_results (
        scan_id, asset_id, ip_address, port, protocol,
        status, service_name, service_banner, service_version, scan_timestamp
    )
    VALUES %s
    ON CONFLICT (asset_id, port, protocol)
    DO UPDATE SET
        status = EXCLUDED.status,
        service_name = EXCLUDED.service_name,
        service_banner = EXCLUDED.service_banner,
        service_version = EXCLUDED.service_version,
        scan_timestamp = EXCLUDED.scan_timestamp;
    """

    try:
        execute_values(cursor, query, data_to_upsert)
        conn.commit()
        print(f"Successfully updated {len(data_to_upsert)} Nmap results for {ip_address}.")
    except Exception as e:
        print(f"Error upserting Nmap data: {e}")
        conn.rollback()
    finally:
        cursor.close()

def main():
    conn = get_db_connection()
    if not conn:
        return

    targets_df = get_targets_to_scan(conn)

    if targets_df.empty:
        print("No targets to scan. Exiting.")
        conn.close()
        return

    print("\n*** NMAP SCANNER INITIATED ***")
    print("This script will actively scan your public-facing assets.")
    print("Ensure you have EXPLICIT PERMISSION before proceeding.")
    print("********************************\n")
    
    # Simple confirmation prompt
    if input("Type 'YES' to begin the scan: ") != "YES":
        print("Scan aborted by user.")
        conn.close()
        return

    for _, row in targets_df.iterrows():
        asset_id = row['asset_id']
        ip_address = str(row['ip_address']) # Convert IPAddress object to string
        ports_to_scan = row['ports_to_scan']
        
        results = run_nmap_scan(ip_address, ports_to_scan)
        
        if results:
            update_db_with_scan_results(conn, asset_id, ip_address, results)

    print("Nmap scan and database update complete.")
    conn.close()

if __name__ == "__main__":
    main()