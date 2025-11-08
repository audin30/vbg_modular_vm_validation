import os
import pandas as pd
import uuid
from db_connector import get_db_connection, batch_upsert
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
CSV_FILE_PATH = os.path.join(DATA_DIR, 'tenable_vulns.csv')

def fetch_tenable_data_from_csv():
    """Fetches vulnerabilities from a local Tenable CSV export."""
    try:
        # Expected columns: asset_ip, cve, cvss_score, port, protocol, status, first_seen, last_seen
        df = pd.read_csv(CSV_FILE_PATH)
        print(f"Successfully read {len(df)} rows from {CSV_FILE_PATH}")
        
        # Add source
        df['source'] = 'Tenable'
        
        # --- THIS IS THE FIX ---
        # Convert date columns, turning any errors into NaT (NULL)
        df['first_seen'] = pd.to_datetime(df['first_seen'], utc=True, errors='coerce')
        df['last_seen'] = pd.to_datetime(df['last_seen'], utc=True, errors='coerce')
        # ---------------------

        # --- FIX: Handle NaN values ---
        # Convert all columns to object type first, so they can hold 'None'
        df = df.astype(object)
        # Replace all pandas-native nulls (NaN, NaT, <NA>) with Python's None
        df = df.where(pd.notna(df), None)
        # -----------------------------

        return df

    except FileNotFoundError:
        print(f"Error: File not found at {CSV_FILE_PATH}")
        return pd.DataFrame()
    except Exception as e:
        print(f"Error reading or processing CSV: {e}")
        return pd.DataFrame()

def link_assets(conn, vuln_df):
    """
    Links vulnerabilities to the asset_id from our 'assets' table
    using the 'asset_ip' field from the CSV.
    """
    print("Linking vulnerabilities to asset IDs...")
    try:
        asset_map_df = pd.read_sql("SELECT asset_id, ip_address FROM assets", conn)
    except Exception as e:
        print(f"Error reading from assets table: {e}")
        return pd.DataFrame()

    if asset_map_df.empty:
        print("Error: No assets found in the database. Run the phpIPAM ingest first.")
        return pd.DataFrame()
        
    # Merge the dataframes to get the foreign key
    merged_df = vuln_df.merge(
        asset_map_df,
        left_on='asset_ip',
        right_on='ip_address',
        how='inner' # 'inner' join drops vulns for assets we don't track
    )
    
    # Clean up and select final columns for the 'vulnerabilities' table
    final_df = merged_df.drop(columns=['asset_ip', 'ip_address'])
    
    # We need a unique key for the upsert
    # A single asset can have the same CVE on multiple ports
    final_df = final_df.drop_duplicates(subset=['asset_id', 'cve', 'port'])
    
    # Generate vuln_id (Primary Key) as a string
    final_df['vuln_id'] = [str(uuid.uuid4()) for _ in range(len(final_df))]
    
    return final_df

if __name__ == "__main__":
    conn = get_db_connection()
    if conn:
        print("Fetching Tenable data from CSV...")
        raw_vulns_df = fetch_tenable_data_from_csv()
        
        if not raw_vulns_df.empty:
            linked_vulns_df = link_assets(conn, raw_vulns_df)
            
            if not linked_vulns_df.empty:
                print(f"Ready to upsert {len(linked_vulns_df)} linked vulnerabilities.")
                batch_upsert(
                    conn=conn,
                    df=linked_vulns_df,
                    table_name="vulnerabilities",
                    # A vuln is unique by asset, CVE, and port
                    unique_columns=['asset_id', 'cve', 'port'] 
                )
            else:
                print("No vulnerabilities were linked to existing assets.")
        
        conn.close()