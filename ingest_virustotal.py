import pandas as pd
import psycopg2
import os
import sys
from dotenv import load_dotenv
from psycopg2.extras import execute_values

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

def main():
    conn = get_db_connection()
    if conn is None:
        sys.exit(1)

    csv_path = os.path.join('data', 'virustotal_reports.csv')
    if not os.path.exists(csv_path):
        print(f"Error: File not found at {csv_path}")
        sys.exit(1)

    print(f"Reading VirusTotal data from {csv_path}...")
    df = pd.read_csv(csv_path)

    # 1. Update based on IP Address
    # Prepare data for IP-based updates
    ip_df = df[df['ip_address'].notna()][['ip_address', 'vt_ip_score', 'vt_domain_score']].copy()
    
    # Convert dataframe to a list of tuples for executemany
    ip_update_data = [
        (int(row['vt_ip_score']), int(row['vt_domain_score']), row['ip_address'])
        for _, row in ip_df.iterrows()
    ]

    cursor = conn.cursor()
    
    if ip_update_data:
        try:
            print(f"Updating {len(ip_update_data)} assets based on IP address...")
            
            # This is a safe UPDATE query. It only updates existing assets.
            update_query = """
            UPDATE assets
            SET 
                vt_ip_score = %s,
                vt_domain_score = %s
            WHERE
                ip_address = %s::inet;
            """
            
            # Use executemany for efficient batch updates
            cursor.executemany(update_query, ip_update_data)
            conn.commit()
            print(f"Successfully updated {cursor.rowcount} asset(s) with VirusTotal scores.")

        except Exception as e:
            print(f"Error during database update: {e}")
            conn.rollback()
        
    else:
        print("No valid IP address data found in CSV to update.")

    # 2. Update based on Hostname (Removed)
    # The previous logic to upsert based on hostname was incorrect and caused
    # the 'INSERT' error. This script's job is only to update assets
    # that were already created by the phpipam/wiz ingestors.

    cursor.close()
    conn.close()
    print("VirusTotal ingestion complete.")

if __name__ == "__main__":
    main()