import os
import pandas as pd
from db_connector import get_db_connection, batch_upsert
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
CSV_FILE_PATH = os.path.join(DATA_DIR, 'wiz_assets.csv')

def fetch_wiz_assets_from_csv():
    """Fetches Wiz asset context (like is_public) from a local CSV."""
    try:
        # Expected columns: ip_address, is_public, last_seen_wiz
        df = pd.read_csv(CSV_FILE_PATH)
        print(f"Successfully read {len(df)} rows from {CSV_FILE_PATH}")

        # Convert date columns
        df['last_seen_wiz'] = pd.to_datetime(df['last_seen_wiz'], utc=True)
        
        # Ensure correct data types
        df = df.astype({
            "ip_address": "string",
            "is_public": "bool",
        })

        return df

    except FileNotFoundError:
        print(f"Error: File not found at {CSV_FILE_PATH}")
        return pd.DataFrame()
    except Exception as e:
        print(f"Error reading or processing CSV: {e}")
        return pd.DataFrame()

if __name__ == "__main__":
    conn = get_db_connection()
    if conn:
        print("Fetching Wiz asset data from CSV...")
        assets_df = fetch_wiz_assets_from_csv()
        
        if not assets_df.empty:
            # This script's job is to ENRICH existing assets.
            # We use 'ip_address' as the key to find and update records.
            assets_df = assets_df.drop_duplicates(subset=['ip_address'])
            
            batch_upsert(
                conn=conn,
                df=assets_df,
                table_name="assets",
                unique_columns=['ip_address'] # Conflict on IP to update 'is_public'
            )
        
        conn.close()