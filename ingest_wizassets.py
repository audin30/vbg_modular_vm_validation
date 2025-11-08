import os
import pandas as pd
from db_connector import get_db_connection
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
CSV_FILE_PATH = os.path.join(DATA_DIR, 'wiz_assets.csv')

def fetch_wiz_data_from_csv():
    """Fetches asset context from a local Wiz CSV export."""
    try:
        # Expected columns: ip_address, is_public, os
        df = pd.read_csv(CSV_FILE_PATH)
        print(f"Successfully read {len(df)} rows from {CSV_FILE_PATH}")

        # --- NEW FIX: Ensure all expected columns exist ---
        # If 'os' column is missing from CSV, create it with None
        if 'os' not in df.columns:
            df['os'] = pd.NA
        # If 'is_public' is missing, create it with None
        if 'is_public' not in df.columns:
            df['is_public'] = pd.NA
        # --------------------------------------------------
        
        # Add timestamp
        df['last_seen_wiz'] = pd.Timestamp.now(tz='UTC')

        # --- FIX: Handle NaN values ---
        # 1. Cast boolean columns to nullable boolean
        df['is_public'] = df['is_public'].astype('boolean')

        # 2. Convert all NaN/NaT to None (SQL NULL)
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

def update_assets_in_db(conn, assets_df):
    """
    Updates existing assets in the database with new info from Wiz
    based on matching 'ip_address'.
    """
    print(f"Updating {len(assets_df)} assets with Wiz data...")
    cursor = conn.cursor()
    
    # Create a temporary table to hold the staging data
    cursor.execute("""
    CREATE TEMPORARY TABLE wiz_stage (
        ip_address INET,
        is_public BOOLEAN,
        os TEXT,
        last_seen_wiz TIMESTAMPTZ
    ) ON COMMIT DROP;
    """)
    
    # Convert DataFrame to list of tuples for insertion
    data_tuples = [
        # This line will no longer fail, as 'os' is guaranteed to exist
        (row['ip_address'], row['is_public'], row['os'], row['last_seen_wiz'])
        for _, row in assets_df.iterrows()
        if pd.notna(row['ip_address']) # Don't try to update on NULL IP
    ]
    
    # Insert data into the temporary table
    from psycopg2.extras import execute_values
    execute_values(cursor, "INSERT INTO wiz_stage VALUES %s", data_tuples)
    
    # Update the main 'assets' table from the temporary table
    update_query = """
    UPDATE assets
    SET
        is_public = COALESCE(s.is_public, assets.is_public),
        os = COALESCE(s.os, assets.os),
        last_seen_wiz = s.last_seen_wiz
    FROM wiz_stage s
    WHERE assets.ip_address = s.ip_address;
    """
    
    try:
        cursor.execute(update_query)
        conn.commit()
        print(f"Successfully updated {cursor.rowcount} assets in the database.")
    except Exception as e:
        print(f"Error updating assets from staging table: {e}")
        conn.rollback()
    finally:
        cursor.close()

if __name__ == "__main__":
    conn = get_db_connection()
    if conn:
        print("Fetching Wiz asset data from CSV...")
        raw_assets_df = fetch_wiz_data_from_csv()
        
        if not raw_assets_df.empty:
            update_assets_in_db(conn, raw_assets_df)
        
        conn.close()