import pandas as pd
import psycopg2
import os
import sys
import uuid  # <-- Added this to create primary keys
from dotenv import load_dotenv
from db_connector import get_db_connection, batch_upsert

# Load environment variables
load_dotenv()

def main():
    conn = get_db_connection()
    if conn is None:
        sys.exit(1)

    csv_path = os.path.join('data', 'phpipam_assets.csv')
    if not os.path.exists(csv_path):
        print(f"Error: File not found at {csv_path}")
        sys.exit(1)

    print(f"Reading phpIPAM data from {csv_path}...")
    df = pd.read_csv(csv_path)

    # Generate a UUID for the asset_id (Primary Key) for each row
    df['asset_id'] = [str(uuid.uuid4()) for _ in range(len(df))]

    # --- FIX: Check if column exists *before* trying to access it ---
    if 'last_seen_phpipam' in df.columns:
        # If column exists, convert it
        df['last_seen_phpipam'] = pd.to_datetime(df['last_seen_phpipam'], errors='coerce', utc=True)
    else:
        # If column does NOT exist, create it with the current time
        df['last_seen_phpipam'] = pd.Timestamp.now(tz='UTC')
    # ---------------------------------------------------------------


    # Define all columns the 'assets' table expects
    all_asset_columns = [
        'asset_id', 'ip_address', 'hostname', 'environment', 
        'description', 'owner', 'os', 'is_public', 
        'vt_ip_score', 'vt_domain_score',
        'last_seen_phpipam', 'last_seen_wiz', 'last_seen_tenable'
    ]
    
    # Use reindex to conform the DataFrame to the full table structure.
    df = df.reindex(columns=all_asset_columns)
    
    # --- FIX: Convert new empty timestamp columns from NaN (float) to NaT (datetime-null) ---
    df['last_seen_wiz'] = pd.to_datetime(df['last_seen_wiz'], errors='coerce', utc=True)
    df['last_seen_tenable'] = pd.to_datetime(df['last_seen_tenable'], errors='coerce', utc=True)
    # --------------------------------------------------------------------------------------
    
    # --- FIX: Handle NaN/NaT values before sending to DB ---
    # 1. Cast boolean columns to nullable boolean to handle NaN correctly
    if 'is_public' in df.columns:
        df['is_public'] = df['is_public'].astype('boolean') # This converts NaN to <NA>

    # 2. Convert all remaining NaN (float) or <NA> (bool) or NaT (datetime) to None
    #    (which psycopg2 converts to SQL NULL)
    
    # --- THIS IS THE FIX ---
    # Convert all columns to object type first, so they can hold 'None'
    df = df.astype(object)
    # Replace all pandas-native nulls (NaN, NaT, <NA>) with Python's None
    df = df.where(pd.notna(df), None)
    # -----------------------
    
    # Clear the assets table for a fresh start
    try:
        print("Clearing 'assets' table for fresh ingestion...")
        cursor = conn.cursor()
        # CASCADE drops dependent objects (like in vulnerabilities)
        cursor.execute("TRUNCATE TABLE assets CASCADE;")
        conn.commit()
        cursor.close()
    except Exception as e:
        print(f"Error truncating table: {e}")
        conn.rollback()
        conn.close()
        sys.exit(1)

    # Use batch_upsert to insert the new data
    # 'ip_address' is the unique key to check for conflicts
    batch_upsert(
        conn=conn,
        df=df,
        table_name="assets",
        unique_columns=['ip_address']
    )

    conn.close()
    print("phpIPAM ingestion complete.")

if __name__ == "__main__":
    main()