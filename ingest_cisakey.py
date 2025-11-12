import os
import pandas as pd
from db_connector import get_db_connection
from dotenv import load_dotenv
from psycopg2.extras import execute_values
import logging # <-- Ensure logging is imported

load_dotenv()
# Configure basic logging for this script
logging.basicConfig(level=logging.INFO, format='%(asctime)s - CISA_INGEST - %(levelname)s - %(message)s')

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
CSV_FILE_PATH = os.path.join(DATA_DIR, 'cisa_kev.csv')

def main():
    conn = get_db_connection()
    if not conn: return

    try:
        logging.info(f"Reading CISA KEV data from {CSV_FILE_PATH}...")
        df = pd.read_csv(CSV_FILE_PATH)
        
        # Ensure all columns exist, including the new 'kev_link' (added via mock_data.py)
        required_cols = [
            'cveID', 'vendorProject', 'product', 'vulnerabilityName', 
            'dateAdded', 'shortDescription', 'requiredAction', 'dueDate', 
            'kev_link' # <-- NEW: Required column
        ]
        
        # Simple check to ensure the CSV has the new column
        if 'kev_link' not in df.columns:
             df['kev_link'] = None
             logging.warning("CSV is missing 'kev_link' column. Inserting NULL values.")

        cursor = conn.cursor()
        logging.info("Clearing old CISA KEV data...")
        cursor.execute("TRUNCATE TABLE cisa_kev;")

        logging.info(f"Inserting {len(df)} CISA KEV records...")
        
        # UPDATED QUERY: Now includes the new 'kev_link' column
        query = """
            INSERT INTO cisa_kev (
                cve_id, vendor_project, product, vulnerability_name, 
                date_added, short_description, required_action, due_date, kev_link
            ) VALUES %s
        """
        
        # UPDATED TUPLE: Now includes the new 'kev_link' field
        data_tuples = [
            (row.cveID, row.vendorProject, row.product, row.vulnerabilityName,
             row.dateAdded, row.shortDescription, row.requiredAction, 
             row.dueDate, row.kev_link)
            for row in df.itertuples(index=False)
        ]
        
        execute_values(cursor, query, data_tuples)
        conn.commit()
        logging.info("CISA KEV ingestion complete.")

    except FileNotFoundError:
        logging.error(f"Error: File not found at {CSV_FILE_PATH}")
    except Exception as e:
        logging.error(f"Error during CISA ingestion: {e}")
        if conn: conn.rollback()
    finally:
        if conn: conn.close()

if __name__ == "__main__":
    main()