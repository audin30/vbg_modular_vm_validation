import os
import pandas as pd
from db_connector import get_db_connection
from dotenv import load_dotenv
from psycopg2.extras import execute_values

load_dotenv()
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
CSV_FILE_PATH = os.path.join(DATA_DIR, 'cisa_kev.csv')

def main():
    conn = get_db_connection()
    if not conn: return

    try:
        print(f"Reading CISA KEV data from {CSV_FILE_PATH}...")
        df = pd.read_csv(CSV_FILE_PATH)
        
        # Ensure columns match what CISA provides (and what we mocked)
        # cveID, vendorProject, product, vulnerabilityName, dateAdded, shortDescription, requiredAction, dueDate
        
        cursor = conn.cursor()
        print("Clearing old CISA KEV data...")
        cursor.execute("TRUNCATE TABLE cisa_kev;")

        print(f"Inserting {len(df)} CISA KEV records...")
        query = """
            INSERT INTO cisa_kev (
                cve_id, vendor_project, product, vulnerability_name, 
                date_added, short_description, required_action, due_date
            ) VALUES %s
        """
        
        data_tuples = [
            (row.cveID, row.vendorProject, row.product, row.vulnerabilityName,
             row.dateAdded, row.shortDescription, row.requiredAction, row.dueDate)
            for row in df.itertuples(index=False)
        ]
        
        execute_values(cursor, query, data_tuples)
        conn.commit()
        print("CISA KEV ingestion complete.")

    except FileNotFoundError:
        print(f"Error: File not found at {CSV_FILE_PATH}")
    except Exception as e:
        print(f"Error during CISA ingestion: {e}")
        if conn: conn.rollback()
    finally:
        if conn: conn.close()

if __name__ == "__main__":
    main()