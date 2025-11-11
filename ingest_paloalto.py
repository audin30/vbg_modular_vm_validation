import os
import pandas as pd
import uuid
from db_connector import get_db_connection
from dotenv import load_dotenv
from psycopg2.extras import execute_values
import logging # <-- NEW: Import logging module

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables
load_dotenv()

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
CSV_FILE_PATH = os.path.join(DATA_DIR, 'paloalto_rules.csv')

def fetch_palo_rules_from_csv():
    """Fetches firewall rules from a local CSV file."""
    try:
        # Expected columns: rule_name, source_address, dest_address, service_port, protocol, action, policy_source
        # 'source_address' and 'dest_address' are strings with CIDRs separated by '|'
        df = pd.read_csv(CSV_FILE_PATH)
        logging.info(f"Successfully read {len(df)} rows from {CSV_FILE_PATH}") # <-- UPDATED: Use logging
        
        # We only care about 'allow' rules
        df = df[df['action'].str.lower() == 'allow'].copy()

        # Convert pipe-separated strings to Python lists (for the 'CIDR[]' SQL type)
        # We ensure that empty strings result in an empty list, not a list containing one empty string.
        df['source_address'] = df['source_address'].fillna('').apply(lambda x: x.split('|') if x else [])
        df['dest_address'] = df['dest_address'].fillna('').apply(lambda x: x.split('|') if x else [])

        # FIX: Handle NaN values
        # Fill missing ports with 0 (representing 'any' for the purpose of the policy)
        df['service_port'] = df['service_port'].fillna(0).astype(int)
        
        # FIX: Replace NaN/None in other columns with None for consistent SQL NULL
        df = df.astype(object)
        df = df.where(pd.notna(df), None)

        return df

    except FileNotFoundError:
        logging.error(f"Error: File not found at {CSV_FILE_PATH}") # <-- UPDATED: Use logging
        return pd.DataFrame()
    except Exception as e:
        logging.error(f"Error reading or processing CSV: {e}") # <-- UPDATED: Use logging
        return pd.DataFrame()

# --- REMOVED: format_list_for_sql_array is no longer needed ---

if __name__ == "__main__":
    conn = get_db_connection()
    if conn:
        logging.info("Fetching Palo Alto rules from CSV...") # <-- UPDATED: Use logging
        rules_df = fetch_palo_rules_from_csv()
        
        if not rules_df.empty:
            logging.info("Clearing old firewall rules from database...") # <-- UPDATED: Use logging
            cursor = conn.cursor()
            try:
                cursor.execute("TRUNCATE TABLE firewall_rules;")
                conn.commit()
                logging.info("Old rules cleared.") # <-- UPDATED: Use logging
                
                logging.info(f"Inserting {len(rules_df)} new 'allow' rules...") # <-- UPDATED: Use logging

                query = """
                INSERT INTO firewall_rules (
                    rule_id, rule_name, source_address, dest_address, 
                    service_port, protocol, action, policy_source
                ) VALUES %s
                """

                # Create data tuples, passing Python lists for array columns
                data_tuples = []
                for _, row in rules_df.iterrows():
                    data_tuples.append((
                        str(uuid.uuid4()), 
                        row['rule_name'],
                        # FIX: Pass the Python list of CIDRs directly
                        row['source_address'], 
                        row['dest_address'],
                        row['service_port'],
                        row['protocol'],
                        row['action'],
                        row['policy_source']
                    ))
                
                execute_values(cursor, query, data_tuples)
                conn.commit()
                
                logging.info(f"Successfully inserted {len(rules_df)} firewall rules.") # <-- UPDATED: Use logging
            
            except Exception as e:
                logging.error(f"Error during SQL execution: {e}") # <-- UPDATED: Use logging
                conn.rollback()
            finally:
                cursor.close()
        
        conn.close()