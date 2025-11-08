import os
import pandas as pd
import uuid
from db_connector import get_db_connection
from dotenv import load_dotenv
from psycopg2.extras import execute_values

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
        print(f"Successfully read {len(df)} rows from {CSV_FILE_PATH}")

        # We only care about 'allow' rules
        df = df[df['action'].str.lower() == 'allow'].copy()

        # Convert pipe-separated strings to Python lists (for the 'CIDR[]' SQL type)
        df['source_address'] = df['source_address'].fillna('').apply(lambda x: x.split('|') if x else [])
        df['dest_address'] = df['dest_address'].fillna('').apply(lambda x: x.split('|') if x else [])

        # --- FIX: Handle NaN values ---
        # Fill missing ports with 0 (representing 'any')
        df['service_port'] = df['service_port'].fillna(0).astype(int)
        # -----------------------------

        return df

    except FileNotFoundError:
        print(f"Error: File not found at {CSV_FILE_PATH}")
        return pd.DataFrame()
    except Exception as e:
        print(f"Error reading or processing CSV: {e}")
        return pd.DataFrame()

def format_list_for_sql_array(py_list):
    """Converts a Python list ['a', 'b'] to a PostgreSQL array string '{a,b}'."""
    if not py_list:
        return '{}' # Return empty Postgres array
    return "{" + ",".join(py_list) + "}"

if __name__ == "__main__":
    conn = get_db_connection()
    if conn:
        print("Fetching Palo Alto rules from CSV...")
        rules_df = fetch_palo_rules_from_csv()
        
        if not rules_df.empty:
            print("Clearing old firewall rules from database...")
            cursor = conn.cursor()
            try:
                cursor.execute("TRUNCATE TABLE firewall_rules;")
                conn.commit()
                print("Old rules cleared.")
                
                print(f"Inserting {len(rules_df)} new 'allow' rules...")

                query = """
                INSERT INTO firewall_rules (
                    rule_id, rule_name, source_address, dest_address, 
                    service_port, protocol, action, policy_source
                ) VALUES %s
                """

                # Create data tuples with correctly formatted arrays
                data_tuples = []
                for _, row in rules_df.iterrows():
                    data_tuples.append((
                        str(uuid.uuid4()), # Convert UUID to string
                        row['rule_name'],
                        format_list_for_sql_array(row['source_address']),
                        format_list_for_sql_array(row['dest_address']),
                        row['service_port'],
                        row['protocol'],
                        row['action'],
                        row['policy_source']
                    ))
                
                execute_values(cursor, query, data_tuples)
                conn.commit()
                
                print(f"Successfully inserted {len(rules_df)} firewall rules.")
            
            except Exception as e:
                print(f"Error during SQL execution: {e}")
                conn.rollback()
            finally:
                cursor.close()
        
        conn.close()