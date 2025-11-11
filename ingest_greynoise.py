import os
import pandas as pd
from dotenv import load_dotenv
import logging
from greynoise.api import GreyNoise, APIConfig
from db_connector import get_db_connection, batch_upsert # Assuming batch_upsert is available

load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - GN_INGEST - %(levelname)s - %(message)s')

def get_greynoise_client():
    """Initializes and returns the GreyNoise API client."""
    api_key = os.environ.get("GREYNOISE_API_KEY")
    if not api_key:
        logging.error("GREYNOISE_API_KEY not set in .env. Skipping GreyNoise ingestion.")
        return None
        
    try:
        api_config = APIConfig(
            api_key=api_key, 
            integration_name="ai-vulnerability-analyst-v1.0"
        )
        # Using the standard GreyNoise client
        return GreyNoise(api_config)
    except Exception as e:
        logging.error(f"Error initializing GreyNoise client: {e}")
        return None

def fetch_ip_data(conn):
    """Fetches all unique IP addresses from the assets table."""
    try:
        # Only grab IPs that haven't been enriched recently or ever
        df = pd.read_sql("SELECT ip_address FROM assets", conn)
        return df['ip_address'].tolist()
    except Exception as e:
        logging.error(f"Error fetching IPs from database: {e}")
        return []

def main():
    gn_client = get_greynoise_client()
    if not gn_client: return

    conn = get_db_connection()
    if not conn: return
    
    ips_to_query = fetch_ip_data(conn)
    if not ips_to_query:
        logging.info("No IP addresses found to query.")
        conn.close()
        return

    logging.info(f"Querying GreyNoise for {len(ips_to_query)} IPs...")
    
    try:
        # Use the multi-lookup quick endpoint for efficiency
        # This function handles batching internally up to the limit of the client/API
        gn_results = gn_client.quick(ips_to_query)

        update_data = []
        for result in gn_results:
            # Only process results that were found
            if result.get('internet_scanner_intelligence', {}).get('found') or result.get('business_service_intelligence', {}).get('found'):
                update_data.append({
                    'ip_address': result.get('ip'),
                    # Prioritize Classification from Internet Scanner, otherwise rely on RIOT/Business Service
                    'gn_classification': result.get('internet_scanner_intelligence', {}).get('classification') or 'RIOT', 
                    'gn_last_seen': result.get('internet_scanner_intelligence', {}).get('last_seen') or None
                })
        
        if not update_data:
            logging.info("No GreyNoise results found for any IPs.")
            conn.close()
            return
            
        gn_df = pd.DataFrame(update_data)
        
        # Prepare the DataFrame for upsert (only using update-able columns)
        final_df = gn_df[['ip_address', 'gn_classification', 'gn_last_seen']].copy()

        # Update the assets table (using batch_upsert logic from db_connector.py)
        # Note: batch_upsert performs an upsert based on the unique key 'ip_address'
        batch_upsert(
            conn=conn,
            df=final_df,
            table_name="assets",
            unique_columns=['ip_address']
        )
        
    except Exception as e:
        logging.error(f"Error during GreyNoise API query or upsert: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    main()