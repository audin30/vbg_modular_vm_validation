import os
import sys
import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def get_db_connection():
    """
    Establishes and returns a connection to the PostgreSQL database
    using credentials from the .env file.
    """
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
        print(f"Error: Unable to connect to the database. {e}", file=sys.stderr)
        return None

def batch_upsert(conn, df, table_name, unique_columns):
    """
    Performs a high-performance "UPSERT" (INSERT ON CONFLICT)
    using a pandas DataFrame.

    - conn: The psycopg2 connection object.
    - df: The pandas DataFrame with your data.
    - table_name: The name of the database table to upsert into.
    - unique_columns: A list of column names that form the unique constraint
                      (e.g., ['ip_address']).
    """
    if df.empty:
        print(f"No data to upsert for {table_name}.")
        return

    cols = ','.join([f'"{col}"' for col in df.columns]) # Handle special column names
    
    # Create the 'excluded' part of the update statement
    update_cols = ', '.join([
        f'"{col}"=EXCLUDED."{col}"' for col in df.columns if col not in unique_columns
    ])
    
    # Create the conflict constraint
    constraint = ','.join([f'"{col}"' for col in unique_columns])
    
    # Create the full SQL query
    query = f"""
    INSERT INTO {table_name} ({cols})
    VALUES %s
    ON CONFLICT ({constraint})
    DO UPDATE SET {update_cols};
    """
    
    cursor = conn.cursor()
    try:
        # Convert DataFrame to a list of tuples
        data_tuples = [tuple(x) for x in df.to_numpy()]
        
        # Use execute_values for efficient batch insertion
        execute_values(cursor, query, data_tuples)
        conn.commit()
        print(f"Successfully upserted {len(data_tuples)} rows to {table_name}.")
    except Exception as e:
        print(f"Error during batch upsert to {table_name}: {e}", file=sys.stderr)
        conn.rollback()
    finally:
        cursor.close()

if __name__ == "__main__":
    # You can run this file directly to test your connection
    # python db_connector.py
    print("Testing database connection...")
    connection = get_db_connection()
    if connection:
        print("Connection successful!")
        connection.close()
    else:
        print("Connection failed. Check your .env file and PostgreSQL server.")