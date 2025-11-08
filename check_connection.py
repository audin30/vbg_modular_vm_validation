import os
import psycopg2
from dotenv import load_dotenv

print("--- Starting Connection Test ---")

# 1. Try to load the .env file
try:
    if load_dotenv():
        print("SUCCESS: .env file found and loaded.")
    else:
        print("WARNING: No .env file found.")
except Exception as e:
    print(f"ERROR: Failed to load .env file: {e}")

# 2. Print the environment variables it found
# (Don't worry, this only prints to your terminal)
print(f"  PG_DBNAME: {os.environ.get('PG_DBNAME')}")
print(f"  PG_USER: {os.environ.get('PG_USER')}")
print(f"  PG_HOST: {os.environ.get('PG_HOST')}")
print(f"  PG_PORT: {os.environ.get('PG_PORT')}")
# We'll skip printing the password for security

# 3. Try to connect to the database
conn = None
try:
    print("\nAttempting to connect to PostgreSQL...")
    conn = psycopg2.connect(
        dbname=os.environ.get("PG_DBNAME"),
        user=os.environ.get("PG_USER"),
        password=os.environ.get("PG_PASSWORD"),
        host=os.environ.get("PG_HOST"),
        port=os.environ.get("PG_PORT")
    )
    
    print("SUCCESS: Database connection established!")
    
    # 4. Try to read from the 'assets' table
    print("Attempting to query 'assets' table...")
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM assets;")
    count = cursor.fetchone()[0]
    print(f"SUCCESS: Found {count} rows in 'assets' table.")
    
except psycopg2.Error as e:
    print(f"\n--- DATABASE ERROR ---")
    print(f"Failed to connect or query the database. Error details:")
    print(e)
    print("------------------------")
    if "authentication failed" in str(e):
        print("HINT: Your password in .env might be wrong.")
    if "database" and "does not exist" in str(e):
        print("HINT: Your PG_DBNAME in .env might be wrong.")
    if "Connection refused" in str(e):
        print("HINT: Is your PostgreSQL server running? Is PG_HOST and PG_PORT correct?")
        
except Exception as e:
    print(f"\n--- UNEXPECTED SCRIPT ERROR ---")
    print(f"An error occurred: {e}")
    
finally:
    if conn:
        conn.close()
        print("\nDatabase connection closed.")
        
print("\n--- Test Finished ---")