import subprocess
import sys
import logging
import os

# Configure basic logging for the runner
logging.basicConfig(level=logging.INFO, format='%(asctime)s - RUNNER - %(levelname)s - %(message)s')

INGESTION_SCRIPTS = [
    # 1. Generate Mock Data (Always run first if you don't have real CSVs)
    "mock_data.py", 
    
    # 2. Create the assets (Initial asset inventory, required for all others)
    "ingest_phpipam.py",

    # 3. Enriches the assets (Updates existing asset records)
    "ingest_wizassets.py",
    "ingest_virustotal.py",
    
    # 4. Ingests Lookup Tables (Needed for risk correlation)
    "ingest_cisakey.py",

    # 5. Creates the vulnerabilities (Links to assets created in step 2)
    "ingest_tenable.py",
    "ingest_wizvulns.py",

    # 6. Creates the network rules
    "ingest_paloalto.py",
]
NMAP_SCRIPT = "run_nmap_scan.py" # Separated the Nmap script

def run_script(script_name):
    """Executes a single Python script."""
    logging.info(f"--- Starting {script_name} ---")
    try:
        if not os.path.exists(script_name):
            logging.error(f"Script not found: {script_name}. Skipping.")
            return True
            
        result = subprocess.run(
            [sys.executable, script_name],
            check=True,
            capture_output=True,
            text=True
        )
        logging.info(f"{script_name} completed successfully.")
        
        if result.stdout:
            print(result.stdout.strip())
            
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"{script_name} FAILED with exit code {e.returncode}")
        print(f"Stdout:\n{e.stdout}")
        print(f"Stderr:\n{e.stderr}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred while running {script_name}: {e}")
        return False

def main():
    """Runs all ingestion scripts in the specified order."""
    logging.info("Starting batch ingestion process...")
    
    for script in INGESTION_SCRIPTS:
        # Simple skip check for mock data if files exist
        if script == "mock_data.py" and os.path.exists(os.path.join('data', 'phpipam_assets.csv')):
             logging.info("Mock data generation skipped: Data directory already contains CSVs.")
             continue

        success = run_script(script)
        if not success and script != "mock_data.py":
            logging.error("Ingestion failed on a critical step. Aborting sequence.")
            sys.exit(1)
            
    # --- NEW OPTIONAL NMAP STEP ---
    print("\n====================================")
    print("WARNING: The Nmap script performs an ACTIVE network scan.")
    
    # The run_nmap_scan.py script already has a "Type 'YES' to begin the scan" prompt inside it.
    # We will run the script, and let its internal prompt handle the final confirmation,
    # but we inform the user of its nature here.
    
    nmap_confirm = input(f"Do you want to run the active Nmap scan ({NMAP_SCRIPT}) now? (y/N): ")
    print("====================================\n")
    
    if nmap_confirm.lower() == 'y':
        # If the user says 'y', we run the script, which will then present its own internal 'YES' prompt.
        run_script(NMAP_SCRIPT)
    else:
        logging.warning("Nmap scan skipped by user request.")
        
    logging.info("====================================")
    logging.info("BATCH INGESTION COMPLETE. Database is populated.")
    logging.info("Next step: Run 'python app.py'")
    logging.info("====================================")

if __name__ == "__main__":
    main()