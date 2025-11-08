AI Vulnerability & Risk Correlation Engine

This project is based on the original script from audin30/vbg_modular_vm_validation.

This project is a backend application that correlates data from multiple enterprise security and IT sources to provide a true risk analysis of vulnerabilities, rather than relying on CVSS scores alone.It ingests data from various sources (asset management, vulnerability scanners, firewalls), correlates it in a central database, and then uses a Large Language Model (LLM) to analyze the correlated data and provide a human-readable, prioritized list of risks.Core Concept: The "True Risk" ProblemA CVSS 10.0 vulnerability on an internal test server with no network access is less critical than a CVSS 6.5 vulnerability on a public-facing, internet-exposed production database.This tool aims to solve that problem by correlating:Asset Context (phpIPAM): What is this asset? Is it Production? Who owns it?Vulnerability Data (Tenable/Wiz): What CVE is on the asset? What port is it on?Cloud/Exposure Context (Wiz): Is this asset is_public (internet-facing)?Network Path (Palo Alto): Is there an Allow rule from the INTERNET to the vulnerable asset and port?Threat Intel (VirusTotal): Is the asset's IP or domain malicious (high VT score)?Active Verification (Nmap): Is the vulnerable port actually open, closed, or filtered?The application's goal is to take into consideration the uniqueness of cloud-native and hybrid infrastructure, including the different internal setups of each business unit, to move beyond generic vulnerability management.Project Structure/ai-vulnerability-analyst
|
|-- data/                     # Directory to hold the CSV data files
|   |-- phpipam_assets.csv      # Mock asset data (IP, hostname, owner, env)
|   |-- tenable_vulns.csv       # Mock vulnerability data (IP, cve, port)
|   |-- wiz_assets.csv          # Mock cloud asset data (IP, is_public, os)
|   |-- wiz_vulns.csv           # Mock cloud vulnerability data
|   |-- paloalto_rules.csv      # Mock firewall rules (source, dest, port)
|   |-- virustotal_reports.csv  # Mock VT scores (ip, domain, score)
|
|-- .env                      # Stores all secrets (DB pass, API keys)
|-- .gitignore                # Standard Python .gitignore
|
|-- schema.sql                # SQL script to create all DB tables and indexes
|-- requirements.txt          # Python libraries for ingestion (pandas, psycopg2, nmap, faker)
|-- server_requirements.txt   # Python libraries for the backend (flask, requests)
|
|-- generate_mock_csvs.py     # SCRIPT: (Tester) Creates all 50+ mock CSVs in /data
|
|-- ingest_phpipam_csv.py     # SCRIPT: Ingestor 1: Reads phpipam_assets.csv -> assets table
|-- ingest_wiz_assets_csv.py  # SCRIPT: Ingestor 2: Reads wiz_assets.csv -> updates assets table
|-- ingest_virustotal_csv.py  # SCRIPT: Ingestor 3: Reads virustotal_reports.csv -> updates assets table
|-- ingest_tenable_csv.py     # SCRIPT: Ingestor 4: Reads tenable_vulns.csv -> vulnerabilities table
|-- ingest_wiz_vulns_csv.py   # SCRIPT: Ingestor 5: Reads wiz_vulns.csv -> vulnerabilities table
|-- ingest_paloalto_csv.py    # SCRIPT: Ingestor 6: Reads paloalto_rules.csv -> firewall_rules table
|-- run_nmap_scan.py          # SCRIPT: Ingestor 7: (Active Scan) -> nmap_scan_results table
|
|-- app.py                    # BACKEND: The Flask server (RAG Engine)
|-- ai_vuln_analyst.html      # FRONTEND: The Web UI (Dashboard)
|-- db_connector.py           # Helper: Manages database connection
|-- check_connection.py       # Helper: (Tester) Verifies DB connection and .env file
|
|-- README.md                 # This file
How to Run (Windows 11 / PowerShell)1. One-Time SetupInstall Python (3.8+).Install PostgreSQL (and create a database, e.g., csg_dso_ai).Clone this repository and cd into the project directory.Create a Virtual Environment:python -m venv venv
.\venv\Scripts\Activate.ps1
Install Dependencies:pip install -r requirements.txt
pip install -r server_requirements.txt
Create your .env file:Create a file named .env in the root folder.Copy the contents of .env.example (if provided) or add the following keys:PG_DBNAME="your_db_name"
PG_USER="your_postgres_user"
PG_PASSWORD="your_postgres_password"
PG_HOST="localhost"
PG_PORT="5432"
GEMINI_API_KEY="YOUR_GOOGLE_AI_STUDIO_API_KEY"
Create the Database Schema:Find the psql.exe file (e.g., C:\Program Files\PostgreSQL\16\bin\psql.exe).Run the schema script from PowerShell (use your own credentials):& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -h localhost -U your_postgres_user -d your_db_name -f schema.sql
2. Verify Your ConnectionBefore ingesting, run the connection checker. This will validate your .env file and database connection.python check_connection.py
If this script is successful, you are ready to ingest data.3. Run the Ingestion Scripts (In Order)This is the main workflow. Run these scripts one by one to populate your database.Generate Mock Data (First time only):python generate_mock_csvs.py
(Alternatively, place your real CSVs in the data/ folder).Run Ingestion Scripts (Order is important):# 1. Creates the assets
python ingest_phpipam_csv.py

# 2. Enriches the assets
python ingest_wiz_assets_csv.py
python ingest_virustotal_csv.py

# 3. Creates the vulnerabilities (links to assets)
python ingest_tenable_csv.py
python ingest_wiz_vulns_csv.py

# 4. Creates the firewall rules
python ingest_paloalto_csv.py

# 5. Runs the live scan (links to assets & vulns)
python run_nmap_scan.py 
4. Run the ApplicationStart the Backend Server:In your PowerShell terminal, run:python app.py
Leave this terminal running. It is now serving your API at http://127.0.0.1:5555.Launch the Frontend:In your file explorer, find and double-click ai_vuln_analyst.html.It will open in your default browser.Click the "Run Analysis" button to get your prioritized list.