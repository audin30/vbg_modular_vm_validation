import os
import pandas as pd
import datetime
import random
from faker import Faker

# --- Configuration ---
NUM_ASSETS = 50
NUM_VULNERABILITIES = 35 # Less than assets, as not everything is vulnerable
PUBLIC_IP_CHANCE = 0.3   # 30% of assets will be public-facing
VT_THREAT_CHANCE = 0.1   # 10% of assets will have a high VT score

# Initialize Faker
fake = Faker()

# --- Reusable Data Pools ---
ENVIRONMENTS = ["Production", "Staging", "Development", "QA"]
OWNERS = ["Finance Team", "Web Team", "Engineering", "QA Team", "Data Science", "Marketing"]
COMMON_PORTS = [22, 80, 443, 3306, 5432, 8080, 9200, 6379]
CVE_LIST = [
    "CVE-2023-1234", "CVE-2023-5678", "CVE-2023-9999", "CVE-2023-4444",
    "CVE-2024-2222", "CVE-2024-3333", "CVE-2024-5555", "CVE-2024-8765"
]
OS_LIST = [
    "Ubuntu 22.04 LTS", "Ubuntu 20.04 LTS", "RHEL 8", "RHEL 9",
    "Windows Server 2019", "Windows Server 2022", "Debian 11"
]
STATUSES = ["Open", "Fixed"] # We'll mostly use 'Open'
PROTOCOLS = ["TCP", "UDP"]

def generate_assets():
    """Generates a list of 50 mock assets."""
    assets = []
    for _ in range(NUM_ASSETS):
        env = random.choice(ENVIRONMENTS)
        hostname = f"{env.lower()}-{fake.word().lower()}-{random.randint(1, 99)}.company.local"
        
        # Make some public, some private
        is_public = random.random() < PUBLIC_IP_CHANCE
        if is_public:
            ip_address = fake.ipv4_public()
        else:
            ip_address = fake.ipv4_private()
            
        assets.append({
            "ip_address": ip_address,
            "hostname": hostname,
            "environment": env,
            "description": f"{env} {fake.bs().title()} Server",
            "owner": random.choice(OWNERS),
            "os": random.choice(OS_LIST),
            "is_public": is_public # We'll use this to build other data
        })
    return assets

def generate_correlated_data(assets):
    """
    Generates vulnerabilities, firewall rules, and VT reports
    based on the master asset list.
    """
    wiz_assets_data = []
    vt_reports_data = []
    tenable_vulns_data = []
    wiz_vulns_data = []
    firewall_rules_data = []
    
    # Keep track of which assets have vulns to build rules
    vulnerable_assets = [] # (asset_ip, port, is_public)
    
    # --- Generate Wiz Assets & VT Reports (1-to-1 with assets) ---
    for asset in assets:
        wiz_assets_data.append({
            "ip_address": asset["ip_address"],
            "is_public": asset["is_public"],
            "os": f"{asset['os']} (Wiz Scan)",
            "last_seen_wiz": datetime.datetime.now(datetime.timezone.utc)
        })
        
        # Generate VT scores
        vt_ip_score = 0
        vt_domain_score = 0
        if random.random() < VT_THREAT_CHANCE:
            if random.random() < 0.5:
                vt_ip_score = random.randint(70, 100)
            else:
                vt_domain_score = random.randint(70, 100)
                
        vt_reports_data.append({
            "ip_address": asset["ip_address"],
            "hostname": asset["hostname"],
            "vt_ip_score": vt_ip_score,
            "vt_domain_score": vt_domain_score
        })

    # --- Generate Vulnerabilities (Fewer than assets) ---
    assets_to_make_vulnerable = random.sample(assets, NUM_VULNERABILITIES)
    
    for asset in assets_to_make_vulnerable:
        port = random.choice(COMMON_PORTS)
        vuln = {
            "asset_ip": asset["ip_address"],
            "cve": random.choice(CVE_LIST),
            "cvss_score": round(random.uniform(4.0, 10.0), 1),
            "port": port,
            "protocol": "TCP", # Most common
            "status": "Open", # Most interesting
            "first_seen": fake.date_time_this_year(tzinfo=datetime.timezone.utc).isoformat(),
            "last_seen": fake.date_time_between(start_date='-30d', tzinfo=datetime.timezone.utc).isoformat()
        }
        
        # Randomly assign to Tenable or Wiz
        if random.random() < 0.5:
            tenable_vulns_data.append(vuln)
        else:
            wiz_vulns_data.append(vuln)
        
        # Save this for the firewall rule generator
        vulnerable_assets.append((asset["ip_address"], port, asset["is_public"]))

    # --- Generate Correlated Firewall Rules ---
    rule_id_counter = 1
    for ip, port, is_public in vulnerable_assets:
        
        # Create a rule for this vulnerability
        rule_type = random.choice(["internet", "internal", "blocked"])
        
        if is_public and rule_type == "internet":
            # CRITICAL RISK: Public IP, Publicly exposed
            firewall_rules_data.append({
                "rule_name": f"Allow-Internet-to-Public-{rule_id_counter}",
                "source_address": "0.0.0.0/0",
                "dest_address": f"{ip}/32",
                "service_port": port,
                "protocol": "TCP",
                "action": "Allow",
                "policy_source": "edge-firewall-01"
            })
        elif rule_type == "internal":
            # MEDIUM RISK: Exposed to internal subnets
            firewall_rules_data.append({
                "rule_name": f"Allow-Internal-to-App-{rule_id_counter}",
                "source_address": "10.0.0.0/8|172.16.0.0/12|192.168.0.0/16",
                "dest_address": f"{ip}/32",
                "service_port": port,
                "protocol": "TCP",
                "action": "Allow",
                "policy_source": "corp-firewall-01"
            })
        # else (rule_type == "blocked"):
            # LOW RISK: No 'Allow' rule. We just don't create a rule,
            # so the backend will find "Not Reachable".

        rule_id_counter += 1

    # Add a final default deny rule (which will be ignored by ingest)
    firewall_rules_data.append({
        "rule_name": "Default-Deny-All",
        "source_address": "0.0.0.0/0",
        "dest_address": "0.0.0.0/0",
        "service_port": 0,
        "protocol": "TCP",
        "action": "Deny",
        "policy_source": "corp-firewall"
    })
    
    return wiz_assets_data, vt_reports_data, tenable_vulns_data, wiz_vulns_data, firewall_rules_data


def generate_csvs():
    """Generates all mock CSV files in the 'data' directory."""
    
    # Create data directory if it doesn't exist
    DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
        print(f"Created directory: {DATA_DIR}")

    # --- Generate all data ---
    print(f"Generating {NUM_ASSETS} mock assets...")
    phpipam_assets = generate_assets()
    
    print("Generating correlated data (Wiz assets, VT reports, vulns, firewall rules)...")
    wiz_assets, vt_reports, tenable_vulns, wiz_vulns, firewall_rules = generate_correlated_data(phpipam_assets)

    # --- Create DataFrames ---
    df_phpipam = pd.DataFrame(phpipam_assets)
    df_wiz_assets = pd.DataFrame(wiz_assets)
    df_tenable_vulns = pd.DataFrame(tenable_vulns)
    df_wiz_vulns = pd.DataFrame(wiz_vulns)
    df_palo_rules = pd.DataFrame(firewall_rules)
    df_vt_reports = pd.DataFrame(vt_reports)

    # --- Define file paths and write CSVs ---
    files = {
        'phpipam_assets.csv': df_phpipam,
        'wiz_assets.csv': df_wiz_assets,
        'tenable_vulns.csv': df_tenable_vulns,
        'wiz_vulns.csv': df_wiz_vulns,
        'paloalto_rules.csv': df_palo_rules,
        'virustotal_reports.csv': df_vt_reports,
    }

    for filename, df in files.items():
        path = os.path.join(DATA_DIR, filename)
        df.to_csv(path, index=False)
        print(f"Successfully generated: {path} ({len(df)} rows)")

    print(f"\nAll mock CSV files generated successfully in the 'data/' directory.")
    print(f"Total Assets: {len(df_phpipam)}")
    print(f"Total Vulnerabilities: {len(df_tenable_vulns) + len(df_wiz_vulns)}")
    print(f"Total 'Allow' Firewall Rules: {len(df_palo_rules[df_palo_rules['action'] == 'Allow'])}")
    print("You can now run the CSV ingestion scripts.")

if __name__ == "__main__":
    # Install Faker if you don't have it: pip install Faker
    generate_csvs()