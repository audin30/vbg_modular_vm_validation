import os
import pandas as pd
import datetime
import random
from faker import Faker

# --- Configuration ---
NUM_ASSETS = 50
NUM_VULNERABILITIES = 40
PUBLIC_IP_CHANCE = 0.3
VT_THREAT_CHANCE = 0.1

fake = Faker()

ENVIRONMENTS = ["Production", "Staging", "Development", "QA"]
OWNERS = ["Finance Team", "Web Team", "Engineering", "QA Team", "Data Science"]
COMMON_PORTS = [22, 80, 443, 3306, 5432, 8080, 3389]
# Some of these will be CISA KEV, some won't
CVE_LIST = [
    "CVE-2023-1234", "CVE-2023-5678", "CVE-2021-44228", "CVE-2023-9999",
    "CVE-2017-0144", "CVE-2024-2222", "CVE-2024-3333"
]
# The subset that are "known exploited" for our mock data
CISA_KEV_LIST = [
    "CVE-2021-44228", # Log4Shell
    "CVE-2017-0144",  # EternalBlue
    "CVE-2023-1234"   # Mock critical
]

OS_LIST = ["Ubuntu 22.04", "RHEL 8", "Windows Server 2019", "Debian 11"]

def generate_assets():
    assets = []
    for _ in range(NUM_ASSETS):
        env = random.choice(ENVIRONMENTS)
        is_public = random.random() < PUBLIC_IP_CHANCE
        assets.append({
            "ip_address": fake.ipv4_public() if is_public else fake.ipv4_private(),
            "hostname": f"{env.lower()}-{fake.word()}-{random.randint(1,99)}.local",
            "environment": env,
            "description": f"{env} Server",
            "owner": random.choice(OWNERS),
            "os": random.choice(OS_LIST),
            "is_public": is_public
        })
    return assets

def generate_cisa_kev():
    """Generates the mock CISA KEV catalog, now including the link."""
    kev_data = []
    for cve in CISA_KEV_LIST:
        kev_data.append({
            "cveID": cve,
            "vendorProject": "Mock Vendor",
            "product": "Mock Product",
            "vulnerabilityName": f"Active Exploit for {cve}",
            "dateAdded": fake.date_between(start_date='-2y', end_date='today').isoformat(),
            "shortDescription": "Attackers are actively exploiting this vulnerability in the wild.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": fake.future_date(end_date='+30d').isoformat(),
            # --- NEW FIELD ADDED HERE ---
            "kev_link": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search={cve}" 
        })
    return kev_data

def generate_correlated_data(assets):
    wiz_assets, vt_reports, tenable_vulns, wiz_vulns, firewall_rules = [], [], [], [], []
    vulnerable_assets = []

    for asset in assets:
        wiz_assets.append({"ip_address": asset["ip_address"], "is_public": asset["is_public"], "os": asset["os"], "last_seen_wiz": datetime.datetime.now(datetime.timezone.utc)})
        if random.random() < VT_THREAT_CHANCE:
             vt_reports.append({"ip_address": asset["ip_address"], "vt_ip_score": random.randint(60, 100), "vt_domain_score": random.randint(0, 100)})

    assets_to_make_vulnerable = random.sample(assets, NUM_VULNERABILITIES)
    for asset in assets_to_make_vulnerable:
        port = random.choice(COMMON_PORTS)
        cve = random.choice(CVE_LIST)
        # CISA KEVs usually have higher CVSS
        cvss = round(random.uniform(7.0, 10.0), 1) if cve in CISA_KEV_LIST else round(random.uniform(4.0, 9.0), 1)
        
        vuln = {
            "asset_ip": asset["ip_address"], "cve": cve, "cvss_score": cvss, "port": port,
            "protocol": "TCP", "status": "Open",
            "first_seen": fake.date_this_year().isoformat(), "last_seen": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        if random.random() < 0.5: tenable_vulns.append(vuln)
        else: wiz_vulns.append(vuln)
        vulnerable_assets.append((asset["ip_address"], port, asset["is_public"]))

    rule_counter = 1
    for ip, port, is_public in vulnerable_assets:
        rule_type = random.choice(["internet", "internal", "blocked"])
        if is_public and rule_type == "internet":
             firewall_rules.append({"rule_name": f"Allow-Internet-{rule_counter}", "source_address": "0.0.0.0/0", "dest_address": f"{ip}/32", "service_port": port, "protocol": "TCP", "action": "Allow", "policy_source": "edge-fw"})
        elif rule_type == "internal":
             firewall_rules.append({"rule_name": f"Allow-Internal-{rule_counter}", "source_address": "10.0.0.0/8", "dest_address": f"{ip}/32", "service_port": port, "protocol": "TCP", "action": "Allow", "policy_source": "core-fw"})
        rule_counter += 1

    return wiz_assets, vt_reports, tenable_vulns, wiz_vulns, firewall_rules

if __name__ == "__main__":
    DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
    if not os.path.exists(DATA_DIR): os.makedirs(DATA_DIR)
    
    assets = generate_assets()
    cisa_kev = generate_cisa_kev()
    wiz, vt, tenable, wiz_v, fw = generate_correlated_data(assets)

    pd.DataFrame(assets).to_csv(os.path.join(DATA_DIR, 'phpipam_assets.csv'), index=False)
    pd.DataFrame(cisa_kev).to_csv(os.path.join(DATA_DIR, 'cisa_kev.csv'), index=False)
    pd.DataFrame(wiz).to_csv(os.path.join(DATA_DIR, 'wiz_assets.csv'), index=False)
    pd.DataFrame(vt).to_csv(os.path.join(DATA_DIR, 'virustotal_reports.csv'), index=False)
    pd.DataFrame(tenable).to_csv(os.path.join(DATA_DIR, 'tenable_vulns.csv'), index=False)
    pd.DataFrame(wiz_v).to_csv(os.path.join(DATA_DIR, 'wiz_vulns.csv'), index=False)
    pd.DataFrame(fw).to_csv(os.path.join(DATA_DIR, 'paloalto_rules.csv'), index=False)

    print("Mock data (including CISA KEV) generated in /data.")