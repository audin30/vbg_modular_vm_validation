/*
This script deletes all existing tables and rebuilds the schema from scratch.
All data will be lost.
*/

-- Drop tables in reverse order of dependency
DROP TABLE IF EXISTS nmap_scan_results CASCADE;
DROP TABLE IF EXISTS firewall_rules CASCADE;
DROP TABLE IF EXISTS vulnerabilities CASCADE;
DROP TABLE IF EXISTS assets CASCADE;
DROP TABLE IF EXISTS cisa_kev CASCADE; -- NEW

/* ===================================================
Table 1: assets
Your central inventory. The single source of truth for all assets.
===================================================
*/
CREATE TABLE assets (
    asset_id UUID PRIMARY KEY,
    ip_address INET UNIQUE NOT NULL,
    hostname TEXT,
    environment TEXT,
    description TEXT,
    owner TEXT,
    os TEXT,
    is_public BOOLEAN DEFAULT false,
    vt_ip_score INTEGER,
    vt_domain_score INTEGER,
    last_seen_phpipam TIMESTAMPTZ,
    last_seen_wiz TIMESTAMPTZ,
    last_seen_tenable TIMESTAMPTZ
);

CREATE INDEX idx_assets_ip ON assets USING GIST (ip_address inet_ops);
CREATE INDEX idx_assets_hostname ON assets (hostname);

/* ===================================================
Table 2: vulnerabilities
A record of all open vulnerabilities on your assets.
===================================================
*/
CREATE TABLE vulnerabilities (
    vuln_id UUID PRIMARY KEY,
    asset_id UUID NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    cve VARCHAR(20),
    cvss_score FLOAT,
    port INTEGER,
    protocol VARCHAR(10),
    status TEXT,
    source TEXT,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ
);

CREATE INDEX idx_vuln_asset_id ON vulnerabilities (asset_id);
CREATE INDEX idx_vuln_cve ON vulnerabilities (cve);
CREATE INDEX idx_vuln_cvss_score ON vulnerabilities (cvss_score);
CREATE UNIQUE INDEX idx_vuln_unique_combo ON vulnerabilities (asset_id, cve, port);

/* ===================================================
NEW TABLE: cisa_kev
Catalog of Known Exploited Vulnerabilities.
===================================================
*/
CREATE TABLE cisa_kev (
    cve_id VARCHAR(20) PRIMARY KEY,
    vendor_project TEXT,
    product TEXT,
    vulnerability_name TEXT,
    date_added DATE,
    short_description TEXT,
    required_action TEXT,
    due_date DATE
);
-- No indexes needed besides PRIMARY KEY for this lookup table

/* ===================================================
Table 4: firewall_rules
All 'allow' rules from your firewall.
===================================================
*/
CREATE TABLE firewall_rules (
    rule_id UUID PRIMARY KEY,
    rule_name TEXT,
    source_address CIDR[],
    dest_address CIDR[],
    service_port INTEGER,
    protocol VARCHAR(10),
    action VARCHAR(10),
    policy_source TEXT
);

CREATE INDEX idx_fw_dest_address ON firewall_rules USING GIN (dest_address);
CREATE INDEX idx_fw_source_address ON firewall_rules USING GIN (source_address);

/* ===================================================
Table 5: nmap_scan_results
Ground-truth scan data for specific IP:Port combinations
===================================================
*/
CREATE TABLE nmap_scan_results (
    scan_id UUID PRIMARY KEY,
    asset_id UUID NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    ip_address INET NOT NULL,
    port INTEGER NOT NULL,
    protocol VARCHAR(10) NOT NULL,
    status TEXT NOT NULL,
    service_name TEXT,
    service_banner TEXT,
    scan_timestamp TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_nmap_asset_id ON nmap_scan_results (asset_id);
CREATE UNIQUE INDEX idx_nmap_unique_scan ON nmap_scan_results (asset_id, port, protocol);