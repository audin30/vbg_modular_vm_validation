/*
This script deletes all existing tables and rebuilds the schema from scratch.
All data will be lost.
*/

-- Drop tables in reverse order of dependency
DROP TABLE IF EXISTS nmap_scan_results CASCADE;
DROP TABLE IF EXISTS firewall_rules CASCADE;
DROP TABLE IF EXISTS vulnerabilities CASCADE;
DROP TABLE IF EXISTS assets CASCADE;

/* ===================================================
Table 1: assets
Your central inventory. The single source of truth for all assets.
===================================================
*/
CREATE TABLE assets (
    -- Core Identifiers
    asset_id UUID PRIMARY KEY,
    ip_address INET UNIQUE NOT NULL, -- INET type is optimized for IP addresses
    hostname TEXT,
    
    -- Business Context (from phpIPAM, Wiz)
    environment TEXT, -- 'Production', 'Staging', 'Dev'
    description TEXT,
    owner TEXT,
    os TEXT,
    
    -- Cloud/Exposure Context (from Wiz)
    is_public BOOLEAN DEFAULT false,
    
    -- Threat Intel Context (from VirusTotal)
    vt_ip_score INTEGER,
    vt_domain_score INTEGER,

    -- Data Timestamps
    last_seen_phpipam TIMESTAMPTZ,
    last_seen_wiz TIMESTAMPTZ,
    last_seen_tenable TIMESTAMPTZ
);

-- Create indexes for faster searching
CREATE INDEX idx_assets_ip ON assets USING GIST (ip_address inet_ops); -- GIST index for IP addresses
CREATE INDEX idx_assets_hostname ON assets (hostname);
CREATE INDEX idx_assets_environment ON assets (environment);

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
    status TEXT, -- 'Open', 'Fixed'
    source TEXT, -- 'Tenable', 'Wiz'
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ
);

-- Create indexes for faster searching
CREATE INDEX idx_vuln_asset_id ON vulnerabilities (asset_id);
CREATE INDEX idx_vuln_cve ON vulnerabilities (cve);
CREATE INDEX idx_vuln_cvss_score ON vulnerabilities (cvss_score);

-- --- THIS IS THE FIX ---
-- Add a unique constraint for the ON CONFLICT logic
CREATE UNIQUE INDEX idx_vuln_unique_combo ON vulnerabilities (asset_id, cve, port);
-- ---------------------

/* ===================================================
Table 3: firewall_rules
All 'allow' rules from your firewall.
===================================================
*/
CREATE TABLE firewall_rules (
    rule_id UUID PRIMARY KEY,
    rule_name TEXT,
    source_address CIDR[], -- CIDR array (e.g., '{ "10.0.0.0/8", "192.168.1.0/24" }')
    dest_address CIDR[], -- CIDR array
    service_port INTEGER,
    protocol VARCHAR(10),
    action VARCHAR(10),
    policy_source TEXT
);

-- Create GIN indexes for fast array lookups (e.g., "does this array contain this IP?")
CREATE INDEX idx_fw_dest_address ON firewall_rules USING GIN (dest_address);
CREATE INDEX idx_fw_source_address ON firewall_rules USING GIN (source_address);
CREATE INDEX idx_fw_service_port ON firewall_rules (service_port);

/* ===================================================
Table 4: nmap_scan_results
Ground-truth scan data for specific IP:Port combinations
===================================================
*/
CREATE TABLE nmap_scan_results (
    scan_id UUID PRIMARY KEY,
    asset_id UUID NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    ip_address INET NOT NULL,
    port INTEGER NOT NULL,
    protocol VARCHAR(10) NOT NULL,
    status TEXT NOT NULL, -- 'open', 'closed', 'filtered'
    service_name TEXT, -- 'ssh', 'http'
    service_banner TEXT, -- 'OpenSSH 8.2p1', 'Apache/2.4.41'
    scan_timestamp TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_nmap_asset_id ON nmap_scan_results (asset_id);
-- Create a unique constraint to prevent duplicate scan results for the same port
CREATE UNIQUE INDEX idx_nmap_unique_scan ON nmap_scan_results (asset_id, port, protocol);