CREATE OR REPLACE VIEW correlated_vulnerability_risk AS
SELECT
    v.vuln_id,
    a.asset_id,
    a.ip_address,
    a.hostname,
    a.environment,
    a.owner,
    a.is_public,
    v.cve,
    v.cvss_score,
    v.port AS vuln_port,
    v.protocol,
    a.vt_ip_score,
    a.vt_domain_score,
    a.gn_classification, -- Includes GreyNoise field (assuming schema is updated)
    
    -- (1) CISA KEV CORRELATION: Check if the CVE is known exploited
    CASE WHEN k.cve_id IS NOT NULL THEN TRUE ELSE FALSE END AS is_cisa_kev,
    k.kev_link, -- <-- NEW FIELD: Pulls the direct link for the frontend
    
    -- (2) LIVE NMAP STATUS: Status from the latest scan
    n.status AS nmap_port_status,
    n.service_banner,
    
    -- (3) FIREWALL EXPOSURE: Check for an Allow rule from the Internet (0.0.0.0/0)
    EXISTS (
        SELECT 1
        FROM firewall_rules fr
        WHERE
            fr.action = 'Allow'
            -- Checks if the rule covers the specific port or is a generic 'any' port (0)
            AND (fr.service_port = v.port OR fr.service_port = 0)
            -- Checks if the source address array contains the Internet CIDR
            AND '0.0.0.0/0' = ANY(fr.source_address)
            -- Checks if the asset's IP is contained within the rule's destination CIDR array
            AND a.ip_address <<= ANY(fr.dest_address) 
    ) AS is_internet_exposed_via_fw
FROM
    vulnerabilities v
JOIN
    assets a ON v.asset_id = a.asset_id
LEFT JOIN
    nmap_scan_results n ON a.asset_id = n.asset_id AND v.port = n.port AND v.protocol = n.protocol
LEFT JOIN
    cisa_kev k ON v.cve = k.cve_id
WHERE
    v.status = 'Open' AND v.cvss_score >= 4.0 
ORDER BY 
    is_cisa_kev DESC, v.cvss_score DESC;