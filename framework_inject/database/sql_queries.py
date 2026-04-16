GET_FINDING = """
    SELECT id, asset_id, vulnerability_id, status, is_dismissed, scanner, resolved_at
    FROM findings
    WHERE id = %s
"""

COUNT_ACTIVE_FINDINGS = """
    SELECT COUNT(*) AS cnt
    FROM findings
    WHERE is_dismissed = FALSE
"""

GET_VULNERABILITIES_WITH_CVSS = """
    SELECT id, cve_id, cvss_score
    FROM vulnerabilities
    WHERE cvss_score IS NOT NULL
"""

GET_FINDINGS_WITH_NULL_REQUIRED_FIELDS = """
    SELECT id
    FROM findings
    WHERE asset_id IS NULL
       OR vulnerability_id IS NULL
       OR status IS NULL
"""

GET_DUPLICATE_CVE_IDS = """
    SELECT cve_id, COUNT(*) AS cnt
    FROM vulnerabilities
    GROUP BY cve_id
    HAVING COUNT(*) > 1
"""

GET_FINDINGS_WITH_INVALID_STATUS = """
    SELECT id, status
    FROM findings
    WHERE is_dismissed = FALSE
      AND status NOT IN %s
"""

GET_ORPHANED_FINDING_ASSETS = """
    SELECT f.id, f.asset_id
    FROM findings f
    LEFT JOIN assets a ON f.asset_id = a.id
    WHERE a.id IS NULL
"""

GET_ORPHANED_FINDING_VULNERABILITIES = """
    SELECT f.id, f.vulnerability_id
    FROM findings f
    LEFT JOIN vulnerabilities v ON f.vulnerability_id = v.id
    WHERE v.id IS NULL
"""
