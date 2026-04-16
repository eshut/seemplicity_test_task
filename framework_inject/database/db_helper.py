from framework_inject.database import sql_queries
from framework_inject.services.sql_service import SQL


class DBHelper:
    def __init__(self, sql: SQL):
        self._sql = sql

    def get_finding(self, finding_id) -> dict:
        result = self._sql.run_script(sql_queries.GET_FINDING, args=(finding_id,))
        return result[0] if result else None

    def count_active_findings(self) -> int:
        result = self._sql.run_script(sql_queries.COUNT_ACTIVE_FINDINGS)
        return result[0]["cnt"] if result else 0

    def get_vulnerabilities_with_cvss(self) -> list:
        return self._sql.run_script(sql_queries.GET_VULNERABILITIES_WITH_CVSS)

    def get_findings_with_null_required_fields(self) -> list:
        return self._sql.run_script(sql_queries.GET_FINDINGS_WITH_NULL_REQUIRED_FIELDS)

    def get_duplicate_cve_ids(self) -> list:
        return self._sql.run_script(sql_queries.GET_DUPLICATE_CVE_IDS)

    def get_findings_with_invalid_status(self, valid_statuses: tuple) -> list:
        return self._sql.run_script(sql_queries.GET_FINDINGS_WITH_INVALID_STATUS, args=(valid_statuses,))

    def get_orphaned_finding_assets(self) -> list:
        return self._sql.run_script(sql_queries.GET_ORPHANED_FINDING_ASSETS)

    def get_orphaned_finding_vulnerabilities(self) -> list:
        return self._sql.run_script(sql_queries.GET_ORPHANED_FINDING_VULNERABILITIES)
