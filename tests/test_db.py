import allure
import requests
from http import HTTPStatus

from tests.constants import API, ASSET_ID, VULN_ID


def _create():
    resp = requests.post(f"{API}/findings", json={
        "asset_id": ASSET_ID,
        "vulnerability_id": VULN_ID,
        "scanner": "db-test",
    })
    assert resp.status_code == HTTPStatus.CREATED
    return resp.json()["id"]


class TestDataIntegrityAfterAPIOperations:
    @allure.title("Dismiss finding via API → DB row has is_dismissed=TRUE")
    @allure.severity(allure.severity_level.BLOCKER)
    @allure.description(
        "Title: Dismissed finding remains accessible by direct ID\n"
        "Severity: High\n\n"
        "Steps to reproduce:\n"
        "1. POST /findings to create a new finding\n"
        "2. DELETE /findings/{id} to dismiss it\n"
        "3. GET /findings/{id}\n\n"
        "Expected: 404 Not Found — dismissed findings should not be accessible\n"
        "Actual: 200 OK with full finding payload. "
        "findings.py:79 queries without is_dismissed filter."
    )
    def test_dismiss_sets_is_dismissed_in_db(self, db):
        with allure.step("Create a finding via API"):
            finding_id = _create()

        with allure.step("Dismiss it via DELETE /findings/{id}"):
            resp = requests.delete(f"{API}/findings/{finding_id}")
            assert resp.status_code == HTTPStatus.NO_CONTENT

        with allure.step("Query DB directly for is_dismissed"):
            row = db.get_finding(finding_id)

        with allure.step("Assert is_dismissed is TRUE in DB"):
            assert row is not None
            assert row["is_dismissed"] is True

        with allure.step("[BUG-1] Verify API returns 404 for dismissed finding"):
            get_resp = requests.get(f"{API}/findings/{finding_id}")
            assert get_resp.status_code == HTTPStatus.NOT_FOUND, (
                f"BUG-1: GET /findings/{finding_id} returned {get_resp.status_code} "
                "instead of 404 for a dismissed finding."
            )

    @allure.title("Create finding via API → DB row matches all response fields")
    @allure.severity(allure.severity_level.BLOCKER)
    def test_create_finding_persisted_correctly(self, db):
        with allure.step("Create a finding via API"):
            finding_id = _create()

        with allure.step("Query DB for the new finding row"):
            row = db.get_finding(finding_id)

        with allure.step("Assert DB row matches expected initial state"):
            assert row is not None
            assert row["id"] == finding_id
            assert row["asset_id"] == ASSET_ID
            assert row["vulnerability_id"] == VULN_ID
            assert row["status"] == "open"
            assert row["is_dismissed"] is False
            assert row["scanner"] == "db-test"

        with allure.step("Cleanup"):
            requests.delete(f"{API}/findings/{finding_id}")

    @allure.title("Update status to 'resolved' via API → DB has correct status and resolved_at")
    @allure.severity(allure.severity_level.CRITICAL)
    def test_status_update_persisted_with_resolved_at(self, db):
        with allure.step("Create a finding"):
            finding_id = _create()

        with allure.step("PUT status='resolved'"):
            resp = requests.put(
                f"{API}/findings/{finding_id}/status",
                json={"status": "resolved"},
            )
            assert resp.status_code == HTTPStatus.OK

        with allure.step("Assert status and resolved_at in DB"):
            row = db.get_finding(finding_id)
            assert row["status"] == "resolved"
            assert row["resolved_at"] is not None

        with allure.step("Cleanup"):
            requests.delete(f"{API}/findings/{finding_id}")

    @allure.title("Unresolved status update clears resolved_at in DB")
    @allure.severity(allure.severity_level.NORMAL)
    def test_non_resolved_status_clears_resolved_at(self, db):
        with allure.step("Create a finding and set it to 'resolved'"):
            finding_id = _create()
            requests.put(f"{API}/findings/{finding_id}/status", json={"status": "resolved"})

        with allure.step("Change status to 'confirmed'"):
            resp = requests.put(
                f"{API}/findings/{finding_id}/status",
                json={"status": "confirmed"},
            )
            assert resp.status_code == HTTPStatus.OK

        with allure.step("Assert resolved_at is null in DB"):
            row = db.get_finding(finding_id)
            assert row["resolved_at"] is None

        with allure.step("Cleanup"):
            requests.delete(f"{API}/findings/{finding_id}")


class TestDatabaseConstraints:
    @allure.title("All vulnerabilities have cvss_score in range 0.0–10.0")
    @allure.severity(allure.severity_level.CRITICAL)
    def test_cvss_score_range(self, db):
        with allure.step("Query all vulnerabilities with non-null cvss_score"):
            rows = db.get_vulnerabilities_with_cvss()

        with allure.step("Assert each cvss_score is between 0.0 and 10.0"):
            violations = [r for r in rows if not (0.0 <= r["cvss_score"] <= 10.0)]
            assert not violations, (
                f"cvss_score out of range in {len(violations)} row(s): "
                + ", ".join(f"{r['cve_id']}={r['cvss_score']}" for r in violations)
            )

    @allure.title("All findings have non-null required fields (asset_id, vulnerability_id, status)")
    @allure.severity(allure.severity_level.CRITICAL)
    def test_findings_required_fields_not_null(self, db):
        with allure.step("Query findings where any required field is null"):
            violations = db.get_findings_with_null_required_fields()

        with allure.step("Assert no null required fields"):
            assert not violations, (
                f"Found {len(violations)} finding(s) with null required fields."
            )

    @allure.title("Vulnerabilities table has no duplicate cve_id values")
    @allure.severity(allure.severity_level.CRITICAL)
    def test_no_duplicate_cve_ids(self, db):
        with allure.step("Query for duplicated cve_id values"):
            duplicates = db.get_duplicate_cve_ids()

        with allure.step("Assert no duplicates"):
            assert not duplicates, (
                f"Duplicate cve_id found: {[r['cve_id'] for r in duplicates]}"
            )

    @allure.title("All non-dismissed findings have a recognised status value")
    @allure.severity(allure.severity_level.NORMAL)
    def test_findings_status_values_are_valid(self, db):
        valid = ("open", "confirmed", "in_progress", "resolved", "false_positive")
        with allure.step("Query findings with unrecognised status"):
            violations = db.get_findings_with_invalid_status(valid)

        with allure.step("Assert all statuses are in the allowed set"):
            assert not violations, (
                f"Unexpected status values: {[(r['id'], r['status']) for r in violations]}"
            )


class TestCrossTableConsistency:
    @allure.title("All finding.asset_id values reference an existing asset row")
    @allure.severity(allure.severity_level.CRITICAL)
    def test_finding_asset_fk_consistency(self, db):
        with allure.step("Find findings whose asset_id has no matching asset"):
            orphans = db.get_orphaned_finding_assets()

        with allure.step("Assert no orphaned asset references"):
            assert not orphans, (
                f"Findings with missing asset: {[(r['id'], r['asset_id']) for r in orphans]}"
            )

    @allure.title("All finding.vulnerability_id values reference an existing vulnerability row")
    @allure.severity(allure.severity_level.CRITICAL)
    def test_finding_vulnerability_fk_consistency(self, db):
        with allure.step("Find findings whose vulnerability_id has no matching vulnerability"):
            orphans = db.get_orphaned_finding_vulnerabilities()

        with allure.step("Assert no orphaned vulnerability references"):
            assert not orphans, (
                f"Findings with missing vulnerability: "
                f"{[(r['id'], r['vulnerability_id']) for r in orphans]}"
            )

    @allure.title("Dismissed findings are not counted in active finding totals")
    @allure.severity(allure.severity_level.NORMAL)
    def test_dismissed_findings_excluded_from_active_count(self, db):
        with allure.step("Count active findings from DB (is_dismissed=FALSE)"):
            db_active = db.count_active_findings()

        with allure.step("Count total from API /findings"):
            api_total = requests.get(f"{API}/findings?per_page=1").json()["total"]

        with allure.step("Assert DB active count matches API total"):
            assert db_active == api_total, (
                f"DB active count ({db_active}) != API total ({api_total}). "
                "Dismissed findings may be leaking into the API response."
            )
