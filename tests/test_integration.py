import allure
import requests
from http import HTTPStatus

from tests.constants import API, SCANNER_API, ASSET_ID, VULN_ID


class TestScannerToDashboard:
    @allure.title("Scan via Scanner Service → findings appear in Dashboard API")
    @allure.severity(allure.severity_level.BLOCKER)
    def test_scan_creates_findings_visible_in_dashboard(self):
        with allure.step("Record current findings total in Dashboard API"):
            before = requests.get(f"{API}/findings?per_page=1").json()["total"]

        with allure.step("POST /scans to Scanner Service"):
            resp = requests.post(f"{SCANNER_API}/scans", json={
                "asset_id": ASSET_ID,
                "vulnerability_ids": [VULN_ID],
                "scanner_name": "integration-test",
            })
            assert resp.status_code == HTTPStatus.CREATED
            scan = resp.json()
            assert scan["status"] == "completed"
            assert scan["findings_count"] >= 1

        with allure.step("GET /findings from Dashboard API and verify count increased"):
            after = requests.get(f"{API}/findings?per_page=1").json()["total"]
            assert after > before, (
                f"Expected findings total to grow after scan. Before: {before}, after: {after}."
            )

    @allure.title("Scan result fields are consistent between Scanner and Dashboard responses")
    @allure.severity(allure.severity_level.CRITICAL)
    def test_scan_finding_fields_consistent(self):
        with allure.step("Run a scan via Scanner Service"):
            scan_resp = requests.post(f"{SCANNER_API}/scans", json={
                "asset_id": ASSET_ID,
                "vulnerability_ids": [VULN_ID],
                "scanner_name": "integration-check",
            })
            assert scan_resp.status_code == HTTPStatus.CREATED

        with allure.step("Find the newest finding in Dashboard API for this asset"):
            findings_resp = requests.get(f"{API}/findings?per_page=50")
            assert findings_resp.status_code == HTTPStatus.OK
            matching = [
                f for f in findings_resp.json()["items"]
                if f["asset_id"] == ASSET_ID and f["vulnerability_id"] == VULN_ID
            ]
            assert matching, "No matching finding found in Dashboard API after scan"
            finding = matching[0]

        with allure.step("Assert finding has expected initial state"):
            assert finding["status"] == "open"
            assert finding["is_dismissed"] is False


class TestStatusUpdateConsistency:
    @allure.title("Update finding status via API → DB state matches response")
    @allure.severity(allure.severity_level.BLOCKER)
    def test_status_update_db_matches_api_response(self, db):
        with allure.step("Create a finding via Dashboard API"):
            create_resp = requests.post(f"{API}/findings", json={
                "asset_id": ASSET_ID,
                "vulnerability_id": VULN_ID,
                "scanner": "integration-status",
            })
            assert create_resp.status_code == HTTPStatus.CREATED
            finding_id = create_resp.json()["id"]

        with allure.step("PUT status='confirmed'"):
            update_resp = requests.put(
                f"{API}/findings/{finding_id}/status",
                json={"status": "confirmed"},
            )
            assert update_resp.status_code == HTTPStatus.OK

        with allure.step("Query DB for current status"):
            db_row = db.get_finding(finding_id)

        with allure.step("Assert DB status matches API response"):
            assert db_row["status"] == "confirmed"
            assert update_resp.json()["status"] == "confirmed"

        with allure.step("Cleanup"):
            requests.delete(f"{API}/findings/{finding_id}")

    @allure.title("Resolving a finding sets resolved_at in both API response and DB")
    @allure.severity(allure.severity_level.CRITICAL)
    def test_resolved_at_set_in_api_and_db(self, db):
        with allure.step("Create a finding"):
            finding_id = requests.post(f"{API}/findings", json={
                "asset_id": ASSET_ID,
                "vulnerability_id": VULN_ID,
                "scanner": "integration-resolve",
            }).json()["id"]

        with allure.step("PUT status='resolved'"):
            update_resp = requests.put(
                f"{API}/findings/{finding_id}/status",
                json={"status": "resolved"},
            )
            assert update_resp.status_code == HTTPStatus.OK

        with allure.step("Assert resolved_at is non-null in API response"):
            assert update_resp.json()["resolved_at"] is not None

        with allure.step("Assert resolved_at is non-null in DB"):
            assert db.get_finding(finding_id)["resolved_at"] is not None

        with allure.step("Cleanup"):
            requests.delete(f"{API}/findings/{finding_id}")


class TestDuplicateScanHandling:
    @allure.title("[BUG-7] Running the same scan twice creates duplicate findings")
    @allure.severity(allure.severity_level.CRITICAL)
    @allure.description(
        "Title: No deduplication when creating findings via scan\n"
        "Severity: High\n\n"
        "Steps to reproduce:\n"
        "1. POST /scans with asset_id=1, vulnerability_ids=[1]\n"
        "2. POST /scans with the same payload\n"
        "3. GET /findings and compare total count\n\n"
        "Expected: Total grows by at most 1 across both scans\n"
        "Actual: Each scan inserts a new Finding row unconditionally. "
        "scans.py:65 has no existing-finding check and no unique DB constraint."
    )
    def test_rescan_does_not_create_duplicate_findings(self):
        with allure.step("Record current findings total"):
            before = requests.get(f"{API}/findings?per_page=1").json()["total"]

        payload = {
            "asset_id": ASSET_ID,
            "vulnerability_ids": [VULN_ID],
            "scanner_name": "dup-check",
        }

        with allure.step("POST first scan"):
            r1 = requests.post(f"{SCANNER_API}/scans", json=payload)
            assert r1.status_code == HTTPStatus.CREATED

        with allure.step("POST second identical scan"):
            r2 = requests.post(f"{SCANNER_API}/scans", json=payload)
            assert r2.status_code == HTTPStatus.CREATED

        with allure.step("Assert total grew by at most 1"):
            after = requests.get(f"{API}/findings?per_page=1").json()["total"]
            added = after - before
            assert added <= 1, (
                f"BUG-7: Two identical scans created {added} new findings. "
                "Expected at most 1 — scans.py has no duplicate check."
            )

    @allure.title("[BUG-6] Asset list pagination skips first asset (off-by-one in offset)")
    @allure.severity(allure.severity_level.NORMAL)
    @allure.description(
        "Title: GET /assets page 1 skips the first asset\n"
        "Severity: Medium\n\n"
        "Steps to reproduce:\n"
        "1. GET /assets?per_page=100 (all assets)\n"
        "2. GET /assets?page=1&per_page=100\n"
        "3. Compare first item IDs\n\n"
        "Expected: Both responses return the same first asset\n"
        "Actual: Paginated response skips asset with the lowest ID. "
        "assets.py:29 uses offset=(page-1)*per_page+1 instead of (page-1)*per_page."
    )
    def test_asset_list_page1_includes_first_asset(self):
        with allure.step("GET first asset directly by ID"):
            first_asset = requests.get(f"{SCANNER_API}/assets/1")
            assert first_asset.status_code == HTTPStatus.OK
            expected_id = first_asset.json()["id"]

        with allure.step("GET /assets?page=1&per_page=50"):
            page_resp = requests.get(f"{SCANNER_API}/assets?page=1&per_page=50")
            assert page_resp.status_code == HTTPStatus.OK
            items = page_resp.json()["items"]
            assert items, "No assets returned on page 1"

        with allure.step("Assert first asset is present on page 1"):
            returned_ids = [a["id"] for a in items]
            assert expected_id in returned_ids, (
                f"BUG-6: Asset #{expected_id} is missing from page 1. "
                f"Returned IDs: {returned_ids}. Off-by-one in offset calculation."
            )
