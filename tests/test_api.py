import allure
import pytest
import requests
from http import HTTPStatus

from tests.constants import API, ASSET_ID, VULN_ID, VALID_STATUSES, NON_EXISTENT_ID, PER_PAGE_STANDARD


def _create(asset_id=ASSET_ID, vuln_id=VULN_ID, scanner="smoke"):
    return requests.post(f"{API}/findings", json={
        "asset_id": asset_id,
        "vulnerability_id": vuln_id,
        "scanner": scanner,
    })


def _dismiss(finding_id):
    requests.delete(f"{API}/findings/{finding_id}")


class TestFindingsCRUD:
    @allure.title("Create finding — 201 with correct initial state")
    @allure.severity(allure.severity_level.BLOCKER)
    def test_create_finding(self):
        with allure.step("POST /findings with valid asset_id and vulnerability_id"):
            resp = _create()
        with allure.step("Assert 201 and response structure"):
            assert resp.status_code == HTTPStatus.CREATED
            body = resp.json()
            assert body["asset_id"] == ASSET_ID
            assert body["vulnerability_id"] == VULN_ID
            assert body["status"] == "open"
            assert body["is_dismissed"] is False
            assert "id" in body
            assert "detected_at" in body
            assert body["resolved_at"] is None
        with allure.step("Cleanup"):
            _dismiss(body["id"])

    @allure.title("Read finding by ID — 200 with full payload")
    @allure.severity(allure.severity_level.BLOCKER)
    def test_read_finding_by_id(self):
        with allure.step("Create a finding"):
            finding_id = _create().json()["id"]
        with allure.step("GET /findings/{id}"):
            resp = requests.get(f"{API}/findings/{finding_id}")
        with allure.step("Assert 200 and all required fields present"):
            assert resp.status_code == HTTPStatus.OK
            body = resp.json()
            assert body["id"] == finding_id
            for field in ("status", "asset_id", "vulnerability_id", "is_dismissed", "detected_at"):
                assert field in body
        with allure.step("Cleanup"):
            _dismiss(finding_id)

    @allure.title("List findings — 200 with paginated structure")
    @allure.severity(allure.severity_level.CRITICAL)
    def test_list_findings(self):
        with allure.step("GET /findings"):
            resp = requests.get(f"{API}/findings")
        with allure.step("Assert 200 and pagination envelope"):
            assert resp.status_code == HTTPStatus.OK
            body = resp.json()
            for key in ("items", "total", "page", "per_page"):
                assert key in body
            assert isinstance(body["items"], list)
            assert body["total"] > 0

    @allure.title("Update finding status — 200 with updated status")
    @allure.severity(allure.severity_level.BLOCKER)
    def test_update_finding_status(self):
        with allure.step("Create a finding"):
            finding_id = _create().json()["id"]
        with allure.step("PUT /findings/{id}/status to 'confirmed'"):
            resp = requests.put(f"{API}/findings/{finding_id}/status", json={"status": "confirmed"})
        with allure.step("Assert 200 and status field reflects change"):
            assert resp.status_code == HTTPStatus.OK
            assert resp.json()["status"] == "confirmed"
        with allure.step("Cleanup"):
            _dismiss(finding_id)

    @allure.title("Dismiss finding — 204 No Content")
    @allure.severity(allure.severity_level.BLOCKER)
    def test_dismiss_finding(self):
        with allure.step("Create a finding"):
            finding_id = _create().json()["id"]
        with allure.step("DELETE /findings/{id}"):
            resp = requests.delete(f"{API}/findings/{finding_id}")
        with allure.step("Assert 204"):
            assert resp.status_code == HTTPStatus.NO_CONTENT


class TestErrorHandling:
    @allure.title("Create finding with non-existent asset_id — 400")
    @allure.severity(allure.severity_level.CRITICAL)
    def test_create_nonexistent_asset(self):
        with allure.step(f"POST /findings with asset_id={NON_EXISTENT_ID}"):
            resp = _create(asset_id=NON_EXISTENT_ID)
        with allure.step("Assert 400"):
            assert resp.status_code == HTTPStatus.BAD_REQUEST

    @allure.title("Create finding with non-existent vulnerability_id — 400")
    @allure.severity(allure.severity_level.CRITICAL)
    def test_create_nonexistent_vulnerability(self):
        with allure.step(f"POST /findings with vulnerability_id={NON_EXISTENT_ID}"):
            resp = _create(vuln_id=NON_EXISTENT_ID)
        with allure.step("Assert 400"):
            assert resp.status_code == HTTPStatus.BAD_REQUEST

    @allure.title("GET non-existent finding — 404")
    @allure.severity(allure.severity_level.CRITICAL)
    def test_get_nonexistent_finding(self):
        with allure.step(f"GET /findings/{NON_EXISTENT_ID}"):
            resp = requests.get(f"{API}/findings/{NON_EXISTENT_ID}")
        with allure.step("Assert 404"):
            assert resp.status_code == HTTPStatus.NOT_FOUND

    @allure.title("PUT status on non-existent finding — 404")
    @allure.severity(allure.severity_level.CRITICAL)
    def test_update_status_nonexistent_finding(self):
        with allure.step(f"PUT /findings/{NON_EXISTENT_ID}/status"):
            resp = requests.put(f"{API}/findings/{NON_EXISTENT_ID}/status", json={"status": "open"})
        with allure.step("Assert 404"):
            assert resp.status_code == HTTPStatus.NOT_FOUND

    @allure.title("DELETE non-existent finding — 404")
    @allure.severity(allure.severity_level.CRITICAL)
    def test_dismiss_nonexistent_finding(self):
        with allure.step(f"DELETE /findings/{NON_EXISTENT_ID}"):
            resp = requests.delete(f"{API}/findings/{NON_EXISTENT_ID}")
        with allure.step("Assert 404"):
            assert resp.status_code == HTTPStatus.NOT_FOUND

    @allure.title("PUT status with unknown status value — 400")
    @allure.severity(allure.severity_level.CRITICAL)
    def test_update_finding_unknown_status(self):
        with allure.step("Create a finding"):
            finding_id = _create().json()["id"]
        with allure.step("PUT status='invalid_value'"):
            resp = requests.put(f"{API}/findings/{finding_id}/status", json={"status": "invalid_value"})
        with allure.step("Assert 400"):
            assert resp.status_code == HTTPStatus.BAD_REQUEST
        with allure.step("Cleanup"):
            _dismiss(finding_id)

    @allure.title("PUT status on dismissed finding — 404")
    @allure.severity(allure.severity_level.CRITICAL)
    def test_update_status_on_dismissed_finding(self):
        with allure.step("Create then immediately dismiss a finding"):
            finding_id = _create().json()["id"]
            _dismiss(finding_id)
        with allure.step("PUT status on dismissed finding"):
            resp = requests.put(f"{API}/findings/{finding_id}/status", json={"status": "open"})
        with allure.step("Assert 404 — dismissed findings cannot be modified"):
            assert resp.status_code == HTTPStatus.NOT_FOUND


class TestEdgeCases:
    @allure.title("All valid status values are accepted — 200 each")
    @allure.severity(allure.severity_level.NORMAL)
    @pytest.mark.parametrize("status", VALID_STATUSES)
    def test_all_valid_statuses_accepted(self, status):
        with allure.step("Create a finding"):
            finding_id = _create().json()["id"]
        with allure.step(f"PUT status='{status}'"):
            resp = requests.put(f"{API}/findings/{finding_id}/status", json={"status": status})
        with allure.step("Assert 200 and status matches"):
            assert resp.status_code == HTTPStatus.OK
            assert resp.json()["status"] == status
        with allure.step("Cleanup"):
            _dismiss(finding_id)

    @allure.title("Resolving a finding sets resolved_at timestamp")
    @allure.severity(allure.severity_level.NORMAL)
    def test_resolved_finding_has_resolved_at(self):
        with allure.step("Create a finding"):
            finding_id = _create().json()["id"]
        with allure.step("PUT status='resolved'"):
            resp = requests.put(f"{API}/findings/{finding_id}/status", json={"status": "resolved"})
        with allure.step("Assert resolved_at is populated"):
            assert resp.status_code == HTTPStatus.OK
            assert resp.json()["resolved_at"] is not None
        with allure.step("Cleanup"):
            _dismiss(finding_id)

    @allure.title("New finding has resolved_at=null")
    @allure.severity(allure.severity_level.NORMAL)
    def test_new_finding_resolved_at_is_null(self):
        with allure.step("Create a finding"):
            body = _create().json()
        with allure.step("Assert resolved_at is null"):
            assert body["resolved_at"] is None
        with allure.step("Cleanup"):
            _dismiss(body["id"])

    @allure.title("Pagination: per_page=1 returns exactly one item")
    @allure.severity(allure.severity_level.NORMAL)
    def test_pagination_per_page_one(self):
        with allure.step("GET /findings?per_page=1"):
            resp = requests.get(f"{API}/findings?per_page=1")
        with allure.step("Assert 1 item and matching meta"):
            body = resp.json()
            assert len(body["items"]) == 1
            assert body["per_page"] == 1
            assert body["page"] == 1

    @allure.title("Filter status=open returns only open findings")
    @allure.severity(allure.severity_level.NORMAL)
    def test_filter_by_status_returns_only_matching(self):
        with allure.step(f"GET /findings?status=open&per_page={PER_PAGE_STANDARD}"):
            resp = requests.get(f"{API}/findings?status=open&per_page={PER_PAGE_STANDARD}")
        with allure.step("Assert every returned item has status=open"):
            assert resp.status_code == HTTPStatus.OK
            for item in resp.json()["items"]:
                assert item["status"] == "open"

    @allure.title("[BUG-2] Status transition backwards (resolved → open) is accepted — should be 400")
    @allure.severity(allure.severity_level.CRITICAL)
    @allure.description(
        "Title: No status transition validation — any status → any status accepted\n"
        "Severity: High\n\n"
        "Steps to reproduce:\n"
        "1. Create a finding\n"
        "2. PUT status='resolved'\n"
        "3. PUT status='open'\n\n"
        "Expected: 400 — backwards transition should be rejected\n"
        "Actual: 200 OK. findings.py:152 assigns status with no workflow guard."
    )
    def test_backwards_status_transition_rejected(self):
        with allure.step("Create a finding"):
            finding_id = _create().json()["id"]
        with allure.step("Set status to 'resolved'"):
            r = requests.put(f"{API}/findings/{finding_id}/status", json={"status": "resolved"})
            assert r.status_code == HTTPStatus.OK
        with allure.step("Attempt backwards transition resolved → open"):
            r = requests.put(f"{API}/findings/{finding_id}/status", json={"status": "open"})
            assert r.status_code == HTTPStatus.BAD_REQUEST, (
                f"BUG-2: Expected 400 for resolved → open, got {r.status_code}."
            )
        with allure.step("Cleanup"):
            requests.put(f"{API}/findings/{finding_id}/status", json={"status": "open"})
            _dismiss(finding_id)


class TestSearchEndpoint:
    @allure.title("Search with empty query returns empty list")
    @allure.severity(allure.severity_level.NORMAL)
    def test_search_empty_query(self):
        with allure.step("GET /findings/search?q="):
            resp = requests.get(f"{API}/findings/search", params={"q": ""})
        with allure.step("Assert 200 with empty list"):
            assert resp.status_code == HTTPStatus.OK
            assert resp.json() == []

    @allure.title("Search by CVE prefix returns matching results")
    @allure.severity(allure.severity_level.NORMAL)
    def test_search_by_cve_prefix(self):
        with allure.step("GET /findings/search?q=CVE"):
            resp = requests.get(f"{API}/findings/search", params={"q": "CVE"})
        with allure.step("Assert 200 and non-empty list"):
            assert resp.status_code == HTTPStatus.OK
            results = resp.json()
            assert isinstance(results, list)
            assert len(results) > 0

    @allure.title("Search result items contain expected fields")
    @allure.severity(allure.severity_level.NORMAL)
    def test_search_result_structure(self):
        with allure.step("GET /findings/search?q=CVE"):
            resp = requests.get(f"{API}/findings/search", params={"q": "CVE"})
        with allure.step("Assert each item has required fields"):
            assert resp.status_code == HTTPStatus.OK
            for item in resp.json():
                for field in ("finding_id", "status", "cve_id", "severity", "hostname"):
                    assert field in item

    @allure.title("[BUG-3] SQL injection in /findings/search?q= returns all records")
    @allure.severity(allure.severity_level.BLOCKER)
    @allure.description(
        "Title: SQL injection vulnerability in findings search endpoint\n"
        "Severity: Critical\n\n"
        "Steps to reproduce:\n"
        "1. GET /findings/search?q=' OR '1'='1\n\n"
        "Expected: 0 results — payload should not match any CVE/hostname\n"
        "Actual: Returns all findings rows. findings.py:52 interpolates 'q' "
        "directly into a raw SQL f-string instead of using parameterized queries."
    )
    def test_search_sql_injection(self):
        with allure.step("Send injection payload: ' OR '1'='1"):
            resp = requests.get(f"{API}/findings/search", params={"q": "' OR '1'='1"})
        with allure.step("Assert payload does not return all records"):
            assert resp.status_code != HTTPStatus.OK or len(resp.json()) == 0, (
                f"BUG-3: SQL injection returned {len(resp.json())} records. "
                "f-string used in raw SQL query at findings.py:52."
            )
