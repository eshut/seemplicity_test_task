import allure

from framework_inject.pages.qa_dashboard.pages.dashboard_page import DashboardPage


class TestDashboardSmoke:
    @allure.title("Dashboard loads at / with findings data visible")
    @allure.severity(allure.severity_level.BLOCKER)
    def test_dashboard_loads_with_findings(self, dashboard: DashboardPage):
        with allure.step("Navigate to http://localhost:8000/"):
            dashboard.open()

        with allure.step("Verify page title is 'Vulnerability Dashboard'"):
            assert dashboard.page.title() == "Vulnerability Dashboard"

        with allure.step("Verify findings table contains at least one data row"):
            rows = dashboard.get_findings_rows()
            assert len(rows) > 0, "No findings rows rendered — dashboard may have failed to load data"

        with allure.step("Verify summary cards show numeric counts"):
            for card_id in ("total-count", "critical-count", "high-count", "medium-count", "low-count"):
                value = dashboard.get_card_value(card_id)
                assert value is not None and value.isdigit(), (
                    f"Card #{card_id} shows '{value}' — expected a numeric count"
                )

    @allure.title("[BUG-8] Change finding status via UI dropdown — change not reflected in table")
    @allure.severity(allure.severity_level.NORMAL)
    @allure.description(
        "Title: Status badge not updated after inline status change\n"
        "Severity: Medium\n\n"
        "Steps to reproduce:\n"
        "1. Open http://localhost:8000/\n"
        "2. Select 'In Progress' from the status dropdown of the first finding\n"
        "3. Observe the status badge in that row\n\n"
        "Expected: Status badge updates to 'in progress' immediately\n"
        "Actual: Badge retains previous value. app.js updateStatus() does not call "
        "loadFindings() after a successful PUT, so the table is never re-rendered."
    )
    def test_status_change_reflected_in_table(self, dashboard: DashboardPage):
        with allure.step("Reset filters and wait for findings to render"):
            dashboard.reset_filters()
            dashboard.page.wait_for_timeout(500)

        with allure.step("Read current status badge text of the first row"):
            status_badge = dashboard.page.locator(
                "#findings-table tr:has(.text-muted) td:nth-child(7) .status"
            ).first
            status_before = status_badge.inner_text().strip()

        with allure.step("Select 'In Progress' from the inline status dropdown"):
            dashboard.change_first_finding_status("in_progress")

        with allure.step("Assert status badge now shows 'in progress'"):
            status_after = status_badge.inner_text().strip()
            assert status_after.lower().replace(" ", "_") == "in_progress", (
                f"BUG-8: Badge still shows '{status_after}' (was '{status_before}'). "
                "Table is not re-rendered after a successful status update."
            )
