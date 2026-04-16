from framework_inject.pages.qa_dashboard.pages.dashboard_page import DashboardPage


class TestPageLoads:
    def test_page_title(self, dashboard: DashboardPage):
        assert dashboard.page.title() == "Vulnerability Dashboard"

    def test_summary_cards_present(self, dashboard: DashboardPage):
        for card_id in ("total-count", "critical-count", "high-count", "medium-count", "low-count"):
            assert dashboard.get_element(f"#{card_id}") is not None

    def test_findings_table_present(self, dashboard: DashboardPage):
        assert dashboard.get_element("#findings-table") is not None

    def test_assets_table_present(self, dashboard: DashboardPage):
        assert dashboard.get_element("#assets-table") is not None


class TestSummaryCards:
    def test_card_values_are_numeric(self, dashboard: DashboardPage):
        for card_id in ("total-count", "critical-count", "high-count", "medium-count", "low-count"):
            value = dashboard.get_card_value(card_id)
            assert value is not None and value != "-"
            assert value.isdigit()

    def test_active_findings_greater_than_zero(self, dashboard: DashboardPage):
        assert int(dashboard.get_card_value("total-count")) > 0

    def test_last_updated_populated(self, dashboard: DashboardPage):
        text = dashboard.get_element_text("#last-updated")
        assert text and "Updated:" in text


class TestFindingsTable:
    def test_findings_table_has_data(self, dashboard: DashboardPage):
        assert len(dashboard.get_findings_rows()) > 0

    def test_filter_by_severity_critical(self, dashboard: DashboardPage):
        dashboard.filter_by_severity("critical")
        assert len(dashboard.get_findings_rows()) > 0
        dashboard.reset_filters()

    def test_filter_by_severity_high(self, dashboard: DashboardPage):
        dashboard.filter_by_severity("high")
        assert len(dashboard.get_findings_rows()) > 0
        dashboard.reset_filters()

    def test_filter_by_status_open(self, dashboard: DashboardPage):
        dashboard.filter_by_status("open")
        assert len(dashboard.get_findings_rows()) > 0
        dashboard.reset_filters()

    def test_filter_by_status_resolved(self, dashboard: DashboardPage):
        dashboard.filter_by_status("resolved")
        assert len(dashboard.get_findings_rows()) > 0
        dashboard.reset_filters()

    def test_combined_severity_and_status_filter(self, dashboard: DashboardPage):
        dashboard.filter_by_severity("critical")
        dashboard.filter_by_status("confirmed")
        assert len(dashboard.get_findings_rows()) > 0
        dashboard.reset_filters()

    def test_status_update_shows_success_message(self, dashboard: DashboardPage):
        dashboard.reset_filters()
        message = dashboard.change_first_finding_status("confirmed")
        assert message is not None and len(message) > 0
        assert "error" not in message.lower()
        dashboard.reset_filters()


class TestAssetsTable:
    def test_assets_table_has_data(self, dashboard: DashboardPage):
        rows = dashboard.get_assets_rows()
        assert len([r for r in rows if "No assets" not in r.inner_text()]) > 0

    def test_assets_include_production_environment(self, dashboard: DashboardPage):
        all_text = " ".join(r.inner_text() for r in dashboard.get_assets_rows())
        assert "production" in all_text.lower()

    def test_assets_include_expected_hostname(self, dashboard: DashboardPage):
        all_text = " ".join(r.inner_text() for r in dashboard.get_assets_rows())
        assert "prod-web-01" in all_text
