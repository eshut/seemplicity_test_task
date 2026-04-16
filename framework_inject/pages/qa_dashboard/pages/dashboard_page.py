from framework_inject.base.base_page import BasePage
from framework_inject.pages.qa_dashboard.constants import BASE_URL


class DashboardPage(BasePage):
    def __init__(self):
        super().__init__(__file__)
        self.total_count = "#total-count"
        self.critical_count = "#critical-count"
        self.high_count = "#high-count"
        self.medium_count = "#medium-count"
        self.low_count = "#low-count"
        self.last_updated = "#last-updated"
        self.findings_tbody = "#findings-table"
        self.findings_data_rows = "#findings-table tr:has(.text-muted)"
        self.filter_severity = "#filter-severity"
        self.filter_status = "#filter-status"
        self.findings_message = "#findings-message .message"
        self.status_selects = ".status-select"
        self.assets_tbody = "#assets-table"
        self.assets_rows = "#assets-table tr"

    def open(self):
        self.goto(BASE_URL)
        self.wait_for_element(self.findings_tbody)
        self.wait_for_element(self.assets_tbody)

    def get_card_value(self, card_id):
        return self.get_element_text(f"#{card_id}")

    def get_findings_rows(self):
        return self.get_elements_list(self.findings_data_rows)

    def get_assets_rows(self):
        return self.get_elements_list(self.assets_rows)

    def filter_by_severity(self, severity):
        self.page.select_option(self.filter_severity, severity)
        self.page.wait_for_timeout(800)

    def filter_by_status(self, status):
        self.page.select_option(self.filter_status, status)
        self.page.wait_for_timeout(800)

    def reset_filters(self):
        self.page.select_option(self.filter_severity, "")
        self.page.select_option(self.filter_status, "")
        self.page.wait_for_timeout(500)

    def change_first_finding_status(self, status):
        selects = self.get_elements_list(self.status_selects)
        if not selects:
            return None
        selects[0].select_option(status)
        self.page.wait_for_timeout(800)
        return self.get_element_text(self.findings_message)
