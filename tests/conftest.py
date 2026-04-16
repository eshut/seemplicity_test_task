import os
import pytest
from framework_inject.browser import Singleton, RunBrowser, BrowserFactory
from framework_inject.pages.qa_dashboard.pages.dashboard_page import DashboardPage

os.environ.setdefault("BROWSER", "ChromeBrowser")
os.environ.setdefault("LOCALIZATION", "en")
os.environ.setdefault("LOG_LEVEL", "INFO")


@pytest.fixture(scope="session")
def dashboard():
    page = DashboardPage()
    page.open()
    yield page
    Singleton.clear(RunBrowser)
    Singleton.clear(BrowserFactory)
