import os
import pytest

from framework_inject.browser import Singleton, RunBrowser, BrowserFactory
from framework_inject.database.db_helper import DBHelper
from framework_inject.pages.qa_dashboard.pages.dashboard_page import DashboardPage
from framework_inject.services.sql_service import SQL
from tests.constants import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, DB_PORT

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


@pytest.fixture
def db():
    sql = SQL(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME, port=DB_PORT, dictionary=True)
    yield DBHelper(sql)
    sql.close_connect()
