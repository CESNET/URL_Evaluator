"""
Shared fixtures of the URL Evaluator test suite (see docs/TEST_FRAMEWORK_PLAN.md).

Real:   SQLite DB file + content dir in tmp_path, Config loaded from
        tests/data/config.test.yaml, local HTTP server (pytest-httpserver).
Mocked: external HTTP APIs (responses), PyMISP (MagicMock), warden_client
        (stub module), Magika (FakeMagika unless the test uses real_magika),
        time.sleep (recorded no-op unless marked real_sleep).
"""

import importlib
import os
import sys
import time

import pytest
import responses
import yaml

from common.config import Config
from common.db import SQLiteWrapper
from common import file_classifier, hybrid_analysis
from tests.fakes import warden_client as fake_warden_client
from tests.fakes.magika import FakeMagika
from tests.fakes.misp import make_fake_misp

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.path.join(REPO_ROOT, "tests", "data")
CREATE_DB_SQL = os.path.join(REPO_ROOT, "install", "create_db.sql")
CONFIG_TEMPLATE = os.path.join(DATA_DIR, "config.test.yaml")

# bin/warden2evaluator.py imports warden_client at module level; the client is
# not on PyPI, so the stub stands in unless a real one is installed.
try:
    import warden_client  # noqa: F401
except ImportError:
    sys.modules["warden_client"] = fake_warden_client


# ---------------------------------------------------------------------------
# Command line options / markers
# ---------------------------------------------------------------------------

def pytest_addoption(parser):
    parser.addoption("--run-live", action="store_true", default=False,
                     help="run tests marked 'live' (real external APIs, keys from env)")


def pytest_collection_modifyitems(config, items):
    run_live = config.getoption("--run-live")
    skip_live = pytest.mark.skip(reason="live test, use --run-live")
    for item in items:
        if "live" in item.keywords:
            if run_live:
                item.add_marker(pytest.mark.enable_socket)  # lift the localhost-only guard
            else:
                item.add_marker(skip_live)


def data_path(*parts):
    """Absolute path of a file in tests/data/."""
    return os.path.join(DATA_DIR, *parts)


# ---------------------------------------------------------------------------
# Config, DB, filesystem
# ---------------------------------------------------------------------------

@pytest.fixture
def content_dir(tmp_path):
    path = tmp_path / "content"
    path.mkdir()
    return str(path)


@pytest.fixture
def db_path(tmp_path):
    """Path of an empty DB created from install/create_db.sql."""
    path = str(tmp_path / "db.sqlite")
    with open(CREATE_DB_SQL, encoding="utf-8") as f:
        schema = f.read()
    db = SQLiteWrapper(path)
    try:
        db.conn.executescript(schema)
    finally:
        db.close()
    return path


@pytest.fixture
def make_config(tmp_path, db_path, content_dir):
    """
    Factory: make_config(**overrides) -> Config. Values come from
    tests/data/config.test.yaml with db_path/content_dir in tmp_path; top-level
    keys can be overridden, e.g. make_config(http_proxy="http://proxy:3128").
    """
    counter = iter(range(1000))

    def _make(**overrides):
        with open(CONFIG_TEMPLATE, encoding="utf-8") as f:
            values = yaml.safe_load(f)
        values.update(db_path=db_path, content_dir=content_dir)
        values.update(overrides)
        path = tmp_path / f"config-{next(counter)}.yaml"
        path.write_text(yaml.safe_dump(values), encoding="utf-8")
        cfg = Config(str(path))
        cfg._test_path = str(path)  # instance attribute, not a config key
        return cfg

    return _make


@pytest.fixture
def config(make_config):
    return make_config()


@pytest.fixture
def db(db_path):
    with SQLiteWrapper(db_path) as conn:
        yield conn


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

@pytest.fixture
def http_mock():
    """
    Active `responses` mock for the `requests` library. Unregistered URLs
    raise ConnectionError; requests to localhost (pytest-httpserver) pass
    through to the real local server.
    """
    with responses.RequestsMock(assert_all_requests_are_fired=False) as mock:
        mock.add_passthru("http://localhost")
        mock.add_passthru("http://127.0.0.1")
        yield mock


# ---------------------------------------------------------------------------
# External clients
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_misp():
    return make_fake_misp()


@pytest.fixture
def warden_events():
    """Queue IDEA event batches for the warden_client stub: warden_events([ev1, ev2], [ev3])."""
    fake_warden_client.Client.reset()
    yield fake_warden_client.Client.queue
    fake_warden_client.Client.reset()


# ---------------------------------------------------------------------------
# Magika
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_magika():
    """The FakeMagika instance installed for the current test (for asserts on .calls)."""
    return file_classifier._magika


@pytest.fixture(scope="session")
def _real_magika_instance():
    magika = pytest.importorskip("magika")
    return magika.Magika()


@pytest.fixture
def real_magika(_real_magika_instance, monkeypatch):
    """Use the real Magika model in this test (mark the test @pytest.mark.slow)."""
    monkeypatch.setattr(file_classifier, "_magika", _real_magika_instance)
    return _real_magika_instance


# ---------------------------------------------------------------------------
# Module-level state reset (autouse)
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_module_state(monkeypatch):
    """
    Reset state kept at module level, so tests never influence each other.
    Add new module-level state here (rule 4 in the plan).
    """
    # file_classifier: FakeMagika by default (real_magika overrides it)
    monkeypatch.setattr(file_classifier, "_magika", FakeMagika())
    monkeypatch.setattr(file_classifier, "_magika_failed", False)

    # hybrid_analysis: rate-limit back-off and request statistics
    monkeypatch.setattr(hybrid_analysis, "_blocked_until", None)
    hybrid_analysis.reset_request_stats()

    # bin/activity_scanner: stop flag and per-run counters (only when imported;
    # the rest of the bin/* state is reset by their init())
    if scanner := sys.modules.get("bin.activity_scanner"):
        scanner.stop_event.clear()
        scanner.run_stats.clear()
    yield
    hybrid_analysis.reset_request_stats()


@pytest.fixture(autouse=True)
def no_sleep(request, monkeypatch):
    """
    Replace time.sleep with a no-op that records the requested delays
    (list of seconds). Tests marked `real_sleep` keep the real one.
    """
    calls = []
    if request.node.get_closest_marker("real_sleep"):
        return calls
    monkeypatch.setattr(time, "sleep", lambda seconds: calls.append(seconds))
    return calls


# ---------------------------------------------------------------------------
# bin/* scripts
# ---------------------------------------------------------------------------

BIN_MODULES = (
    "evaluator", "activity_scanner", "db_cleaner", "evaluator2misp",
    "evaluator2misp_bysource", "evaluator2urlhaus", "honeynetasia2evaluator",
    "tpot2evaluator", "warden2evaluator",
)


@pytest.fixture
def init_bin(config, db):
    """
    Factory: init_bin("db_cleaner", cfg=None) -> the bin/ module after its
    init() with the test config (evaluator also gets the test `db` connection).
    """
    def _init(name, cfg=None):
        module = importlib.import_module(f"bin.{name}")
        cfg = cfg or config
        if name == "evaluator":
            module.init(cfg, db)
        else:
            module.init(cfg)
        return module

    return _init


def _bin_module_fixture(name):
    @pytest.fixture(name=f"{name}_mod")
    def _fixture(init_bin):
        return init_bin(name)
    return _fixture


# evaluator_mod, activity_scanner_mod, db_cleaner_mod, ... (one per BIN_MODULES)
for _name in BIN_MODULES:
    globals()[f"{_name}_mod"] = _bin_module_fixture(_name)


# ---------------------------------------------------------------------------
# Web UI
# ---------------------------------------------------------------------------

@pytest.fixture
def web_app(config, monkeypatch, fake_misp):
    """
    Fresh import of web/main.py bound to the test config. The module reads
    its config and connects to MISP at import time, and keeps paging/filter
    state in globals, so it is re-imported for every test.
    """
    import pymisp

    monkeypatch.setenv("URL_EVALUATOR_CONFIG", config._test_path)
    monkeypatch.setattr(pymisp, "PyMISP", lambda *args, **kwargs: fake_misp)
    sys.modules.pop("web.main", None)
    module = importlib.import_module("web.main")
    module.app.config.update(TESTING=True)
    yield module
    sys.modules.pop("web.main", None)


@pytest.fixture
def web_client(web_app):
    return web_app.app.test_client()
