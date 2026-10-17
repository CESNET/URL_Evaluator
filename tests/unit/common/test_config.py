import pytest

from common.config import Config


def test_values_are_attributes(config):
    assert config.vt_minute_quota == 4
    assert config.ddos_threshold["same_url_single_session"] == 10


def test_overrides(make_config, tmp_path):
    cfg = make_config(http_proxy="http://proxy.test:3128", max_file_size=5)
    assert cfg.http_proxy == "http://proxy.test:3128"
    assert cfg.max_file_size == 5
    assert cfg.db_path.startswith(str(tmp_path))


def test_missing_key_raises_attribute_error(config):
    with pytest.raises(AttributeError):
        config.no_such_key


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        Config(str(tmp_path / "missing.yaml"))
