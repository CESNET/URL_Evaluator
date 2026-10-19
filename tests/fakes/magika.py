"""
Deterministic stand-in for magika.Magika used by unit tests.

It recognises a few payload types by their leading bytes and returns objects
with the same shape as Magika's results (only the attributes read by
common/file_classifier.py), so classification is fast and predictable.
"""

from types import SimpleNamespace

MODEL_NAME = "fake_magika"

# (prefix test, label, group, mime_type, description)
_RULES = [
    (lambda d: d.startswith(b"\x7fELF"), "elf", "executable", "application/x-executable-elf", "ELF executable"),
    (lambda d: d.startswith(b"MZ"), "pebin", "executable", "application/x-dosexec", "PE Windows executable"),
    (lambda d: d.startswith(b"#!") and b"sh" in d.split(b"\n", 1)[0], "shell", "code", "text/x-shellscript", "Shell script"),
    (lambda d: d.startswith(b"#!") and b"python" in d.split(b"\n", 1)[0], "python", "code", "text/x-python", "Python source"),
    (lambda d: d.startswith(b"PK\x03\x04"), "zip", "archive", "application/zip", "ZIP archive data"),
    (lambda d: d.startswith(b"\x1f\x8b"), "gzip", "archive", "application/gzip", "gzip compressed data"),
    (lambda d: d.lstrip()[:15].lower().startswith((b"<!doctype html", b"<html")), "html", "code", "text/html", "HTML document"),
    (lambda d: d.lstrip()[:1] in (b"{", b"["), "json", "code", "application/json", "JSON document"),
]


def classify(data):
    """Return (label, group, mime_type, description) for `data`."""
    if not data:
        return "empty", "inode", "inode/x-empty", "Empty file"
    for test, label, group, mime, description in _RULES:
        if test(data):
            return label, group, mime, description
    return "txt", "text", "text/plain", "Generic text document"


def _result(data):
    label, group, mime, description = classify(data)
    output = SimpleNamespace(label=label, group=group, mime_type=mime, description=description)
    return SimpleNamespace(ok=True, status="ok", prediction=SimpleNamespace(output=output, score=0.99))


class FakeMagika:
    def __init__(self):
        self.calls = []  # ("bytes", data) / ("path", path), for asserts

    def identify_bytes(self, data):
        self.calls.append(("bytes", data))
        return _result(bytes(data))

    def identify_path(self, path):
        self.calls.append(("path", path))
        with open(path, "rb") as f:
            return _result(f.read())

    def get_model_name(self):
        return MODEL_NAME
