#Author: Lukáš Šimoník, xsimonl00@stud.fit.vutbr.cz

"""
Static content-type classification of downloaded payloads with Magika.

Magika (https://github.com/google/magika) is a deep-learning file type
detector: it reads a few KB from the beginning and the end of a file and runs
a small ONNX model on those bytes. The sample is only *read* -- it is never
executed, unpacked, emulated or handed to an external program -- so the
classification is safe to run on live malware.

Result of ``classify_bytes()`` / ``classify_path()``::

    {
      "category":    "executable",              # coarse class, see CATEGORIES
      "label":       "elf",                     # Magika content type label
      "group":       "executable",              # Magika content type group
      "mime_type":   "application/x-executable-elf",
      "description": "ELF executable",
      "score":       0.999,                     # Magika confidence (0..1)
      "model":       "standard_v3_3",           # Magika model that produced it
    }

``None`` is returned when Magika is not installed or the sample cannot be
read, so callers never break because of the classifier.
"""

import logging
import threading

logger = logging.getLogger(__name__)

# Coarse content category used by the GUI filter and badge:
# category -> (human label, severity of the GUI badge: "high" / "medium" / "low").
# The category is derived from the Magika label/group by _category(); keep this
# dict in sync with the filter options of the web GUI (they are generated from it).
CATEGORIES = {
    "executable":  ("Executable binary",       "high"),
    "script":      ("Script",                  "high"),
    "html":        ("HTML page",               "low"),
    "json":        ("JSON",                    "low"),
    "source_code": ("Source code / markup",    "low"),
    "text":        ("Text",                    "low"),
    "archive":     ("Archive / compressed",    "medium"),
    "document":    ("Document",                "medium"),
    "image":       ("Image",                   "low"),
    "media":       ("Audio / video / font",    "low"),
    "data":        ("Application data",        "medium"),
    "unknown":     ("Unknown",                 "medium"),
    "empty":       ("Empty",                   "low"),
}

# Magika labels (group "code") of languages run directly by an interpreter --
# typical droppers and loaders served by malicious URLs.
_SCRIPT_LABELS = {
    "shell", "batch", "powershell", "python", "perl", "ruby", "php", "lua",
    "javascript", "vba", "autoit", "autohotkey", "awk", "tcl", "asp",
}
_GROUP_CATEGORIES = {
    "executable": "executable",
    "archive": "archive",
    "document": "document",
    "image": "image",
    "audio": "media",
    "video": "media",
    "font": "media",
    "text": "text",
    "application": "data",
    "code": "source_code",
}

_magika = None
_magika_lock = threading.Lock()
_magika_failed = False


def _get_magika():
    """Lazily create the shared Magika instance (None when unavailable)."""
    global _magika, _magika_failed
    if _magika is None and not _magika_failed:
        try:
            from magika import Magika
            _magika = Magika()
        except Exception as e:
            _magika_failed = True
            logger.warning(f"Magika is not available, content will not be classified: {e}")
    return _magika


def is_available():
    """True when Magika can be loaded."""
    return _get_magika() is not None


def category_info(category):
    """Return {label, severity} for a stored category (None-safe)."""
    label, severity = CATEGORIES.get(category, (category or "Not classified", "low"))
    return {"label": label, "severity": severity}


def classify_bytes(data):
    """Classify an in-memory payload. Never raises; None when Magika is unavailable."""
    return _identify(lambda m: m.identify_bytes(bytes(data or b"")))


def classify_path(path):
    """Classify a stored sample on disk (only reads it). None on failure."""
    return _identify(lambda m: m.identify_path(path))


def _identify(run):
    magika = _get_magika()
    if magika is None:
        return None
    try:
        # The ONNX session is shared by evaluator / activity_scanner threads.
        with _magika_lock:
            res = run(magika)
    except Exception as e:
        logger.warning(f"Magika classification failed: {e}")
        return None
    if not res.ok:
        logger.warning(f"Magika could not classify the sample: {res.status}")
        return None
    out = res.prediction.output
    label, group = str(out.label), str(out.group)
    return {
        "category": _category(label, group),
        "label": label,
        "group": group,
        "mime_type": out.mime_type,
        "description": out.description,
        "score": round(float(res.prediction.score), 4),
        "model": magika.get_model_name(),
    }


def _category(label, group):
    if label == "empty":
        return "empty"
    if label in ("html", "mht"):
        return "html"
    if label in ("json", "jsonl"):
        return "json"
    if label in _SCRIPT_LABELS:
        return "script"
    return _GROUP_CATEGORIES.get(group, "unknown")
