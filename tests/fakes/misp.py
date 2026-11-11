"""Helpers for mocking the PyMISP client (the whole client, not its HTTP layer)."""

from unittest.mock import MagicMock

from pymisp import PyMISP


def make_fake_misp():
    """
    MagicMock restricted to the PyMISP API: calling a method that PyMISP does
    not have raises AttributeError, so typos in tests or code are caught.
    Set return values per test, e.g. misp.search.return_value = [...].
    """
    misp = MagicMock(spec=PyMISP)
    misp.search.return_value = []
    return misp
