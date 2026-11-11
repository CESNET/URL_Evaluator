"""
Integration tests: several modules together on the real test DB, real
content directory and a real local HTTP server (pytest-httpserver) serving
the "suspicious" URLs. External APIs stay mocked with `responses`.
"""

import pytest

from tests.api_mocks import mock_external_apis


@pytest.fixture
def run_evaluator():
    """
    Drive evaluator like its __main__ loop: process URLs waiting for
    evaluation until none is left. Returns the processed URLs in order.
    """
    def _run(ev, max_rounds=50):
        processed = []
        for _ in range(max_rounds):
            if not (url := ev.next_url()):
                return processed
            ev.process_url(url)
            processed.append(url)
        raise AssertionError(f"evaluator did not finish within {max_rounds} URLs: {processed}")

    return _run


@pytest.fixture
def external_apis(http_mock, config):
    """Factory: external_apis(**kwargs) -> mock_external_apis() bound to the test http_mock/config."""
    return lambda **kwargs: mock_external_apis(http_mock, config, **kwargs)
