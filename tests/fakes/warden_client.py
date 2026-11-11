"""
Stub of the `warden_client` module (not available on PyPI).

tests/conftest.py registers it as sys.modules["warden_client"] when the real
client is not installed, so bin/warden2evaluator.py can be imported. Tests
queue IDEA events with `Client.queue(...)`; getEvents() returns one batch
per call and an empty list once the queue is drained.
"""


class Error(Exception):
    pass


def read_cfg(path):
    return {"config_path": path}


class Client:
    _batches = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.get_events_calls = []

    @classmethod
    def queue(cls, *batches):
        cls._batches.extend(list(b) for b in batches)

    @classmethod
    def reset(cls):
        cls._batches = []

    def getEvents(self, **filters):
        self.get_events_calls.append(filters)
        return Client._batches.pop(0) if Client._batches else []
