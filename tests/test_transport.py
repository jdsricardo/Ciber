"""Unit tests for the transport's transient-error retry (no sockets; _exchange is stubbed)."""
import pathlib
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "scanner"))

from engine.models import HttpRequest, HttpResponse, ScanContext, ScanLimits, ScanMode
from engine.safety import SafetyController
from engine.transport import HttpTransport


def _transport() -> HttpTransport:
    context = ScanContext(target_url="http://127.0.0.1:9/", mode=ScanMode.PASSIVE,
                          limits=ScanLimits(), allow_private=True)
    return HttpTransport(SafetyController(context))


class TransportRetryTests(unittest.TestCase):
    def test_retries_once_on_transient_reset_and_charges_budget_once(self):
        transport = _transport()
        fake = HttpResponse(200, "http://127.0.0.1:9/", {}, [], b"ok", 1)
        calls = []

        def side(self, request):
            calls.append(1)
            if len(calls) == 1:
                raise ConnectionResetError("spurious reset")
            return fake

        with patch.object(HttpTransport, "_exchange", side):
            response = transport.send(HttpRequest(method="GET", url="http://127.0.0.1:9/"))

        self.assertIs(response, fake)
        self.assertEqual(len(calls), 2, "should have retried exactly once")
        self.assertEqual(transport.safety.total, 1, "budget must be charged once for the logical request")

    def test_does_not_retry_a_non_transient_error(self):
        transport = _transport()

        def side(self, request):
            raise ValueError("programming error, not a transient reset")

        with patch.object(HttpTransport, "_exchange", side):
            with self.assertRaises(ValueError):
                transport.send(HttpRequest(method="GET", url="http://127.0.0.1:9/"))

    def test_second_transient_failure_propagates(self):
        transport = _transport()

        def side(self, request):
            raise ConnectionAbortedError("reset again")

        with patch.object(HttpTransport, "_exchange", side):
            with self.assertRaises(ConnectionAbortedError):
                transport.send(HttpRequest(method="GET", url="http://127.0.0.1:9/"))


if __name__ == "__main__":
    unittest.main()
