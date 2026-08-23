import json
import pathlib
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "scanner"))
import scanner

class ScannerTests(unittest.TestCase):
    def test_catalog_has_broad_passive_coverage(self):
        self.assertGreaterEqual(len(scanner.CATALOG), 30)
        families = {item.split('.')[0] for item in scanner.CATALOG}
        self.assertTrue({'transport','tls','headers','cookies','cors','cache','content','disclosure'} <= families)

    def test_private_target_is_blocked(self):
        with self.assertRaises(ValueError):
            scanner.validate_target(__import__('urllib.parse').parse.urlparse('http://127.0.0.1'), False)

    def test_finding_is_developer_oriented(self):
        item = scanner.make_finding('headers.csp', 'missing', 'https://example.com')
        for key in ('severity','evidence','developer_impact','remediation','affected_url','fingerprint'):
            self.assertTrue(item[key])

if __name__ == '__main__':
    unittest.main()
