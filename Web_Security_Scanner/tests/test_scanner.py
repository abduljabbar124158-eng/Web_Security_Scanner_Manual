import unittest
from scanner import scan

class ScannerTests(unittest.TestCase):
    def test_invalid_scheme(self):
        with self.assertRaises(ValueError):
            scan("ftp://example.com")

    def test_missing_hostname(self):
        with self.assertRaises(ValueError):
            scan("http:///missing-host")

if __name__ == "__main__":
    unittest.main()
