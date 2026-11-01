import tempfile
import unittest
from pathlib import Path

from ioc_enrich.config import load_keys


class KeysTest(unittest.TestCase):
    def test_env_and_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "keys.env"
            path.write_text('# my keys\nOTX_API_KEY="otxfile"\nVT_API_KEY=fromfile\n')
            keys = load_keys({"VT_API_KEY": "TESTKEY123"}, path)
        self.assertEqual(keys.vt, "TESTKEY123")      # env wins over file
        self.assertEqual(keys.otx, "otxfile")        # quotes stripped
        self.assertIsNone(keys.abusech)
        self.assertNotIn("TESTKEY123", repr(keys))
        self.assertNotIn("otxfile", repr(keys))
        self.assertIn("vt=set", repr(keys))

    def test_common_file_styles(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "keys.env"
            path.write_text("\ufeffVT_API_KEY=vtkey\r\nexport OTX_API_KEY=otxkey\n"
                            "ABUSEIPDB_API_KEY=abusekey  # mine\nABUSECH_AUTH_KEY='q#1'\n", encoding="utf-8")
            keys = load_keys({}, path)
        self.assertEqual((keys.vt, keys.otx, keys.abuseipdb, keys.abusech), ("vtkey", "otxkey", "abusekey", "q#1"))

    def test_missing_file(self):
        keys = load_keys({}, Path("/nonexistent/keys.env"))
        self.assertIsNone(keys.vt)


if __name__ == "__main__":
    unittest.main()
