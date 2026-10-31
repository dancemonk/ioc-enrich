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

    def test_missing_file(self):
        keys = load_keys({}, Path("/nonexistent/keys.env"))
        self.assertIsNone(keys.vt)


if __name__ == "__main__":
    unittest.main()
