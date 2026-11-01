import io
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ioc_enrich.cli import main
from ioc_enrich.config import load_keys
from ioc_enrich.setup_keys import run

SECRET_VT = "vt-secret-1234567890"
SECRET_OTX = "otx-secret-abcdef"


def answers(*values):
    """A fake getpass that returns the given answers in order."""
    queue = list(values)
    prompts = []

    def ask(prompt):
        prompts.append(prompt)
        return queue.pop(0)
    ask.prompts = prompts
    return ask


class SetupKeysTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "config" / "ioc-enrich" / "keys.env"

    def tearDown(self):
        self.tmp.cleanup()

    def run_setup(self, ask, env=None):
        out = io.StringIO()
        code = run(self.path, ask=ask, out=out, env=env or {})
        return code, out.getvalue()

    def test_saves_entered_keys_and_skips_empty_ones(self):
        code, out = self.run_setup(answers(f"  {SECRET_VT}  ", "", SECRET_OTX, ""))
        self.assertEqual(code, 0)
        keys = load_keys({}, self.path)
        self.assertEqual((keys.vt, keys.abusech, keys.otx, keys.abuseipdb),
                         (SECRET_VT, None, SECRET_OTX, None))
        self.assertIn("Saved 2 keys", out)
        self.assertIn("Not set: abuse.ch (ThreatFox, URLhaus, MalwareBazaar), AbuseIPDB", out)

    def test_never_prints_key_values(self):
        ask = answers(SECRET_VT, "", SECRET_OTX, "")
        _, out = self.run_setup(ask)
        self.assertNotIn(SECRET_VT, out)
        self.assertNotIn(SECRET_OTX, out)
        self.assertTrue(all(SECRET_VT not in p for p in ask.prompts))

    def test_file_and_folder_are_private(self):
        self.run_setup(answers(SECRET_VT, "", "", ""))
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o700)

    def test_existing_file_is_tightened_to_owner_only(self):
        self.path.parent.mkdir(parents=True)
        self.path.write_text("OTX_API_KEY=old\n")
        self.path.chmod(0o644)
        self.run_setup(answers("", "", "", ""))
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_enter_keeps_an_existing_key_and_other_lines_survive(self):
        self.path.parent.mkdir(parents=True)
        self.path.write_text("# my keys\nOTX_API_KEY=old-otx\nVT_API_KEY=old-vt\nOTHER=1\n")
        ask = answers(SECRET_VT, "", "", "")
        _, out = self.run_setup(ask)
        keys = load_keys({}, self.path)
        self.assertEqual((keys.vt, keys.otx), (SECRET_VT, "old-otx"))
        text = self.path.read_text()
        self.assertIn("# my keys", text)
        self.assertIn("OTHER=1", text)
        self.assertEqual(text.count("VT_API_KEY="), 1)
        # The prompt says a key is already set, without showing it
        otx_prompt = ask.prompts[2]
        self.assertIn("already set", otx_prompt)
        self.assertNotIn("old-otx", otx_prompt)
        self.assertIn("Saved 1 key ", out)

    def test_nothing_entered_writes_no_file(self):
        code, out = self.run_setup(answers("", "", "", ""))
        self.assertEqual(code, 0)
        self.assertFalse(self.path.exists())
        self.assertIn("Nothing saved", out)

    def test_ctrl_c_saves_nothing(self):
        def ask(prompt):
            if "OTX" in prompt:
                raise KeyboardInterrupt
            return SECRET_VT
        code, out = self.run_setup(ask)
        self.assertEqual(code, 130)
        self.assertFalse(self.path.exists())
        self.assertIn("nothing saved", out.lower())

    def test_rejects_a_value_with_spaces(self):
        # A pasted "VT_API_KEY=abc" or two keys at once is a mistake, not a key
        code, out = self.run_setup(answers("abc def", "VT_API_KEY=abc", "", ""))
        self.assertEqual(code, 0)
        self.assertFalse(self.path.exists())
        self.assertIn("doesn't look like a key", out)

    def test_warns_when_an_environment_variable_wins(self):
        _, out = self.run_setup(answers(SECRET_VT, "", "", ""), env={"VT_API_KEY": "from-env"})
        self.assertIn("VT_API_KEY is also set as an environment variable", out)
        self.assertNotIn("from-env", out)

    def test_prompt_says_where_to_get_each_key(self):
        ask = answers("", "", "", "")
        self.run_setup(ask)
        self.assertIn("auth.abuse.ch", ask.prompts[1])
        self.assertIn("otx.alienvault.com", ask.prompts[2])


class KeysCommandTest(unittest.TestCase):
    def test_cli_keys_command_writes_the_given_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "keys.env"
            out = io.StringIO()
            with mock.patch("ioc_enrich.setup_keys.getpass.getpass", answers(SECRET_VT, "", "", "")):
                code = main(["keys", "--keys", str(path)], stdout=out, env={})
            self.assertEqual(code, 0)
            self.assertEqual(load_keys({}, path).vt, SECRET_VT)
            self.assertIn(str(path), out.getvalue())

    def test_help_lists_keys_command(self):
        out = io.StringIO()
        with mock.patch("sys.stdout", out), self.assertRaises(SystemExit):
            main(["--help"])
        self.assertIn("ioc-enrich keys", out.getvalue())


if __name__ == "__main__":
    unittest.main()
