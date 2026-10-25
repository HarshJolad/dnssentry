import os
from pathlib import Path
import tempfile
import unittest

from dnssentry.cli import build_client, create_parser, load_env_file


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.parser = create_parser()
        self.orig_env = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.orig_env)

    def test_load_env_file(self):
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".env") as f:
            f.write("GODADDY_PAT=test_token_123\n")
            f_path = Path(f.name)

        try:
            load_env_file(f_path)
            self.assertEqual(os.environ.get("GODADDY_PAT"), "test_token_123")
        finally:
            if f_path.exists():
                f_path.unlink()

    def test_build_client_from_args(self):
        args = self.parser.parse_args(["--token", "cli_pat", "check", "example.com"])
        client = build_client(args)
        self.assertEqual(client.token, "cli_pat")

    def test_check_command_args(self):
        args = self.parser.parse_args(["check", "example.com", "--dkim-selector", "google"])
        self.assertEqual(args.command, "check")
        self.assertEqual(args.domain, "example.com")
        self.assertEqual(args.dkim_selector, "google")

    def test_fix_command_args(self):
        args = self.parser.parse_args([
            "--token", "pat_123",
            "fix", "example.com",
            "--spf-value", "v=spf1 ~all",
            "--apply",
            "--yes",
        ])
        self.assertEqual(args.command, "fix")
        self.assertEqual(args.token, "pat_123")
        self.assertEqual(args.domain, "example.com")
        self.assertEqual(args.spf_value, "v=spf1 ~all")
        self.assertTrue(args.apply)
        self.assertTrue(args.yes)


if __name__ == "__main__":
    unittest.main()
