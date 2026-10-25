import unittest
from unittest.mock import MagicMock

from dnssentry.checker import (
    DEFAULT_SPF_VALUE,
    build_default_dmarc,
    check_dkim,
    check_dmarc,
    check_mx,
    check_spf,
    fix_ms_dkim,
)
from dnssentry.client import GoDaddyClient


class TestChecker(unittest.TestCase):
    def setUp(self):
        self.mock_client = MagicMock(spec=GoDaddyClient)

    def test_check_spf_present_single(self):
        self.mock_client.get_records.return_value = [
            {"type": "TXT", "name": "@", "data": "v=spf1 include:_spf.google.com ~all"}
        ]
        res = check_spf(self.mock_client, "example.com")
        self.assertTrue(res["present"])
        self.assertFalse(res["multiple"])
        self.assertEqual(len(res["records"]), 1)

    def test_check_spf_multiple_invalid(self):
        self.mock_client.get_records.return_value = [
            {"type": "TXT", "name": "@", "data": "v=spf1 include:_spf.google.com ~all"},
            {"type": "TXT", "name": "@", "data": "v=spf1 include:sendgrid.net -all"},
        ]
        res = check_spf(self.mock_client, "example.com")
        self.assertTrue(res["present"])
        self.assertTrue(res["multiple"])
        self.assertEqual(len(res["records"]), 2)

    def test_check_spf_missing(self):
        self.mock_client.get_records.return_value = [
            {"type": "TXT", "name": "@", "data": "google-site-verification=abc"}
        ]
        res = check_spf(self.mock_client, "example.com")
        self.assertFalse(res["present"])
        self.assertFalse(res["multiple"])

    def test_check_dmarc_present(self):
        self.mock_client.get_records.return_value = [
            {"type": "TXT", "name": "_dmarc", "data": "v=DMARC1; p=reject; rua=mailto:d@example.com"}
        ]
        res = check_dmarc(self.mock_client, "example.com")
        self.assertTrue(res["present"])

    def test_check_dmarc_missing(self):
        self.mock_client.get_records.return_value = []
        res = check_dmarc(self.mock_client, "example.com")
        self.assertFalse(res["present"])

    def test_check_dkim_present(self):
        def fake_get_records(domain, r_type, name):
            if name == "google._domainkey" and r_type == "TXT":
                return [{"data": "v=DKIM1; k=rsa; p=MIG..."}]
            return []

        self.mock_client.get_records.side_effect = fake_get_records
        res = check_dkim(self.mock_client, "example.com", selectors=["google", "selector1"])
        self.assertTrue(res["present"])
        self.assertIn("google", res["selectors_found"])
        self.assertNotIn("selector1", res["selectors_found"])

    def test_check_mx_present(self):
        self.mock_client.get_records.return_value = [
            {"type": "MX", "name": "@", "data": "aspmx.l.google.com", "priority": 1}
        ]
        res = check_mx(self.mock_client, "example.com")
        self.assertTrue(res["present"])
        self.assertEqual(len(res["records"]), 1)


    def test_default_spf_value(self):
        self.assertEqual(DEFAULT_SPF_VALUE, "v=spf1 include:spf.protection.outlook.com -all")

    def test_build_default_dmarc(self):
        dmarc = build_default_dmarc("example.com")
        self.assertIn("p=reject", dmarc)
        self.assertIn("sp=reject", dmarc)
        self.assertIn("rua=mailto:dmarc@example.com", dmarc)

    def test_fix_ms_dkim_dry_run(self):
        res = fix_ms_dkim(
            self.mock_client,
            domain="example.com",
            tenant="mytenant",
            ttl=3600,
            apply=False,
            auto_yes=True,
        )
        self.assertFalse(res)
        self.mock_client.put_records.assert_not_called()

    def test_fix_ms_dkim_apply(self):
        res = fix_ms_dkim(
            self.mock_client,
            domain="example.com",
            tenant="mytenant",
            ttl=3600,
            apply=True,
            auto_yes=True,
        )
        self.assertTrue(res)
        self.assertEqual(self.mock_client.put_records.call_count, 2)
        # Check target format
        calls = self.mock_client.put_records.call_args_list
        self.assertEqual(calls[0][0][1], "CNAME")
        self.assertEqual(calls[0][0][2], "selector1._domainkey")
        self.assertEqual(
            calls[0][0][3][0]["data"],
            "selector1-example-com._domainkey.mytenant.onmicrosoft.com",
        )
        self.assertEqual(calls[1][0][1], "CNAME")
        self.assertEqual(calls[1][0][2], "selector2._domainkey")
        self.assertEqual(
            calls[1][0][3][0]["data"],
            "selector2-example-com._domainkey.mytenant.onmicrosoft.com",
        )


if __name__ == "__main__":
    unittest.main()
