import unittest
from dnssentry.client import (
    GoDaddyClient,
    GoDaddyError,
    clear_cache,
    get_cached_records,
    set_cached_records,
)


class TestClient(unittest.TestCase):
    def tearDown(self):
        clear_cache("test-cache-domain.com")

    def test_missing_credentials_raises(self):
        with self.assertRaises(GoDaddyError) as ctx:
            GoDaddyClient()
        self.assertIn("Missing GoDaddy Personal Access Token", str(ctx.exception))

    def test_pat_initialization(self):
        client = GoDaddyClient(token="my_pat_token")
        self.assertEqual(client.token, "my_pat_token")
        self.assertEqual(client.base, GoDaddyClient.PROD_BASE)

    def test_ote_base_url(self):
        client = GoDaddyClient(token="my_pat_token", use_ote=True)
        self.assertEqual(client.base, GoDaddyClient.OTE_BASE)

    def test_cache_save_and_retrieve(self):
        domain = "test-cache-domain.com"
        records = [{"type": "TXT", "name": "@", "data": "v=spf1 ~all"}]
        set_cached_records(domain, records)

        cached = get_cached_records(domain, max_age=60)
        self.assertIsNotNone(cached)
        res_records, age = cached
        self.assertEqual(res_records, records)
        self.assertGreaterEqual(age, 0)

    def test_cache_expiration(self):
        domain = "test-cache-domain.com"
        records = [{"type": "TXT", "name": "@", "data": "v=spf1 ~all"}]
        set_cached_records(domain, records)

        # max_age = -1 means already expired
        cached = get_cached_records(domain, max_age=-1)
        self.assertIsNone(cached)

    def test_cache_clear(self):
        domain = "test-cache-domain.com"
        records = [{"type": "TXT", "name": "@", "data": "v=spf1 ~all"}]
        set_cached_records(domain, records)
        clear_cache(domain)

        cached = get_cached_records(domain, max_age=60)
        self.assertIsNone(cached)


if __name__ == "__main__":
    unittest.main()
