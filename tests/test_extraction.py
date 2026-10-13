import unittest

from src.extraction import masquer_secrets


class TestExtraction(unittest.TestCase):
    def test_masquer_secrets(self):
        self.assertEqual(masquer_secrets("login ok password=abc123 user=bob"),
                         "login ok password=[SECRET] user=bob")

    def test_masquer_secrets_casse_et_deux_points(self):
        self.assertEqual(masquer_secrets("TOKEN: xyz API_KEY=k1"),
                         "TOKEN: [SECRET] API_KEY=[SECRET]")


if __name__ == "__main__":
    unittest.main()