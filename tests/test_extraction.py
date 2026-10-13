import unittest

from src.extraction import masquer_secrets, normaliser_docker

LIGNE = "2026-10-05 10:02:11 ERROR backend OOMKilled restarts=14 node=db-02"


class TestExtraction(unittest.TestCase):
    def test_masquer_secrets(self):
        self.assertEqual(masquer_secrets("login ok password=abc123 user=bob"),
                         "login ok password=[SECRET] user=bob")

    def test_masquer_secrets_casse_et_deux_points(self):
        self.assertEqual(masquer_secrets("TOKEN: xyz API_KEY=k1"),
                         "TOKEN: [SECRET] API_KEY=[SECRET]")

    def test_normaliser_docker(self):
        evt = normaliser_docker(LIGNE, 125)
        self.assertEqual(evt.id, "EVT-00125")
        self.assertEqual(evt.timestamp, "2026-10-05T10:02:11Z")
        self.assertEqual(evt.severity, "HIGH")
        self.assertEqual(evt.source, "DOCKER")
        self.assertEqual(evt.component, "backend")
        self.assertEqual(evt.event_type, "CONTAINER_RESTART")

    def test_docker_masque_les_secrets(self):
        evt = normaliser_docker(
            "2026-10-05 10:05:40 WARN frontend lent password=abc123", 3)
        self.assertEqual(evt.message, "lent password=[SECRET]")

    def test_docker_ligne_trop_courte(self):
        with self.assertRaises(ValueError):
            normaliser_docker("2026-10-05 10:02:11 ERROR backend", 1)


if __name__ == "__main__":
    unittest.main()