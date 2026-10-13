import unittest

from src.extraction import masquer_secrets, normaliser_docker, normaliser_trivy

LIGNE = "2026-10-05 10:02:11 ERROR backend OOMKilled restarts=14 node=db-02"

RAPPORT = {"Target": "backend", "VulnerabilityID": "CVE-2026-1234",
           "PkgName": "lib", "InstalledVersion": "1.2.3",
           "Severity": "CRITICAL", "Timestamp": "2026-10-05T10:07:00Z"}


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

    def test_normaliser_trivy(self):
        evt = normaliser_trivy(RAPPORT, 4)
        self.assertEqual(evt.id, "EVT-00004")
        self.assertEqual(evt.source, "TRIVY")
        self.assertEqual(evt.component, "backend")
        self.assertEqual(evt.event_type, "VULNERABILITY")
        self.assertEqual(evt.severity, "CRITICAL")
        self.assertEqual(evt.message,
                         "Vulnérabilité CVE-2026-1234 détectée dans lib 1.2.3")

    def test_trivy_severite_inconnue(self):
        evt = normaliser_trivy({**RAPPORT, "Severity": "bizarre"}, 1)
        self.assertEqual(evt.severity, "LOW")

    def test_trivy_cle_manquante(self):
        rapport = dict(RAPPORT)
        del rapport["PkgName"]
        with self.assertRaises(ValueError):
            normaliser_trivy(rapport, 1)


if __name__ == "__main__":
    unittest.main()