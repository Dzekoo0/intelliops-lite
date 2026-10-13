import unittest
from src.analyse import analyser, classer, est_doublon, rechercher_runbook
from src.contrat import RUNBOOKS, Evenement


def evt(event_type="LOG", severity="LOW", message="ok", component="backend"):
    return Evenement("EVT-00001", "2026-10-05T10:00:00Z", "DOCKER", component,
                     "production", event_type, severity, message)


class TestAnalyse(unittest.TestCase):
    def test_doublon(self):
        vus = set()
        self.assertFalse(est_doublon(evt(message="a"), vus))
        self.assertTrue(est_doublon(evt(message="a"), vus))


if __name__ == "__main__":
    unittest.main()
    def test_runbook_trouve_sans_casse(self):
        e = evt(message="container oomkilled sur node-1")
        self.assertEqual(rechercher_runbook(e, RUNBOOKS), RUNBOOKS["OOMKilled"])

    def test_runbook_absent(self):
        self.assertIsNone(rechercher_runbook(evt(message="rien"), RUNBOOKS))

    def test_classer_redemarrages(self):
        e = evt("CONTAINER_RESTART", "HIGH", "OOMKilled restarts=14")
        self.assertEqual(classer(e), "CRITICAL")

    def test_classer_redemarrages_limite(self):
        self.assertEqual(classer(evt("CONTAINER_RESTART", "HIGH", "restarts=10")), "CRITICAL")
        self.assertEqual(classer(evt("CONTAINER_RESTART", "HIGH", "restarts=9")), "MEDIUM")

    def test_classer_vulnerabilite_critique(self):
        self.assertEqual(classer(evt("VULNERABILITY", "CRITICAL", "CVE-1")), "HIGH")

    def test_classer_autre_cas(self):
        self.assertEqual(classer(evt("VULNERABILITY", "LOW", "CVE-1")), "LOW")
        self.assertEqual(classer(evt("LOG", "MEDIUM", "slow")), "MEDIUM")

    def test_analyser_restart_critique(self):
        e = evt("CONTAINER_RESTART", "HIGH", "OOMKilled restarts=14")
        a = analyser(e, RUNBOOKS)
        self.assertEqual(a.criticite, "CRITICAL")
        self.assertEqual(a.cause_probable, RUNBOOKS["OOMKilled"])
        self.assertEqual(a.action_recommandee, "Redémarrer backend")
        self.assertTrue(a.sensible)
        self.assertEqual(a.sources, ["DOCKER"])
        self.assertEqual(e.status, "ANALYSED")

    def test_analyser_cause_inconnue_non_sensible(self):
        e = evt("LOG", "LOW", "tout va bien")
        a = analyser(e, RUNBOOKS)
        self.assertEqual(a.cause_probable, "Cause inconnue : analyse manuelle requise")
        self.assertEqual(a.action_recommandee, "Consulter les logs")
        self.assertFalse(a.sensible)

    def test_analyser_vulnerabilite(self):
        e = evt("VULNERABILITY", "CRITICAL", "Vulnérabilité CVE-2026-1234 détectée")
        a = analyser(e, RUNBOOKS)
        self.assertEqual(a.criticite, "HIGH")
        self.assertEqual(a.action_recommandee, "Mettre à jour la dépendance")