    def test_canal_medium(self):
        self.assertEqual(choisir_canal("MEDIUM"), "EMAIL")
        self.assertEqual(choisir_canal("HIGH"), "TEAMS")

    def test_canal_invalide(self):
        with self.assertRaises(ValueError):
            choisir_canal("INCONNU")

    def test_validation_non_sensible(self):
        _, a = exemple(sensible=False, criticite="LOW")
        self.assertTrue(demander_validation(a, "n"))

    def test_validation_variantes(self):
        _, a = exemple()
        for rep in ("o", "OUI", " y ", "Yes"):
            self.assertTrue(demander_validation(a, rep))
        self.assertFalse(demander_validation(a, ""))

    def test_rediger(self):
        e, a = exemple()
        lignes = rediger(e, a).split("\n")
        self.assertEqual(len(lignes), 5)
        self.assertEqual(lignes[0], "[CRITICAL] Service : backend")
        self.assertEqual(lignes[4], "Sources : DOCKER")

    def test_notifier(self):
        e, a = exemple()
        journal = []
        n = notifier(e, a, journal)
        self.assertEqual(n.canal, "TEAMS")
        self.assertEqual(n.destinataire, "equipe-ops")
        self.assertEqual(journal, [n])
        self.assertEqual(e.status, "NOTIFIED")