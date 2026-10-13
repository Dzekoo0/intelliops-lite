import re

from src.contrat import Evenement, SEVERITES

_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|token|secret|api_key)(\s*[=:]\s*)\S+")

_NIVEAUX = {"ERROR": "HIGH", "WARN": "MEDIUM", "INFO": "LOW"}

_CLES_TRIVY = ["Target", "VulnerabilityID", "PkgName",
               "InstalledVersion", "Severity", "Timestamp"]


def masquer_secrets(texte: str) -> str:
    """Remplace la valeur des secrets par [SECRET]."""
    return _SECRET_RE.sub(r"\1\2[SECRET]", texte)


def normaliser_docker(ligne: str, numero: int,
                      environment: str = "production") -> Evenement:
    """Transforme une ligne de log Docker en Evenement."""
    champs = ligne.split()
    if len(champs) < 5:
        raise ValueError(f"Ligne invalide (moins de 5 champs) : {ligne!r}")

    date, heure, niveau, composant = champs[:4]
    message = " ".join(champs[4:])
    event_type = "CONTAINER_RESTART" if "restarts=" in message else "LOG"

    return Evenement(
        id=f"EVT-{numero:05d}",
        timestamp=f"{date}T{heure}Z",
        source="DOCKER",
        component=composant,
        environment=environment,
        event_type=event_type,
        severity=_NIVEAUX.get(niveau.upper(), "LOW"),
        message=masquer_secrets(message),
    )


def normaliser_trivy(rapport: dict, numero: int,
                     environment: str = "production") -> Evenement:
    """Transforme un rapport Trivy en Evenement."""
    for cle in _CLES_TRIVY:
        if cle not in rapport:
            raise ValueError(f"Clé manquante dans le rapport Trivy : {cle}")

    severite = str(rapport["Severity"]).upper()
    if severite not in SEVERITES:
        severite = "LOW"

    return Evenement(
        id=f"EVT-{numero:05d}",
        timestamp=rapport["Timestamp"],
        source="TRIVY",
        component=rapport["Target"],
        environment=environment,
        event_type="VULNERABILITY",
        severity=severite,
        message=(f"Vulnérabilité {rapport['VulnerabilityID']} détectée dans "
                 f"{rapport['PkgName']} {rapport['InstalledVersion']}"),
    )