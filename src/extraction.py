import re

from src.contrat import Evenement, SEVERITES

_SECRET_RE = re.compile(
    r"\b(password|passwd|token|secret|api_key)(\s*[=:]\s*)(\S+)",
    re.IGNORECASE,
)


def masquer_secrets(texte: str) -> str:
    """Remplace la valeur des secrets par [SECRET] (insensible à la casse)."""
    return _SECRET_RE.sub(r"\1\2[SECRET]", texte)