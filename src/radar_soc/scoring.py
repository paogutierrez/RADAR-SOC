"""Risk Scoring: convierte señales en puntuación, clasificación y severidad.

Principio de diseño: ninguna señal aislada genera alerta. Se exige un mínimo
de puntos Y corroboración entre categorías independientes. Esto reduce falsos
positivos como "IP desconocida" o "login nocturno" por sí solos.
"""
from __future__ import annotations

from .models import Classification, Severity

SUSPICION_MIN_SCORE = 40
STRONG_MIN_SCORE = 60
SUSPICION_MIN_CATEGORIES = 2
STEALER_CODE = "endpoint_stealer_indicator"
CONTEXT_CATEGORIES = {"session_context", "network"}


def compute_score(signals: list) -> int:
    return max(0, min(100, sum(s.weight for s in signals)))


def positive_categories(signals: list) -> set:
    return {s.category for s in signals if s.weight > 0}


def classify(signals: list, score: int) -> Classification:
    """Devuelve ANOMALY, SUSPICION o STRONG_SUSPICION. Nunca CONFIRMED."""
    categories = positive_categories(signals)
    codes = {s.code for s in signals if s.weight > 0}
    if (STEALER_CODE in codes and categories & CONTEXT_CATEGORIES
            and score >= STRONG_MIN_SCORE):
        return Classification.STRONG_SUSPICION
    if (score >= SUSPICION_MIN_SCORE
            and len(categories) >= SUSPICION_MIN_CATEGORIES):
        return Classification.SUSPICION
    return Classification.ANOMALY


def severity_for(classification: Classification, score: int) -> Severity:
    if classification is Classification.STRONG_SUSPICION:
        return Severity.CRITICAL if score >= 80 else Severity.HIGH
    if classification is Classification.SUSPICION:
        return Severity.HIGH if score >= 60 else Severity.MEDIUM
    return Severity.INFO
