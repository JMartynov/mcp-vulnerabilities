"""Compatibility module re-exporting SecurityCommentaryEngine."""

from .capability_classifier import (
    RiskCategory,
    SecurityCommentaryEngine,
    ServerCommentaryResult,
    SeverityTier,
    ToolRiskClassification,
)

__all__ = [
    "RiskCategory",
    "SecurityCommentaryEngine",
    "ServerCommentaryResult",
    "SeverityTier",
    "ToolRiskClassification",
]
