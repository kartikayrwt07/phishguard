"""
Detection subsystem exports.
"""
from app.detection.url_parser import ParsedURL, URLNormalizer
from app.detection.features import FeatureExtractor, URLFeatures
from app.detection.brand_matcher import BrandMatchResult, BrandMatcher
from app.detection.dom_evaluator import DOMEvaluationResult, DOMSignalEvaluator, DOMSignals
from app.detection.scoring import EvidenceItem, RiskEngine, RiskReport

__all__ = [
    # URL Analysis
    "ParsedURL",
    "URLNormalizer",
    "FeatureExtractor",
    "URLFeatures",
    # Brand Impersonation
    "BrandMatcher",
    "BrandMatchResult",
    # DOM Evaluation
    "DOMSignals",
    "DOMSignalEvaluator",
    "DOMEvaluationResult",
    # Risk Scoring & Overrides
    "RiskEngine",
    "RiskReport",
    "EvidenceItem",
]
