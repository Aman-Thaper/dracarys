"""Detector registry."""
from dracarys.scanner.detectors.access import ACCESS_DETECTORS
from dracarys.scanner.detectors.exposure import SITE_DETECTORS
from dracarys.scanner.detectors.injection import PARAM_DETECTORS
from dracarys.scanner.detectors.passive import PASSIVE_DETECTORS

ALL_SITE_DETECTORS = [*SITE_DETECTORS, *ACCESS_DETECTORS]

__all__ = ["PASSIVE_DETECTORS", "PARAM_DETECTORS", "ALL_SITE_DETECTORS"]
