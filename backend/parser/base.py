"""Parser framework: abstract base and registry.

Adding a new vendor:
  1. Create backend/parser/<vendor>/ package
  2. Subclass VendorParser
  3. Register with @register_parser(Vendor.X)
  4. Implement section parsers that emit CommonModel objects

No parser should know about target vendor syntax.
"""

from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod
from typing import Callable

from model.enums import SECTION_ORDER, SectionType, Vendor
from model.objects import CommonModel, ParsedSection

logger = logging.getLogger(__name__)


class ParseResult:
    """Outcome of a full vendor parse."""

    def __init__(
        self,
        model: CommonModel,
        sections: list[ParsedSection],
        vendor: Vendor,
        warnings: list[dict] | None = None,
    ) -> None:
        self.model = model
        self.sections = sections
        self.vendor = vendor
        self.warnings = warnings or []


class SectionParser(ABC):
    """Parses one logical configuration section for a vendor."""

    section_type: SectionType

    @abstractmethod
    def parse(self, raw: str, model: CommonModel) -> ParsedSection:
        """Parse `raw` config text, mutate `model`, return section summary."""


class VendorParser(ABC):
    """Top-level parser for a single source vendor."""

    vendor: Vendor
    # Fingerprints used by auto-detection (regex patterns against raw config)
    fingerprints: list[str] = []

    def __init__(self) -> None:
        self.section_parsers: list[SectionParser] = self.build_section_parsers()

    @abstractmethod
    def build_section_parsers(self) -> list[SectionParser]:
        """Return ordered list of section parsers for this vendor."""

    def detect_score(self, raw: str) -> float:
        """Return confidence 0.0–1.0 that `raw` belongs to this vendor."""
        if not self.fingerprints:
            return 0.0
        hits = sum(1 for fp in self.fingerprints if re.search(fp, raw, re.IGNORECASE | re.MULTILINE))
        return min(1.0, hits / max(1, len(self.fingerprints) * 0.5))

    def parse(self, raw: str) -> ParseResult:
        model = CommonModel(source_vendor=self.vendor.value)
        sections: list[ParsedSection] = []
        warnings: list[dict] = []

        for sp in self.section_parsers:
            try:
                section = sp.parse(raw, model)
                sections.append(section)
                if not section.parsed_ok:
                    for err in section.errors:
                        warnings.append(
                            {
                                "code": "PARSE_SECTION_ERROR",
                                "message": err,
                                "section": section.section_type,
                                "severity": "warning",
                            }
                        )
            except Exception as exc:  # noqa: BLE001 – isolate section failures
                logger.exception("Section parser %s failed", sp.section_type)
                sections.append(
                    ParsedSection(
                        section_type=sp.section_type.value,
                        display_name=sp.section_type.display_name,
                        object_count=0,
                        parsed_ok=False,
                        errors=[str(exc)],
                    )
                )
                warnings.append(
                    {
                        "code": "PARSE_SECTION_EXCEPTION",
                        "message": f"Failed to parse {sp.section_type.display_name}: {exc}",
                        "section": sp.section_type.value,
                        "severity": "error",
                    }
                )

        # Ensure all known sections appear in explorer (even if empty)
        present = {s.section_type for s in sections}
        for st in SECTION_ORDER:
            if st.value not in present:
                sections.append(
                    ParsedSection(
                        section_type=st.value,
                        display_name=st.display_name,
                        object_count=0,
                        parsed_ok=True,
                    )
                )

        # Stable order matching SECTION_ORDER
        order_map = {st.value: i for i, st in enumerate(SECTION_ORDER)}
        sections.sort(key=lambda s: order_map.get(s.section_type, 999))

        return ParseResult(model=model, sections=sections, vendor=self.vendor, warnings=warnings)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_PARSER_REGISTRY: dict[Vendor, type[VendorParser]] = {}


def register_parser(vendor: Vendor) -> Callable[[type[VendorParser]], type[VendorParser]]:
    def decorator(cls: type[VendorParser]) -> type[VendorParser]:
        cls.vendor = vendor
        _PARSER_REGISTRY[vendor] = cls
        return cls

    return decorator


def get_parser(vendor: Vendor) -> VendorParser:
    if vendor not in _PARSER_REGISTRY:
        raise KeyError(f"No parser registered for vendor: {vendor}")
    return _PARSER_REGISTRY[vendor]()


def list_parsers() -> list[Vendor]:
    return list(_PARSER_REGISTRY.keys())


def detect_vendor(raw: str) -> tuple[Vendor, float]:
    """Auto-detect source vendor from configuration text."""
    best_vendor = Vendor.UNKNOWN
    best_score = 0.0
    for vendor, cls in _PARSER_REGISTRY.items():
        score = cls().detect_score(raw)
        if score > best_score:
            best_score = score
            best_vendor = vendor
    if best_score < 0.15:
        return Vendor.UNKNOWN, best_score
    return best_vendor, best_score


def ensure_parsers_loaded() -> None:
    """Import vendor packages so @register_parser side-effects run."""
    # Local imports avoid circular deps at module load time
    from parser import fortigate as _fg  # noqa: F401
    from parser import palo as _pa  # noqa: F401
    from parser import checkpoint as _cp  # noqa: F401
    from parser import ftd as _ftd  # noqa: F401
