"""Configuration parsers – vendor CLI/XML → CommonModel."""

from .base import (
    ParseResult,
    SectionParser,
    VendorParser,
    detect_vendor,
    ensure_parsers_loaded,
    get_parser,
    list_parsers,
    register_parser,
)

__all__ = [
    "ParseResult",
    "SectionParser",
    "VendorParser",
    "detect_vendor",
    "ensure_parsers_loaded",
    "get_parser",
    "list_parsers",
    "register_parser",
]
