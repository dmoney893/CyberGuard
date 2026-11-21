"""Lightweight brand-lookalike checks for local correlation rules.

Mirrors the conservative ASCII one-edit / brand-in-hostname logic used by the
backend website analyzer, without importing the backend package.
"""

from __future__ import annotations

import re

# brand label -> official domains that are allowed
BRANDS: dict[str, tuple[str, ...]] = {
    "fedex": ("fedex.com", "fedex.ca"),
    "ups": ("ups.com",),
    "dhl": ("dhl.com", "dhl.de"),
    "paypal": ("paypal.com", "paypal.me"),
    "apple": ("apple.com", "icloud.com"),
    "google": ("google.com", "gmail.com", "youtube.com"),
    "microsoft": ("microsoft.com", "live.com", "office.com", "outlook.com"),
    "amazon": ("amazon.com", "amazon.co.uk", "amazonaws.com"),
    "netflix": ("netflix.com",),
    "facebook": ("facebook.com", "fb.com", "meta.com"),
    "instagram": ("instagram.com",),
    "chase": ("chase.com",),
    "wellsfargo": ("wellsfargo.com",),
    "bankofamerica": ("bankofamerica.com",),
}

ASCII_LOOKALIKE_BRANDS = {
    brand: official
    for brand, official in BRANDS.items()
    if len(brand) >= 4
}


def is_brand_lookalike(domain: str) -> tuple[bool, str | None]:
    """Return (is_lookalike, brand) for a hostname / domain label."""

    host = (domain or "").strip().lower()
    if host.startswith("www."):
        host = host[4:]
    if not host:
        return False, None

    for brand, official in BRANDS.items():
        if any(host == item or host.endswith("." + item) for item in official):
            return False, None

    for brand, official in BRANDS.items():
        if any(host == item or host.endswith("." + item) for item in official):
            continue
        if re.search(r"(?:^|[.-])" + re.escape(brand) + r"(?:[.-]|$)", host):
            # brand mentioned but not on an official domain
            if not any(host == item or host.endswith("." + item) for item in official):
                return True, brand

    labels = host.split(".")[:-1] if "." in host else [host]
    for brand, official in ASCII_LOOKALIKE_BRANDS.items():
        if any(host == item or host.endswith("." + item) for item in official):
            continue
        if any(
            label != brand
            and len(label) == len(brand)
            and sum(a != b for a, b in zip(label, brand)) == 1
            for label in labels
        ):
            return True, brand

    return False, None
