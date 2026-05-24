"""Forensic image handling — open E01 / raw disks, walk their filesystems and
extract browser profiles."""

from forensics.image import open_image, ForensicImageError
from forensics.extractor import ImageProfileLocator, LocatedProfile
from forensics.categorizer import categorize
from forensics.search_terms import derive_search_terms_for_profile, extract_search_term

__all__ = [
    "open_image",
    "ForensicImageError",
    "ImageProfileLocator",
    "LocatedProfile",
    "categorize",
    "derive_search_terms_for_profile",
    "extract_search_term",
]
