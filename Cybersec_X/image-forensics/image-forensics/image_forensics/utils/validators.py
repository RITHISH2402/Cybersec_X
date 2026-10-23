"""Validation utilities for image forensics."""

import os
from pathlib import Path
from typing import Optional, Tuple


def validate_image_file(file_path: str) -> Tuple[bool, Optional[str]]:
    """Validate that file exists and is an image.

    Args:
        file_path: Path to file

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not os.path.exists(file_path):
        return False, f"File not found: {file_path}"

    if not os.path.isfile(file_path):
        return False, f"Not a file: {file_path}"

    ext = Path(file_path).suffix.lower()
    valid_extensions = {'.jpg', '.jpeg', '.png', '.tiff', '.tif', '.webp', '.heic', '.heif', '.gif', '.bmp'}

    if ext not in valid_extensions:
        return False, f"Unsupported file type: {ext}"

    return True, None


def validate_coordinates(lat: float, lon: float) -> Tuple[bool, Optional[str]]:
    """Validate GPS coordinates.

    Args:
        lat: Latitude
        lon: Longitude

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not (-90 <= lat <= 90):
        return False, f"Invalid latitude: {lat} (must be -90 to 90)"

    if not (-180 <= lon <= 180):
        return False, f"Invalid longitude: {lon} (must be -180 to 180)"

    return True, None


def validate_hash(hash_value: str, algorithm: str = 'sha256') -> Tuple[bool, Optional[str]]:
    """Validate hash format.

    Args:
        hash_value: Hash string
        algorithm: Hash algorithm

    Returns:
        Tuple of (is_valid, error_message)
    """
    expected_lengths = {
        'md5': 32,
        'sha1': 40,
        'sha256': 64,
        'sha512': 128
    }

    expected_len = expected_lengths.get(algorithm.lower())
    if expected_len is None:
        return False, f"Unknown algorithm: {algorithm}"

    if len(hash_value) != expected_len:
        return False, f"Invalid {algorithm} hash length: {len(hash_value)}"

    # Check for valid hex characters
    try:
        int(hash_value, 16)
    except ValueError:
        return False, f"Invalid hex characters in hash"

    return True, None