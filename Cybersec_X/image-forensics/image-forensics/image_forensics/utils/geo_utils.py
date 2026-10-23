"""Geolocation utilities for image forensics."""

import math
from typing import Optional, Tuple


def format_gps_coordinates(lat: float, lon: float, lat_ref: str = 'N', lon_ref: str = 'E') -> str:
    """Format GPS coordinates as string.

    Args:
        lat: Latitude in decimal degrees
        lon: Longitude in decimal degrees
        lat_ref: Latitude reference (N/S)
        lon_ref: Longitude reference (E/W)

    Returns:
        Formatted coordinate string
    """
    lat_dir = lat_ref if lat >= 0 else 'S'
    lon_dir = lon_ref if lon >= 0 else 'W'

    return f"{abs(lat):.6f}° {lat_dir}, {abs(lon):.6f}° {lon_dir}"


def gps_to_decimal(coord: Tuple[int, int, int], ref: str) -> Optional[float]:
    """Convert GPS coordinate to decimal degrees.

    Args:
        coord: Tuple of (degrees, minutes, seconds) or rational
        ref: Reference direction (N/S/E/W)

    Returns:
        Decimal degrees or None
    """
    try:
        if isinstance(coord, tuple) and len(coord) == 3:
            degrees = coord[0]
            minutes = coord[1]
            seconds = coord[2]

            # Handle rational format
            if isinstance(degrees, tuple):
                degrees = degrees[0] / degrees[1] if degrees[1] != 0 else 0
            if isinstance(minutes, tuple):
                minutes = minutes[0] / minutes[1] if minutes[1] != 0 else 0
            if isinstance(seconds, tuple):
                seconds = seconds[0] / seconds[1] if seconds[1] != 0 else 0

            decimal = degrees + minutes / 60 + seconds / 3600

            if ref in ['S', 'W']:
                decimal = -decimal

            return decimal
    except:
        pass

    return None


def calculate_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate distance between two GPS points using Haversine formula.

    Args:
        lat1: Latitude of point 1
        lon1: Longitude of point 1
        lat2: Latitude of point 2
        lon2: Longitude of point 2

    Returns:
        Distance in kilometers
    """
    R = 6371  # Earth's radius in kilometers

    lat1_rad = math.radians(lat1)
    lat2_rad = math.radians(lat2)
    delta_lat = math.radians(lat2 - lat1)
    delta_lon = math.radians(lon2 - lon1)

    a = math.sin(delta_lat / 2) ** 2 + \
        math.cos(lat1_rad) * math.cos(lat2_rad) * \
        math.sin(delta_lon / 2) ** 2

    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    return R * c


def is_valid_coordinate(lat: float, lon: float) -> bool:
    """Check if coordinates are valid.

    Args:
        lat: Latitude
        lon: Longitude

    Returns:
        True if valid
    """
    return -90 <= lat <= 90 and -180 <= lon <= 180


def get_cardinal_direction(lat: float, lon: float) -> Tuple[str, str]:
    """Get cardinal directions for coordinates.

    Args:
        lat: Latitude
        lon: Longitude

    Returns:
        Tuple of (latitude_dir, longitude_dir)
    """
    lat_dir = 'N' if lat >= 0 else 'S'
    lon_dir = 'E' if lon >= 0 else 'W'

    return lat_dir, lon_dir


def reverse_geocode(lat: float, lon: float) -> Optional[str]:
    """Placeholder for reverse geocoding.

    Note: Requires external API for actual implementation.

    Args:
        lat: Latitude
        lon: Longitude

    Returns:
        Location string or None
    """
    # This would typically call a geocoding API
    # For now, return None as it requires external service
    return None