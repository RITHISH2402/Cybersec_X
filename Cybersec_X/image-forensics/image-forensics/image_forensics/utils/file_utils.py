"""File utilities for image forensics."""

import os
from pathlib import Path
from typing import List


# Supported image extensions
IMAGE_EXTENSIONS = {
    '.jpg', '.jpeg', '.png', '.tiff', '.tif',
    '.webp', '.heic', '.heif', '.gif', '.bmp'
}


def get_image_files(directory: str, recursive: bool = False) -> List[Path]:
    """Get list of image files in directory.

    Args:
        directory: Directory path
        recursive: Whether to search recursively

    Returns:
        List of image file paths
    """
    dir_path = Path(directory)
    image_files = []

    if recursive:
        for ext in IMAGE_EXTENSIONS:
            image_files.extend(dir_path.rglob(f"*{ext}"))
    else:
        for ext in IMAGE_EXTENSIONS:
            image_files.extend(dir_path.glob(f"*{ext}"))

    return sorted(image_files)


def get_file_info(file_path: str) -> dict:
    """Get file information.

    Args:
        file_path: Path to file

    Returns:
        Dictionary with file info
    """
    from datetime import datetime

    stat = os.stat(file_path)
    return {
        'size': stat.st_size,
        'created': datetime.fromtimestamp(stat.st_ctime),
        'modified': datetime.fromtimestamp(stat.st_mtime),
        'accessed': datetime.fromtimestamp(stat.st_atime)
    }


def is_image_file(file_path: str) -> bool:
    """Check if file is a supported image.

    Args:
        file_path: Path to file

    Returns:
        True if image file
    """
    ext = Path(file_path).suffix.lower()
    return ext in IMAGE_EXTENSIONS


def format_size(size_bytes: int) -> str:
    """Format file size.

    Args:
        size_bytes: Size in bytes

    Returns:
        Formatted size string
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} TB"