"""Metadata extraction module for image forensics."""

import os
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

try:
    import piexif
    PIEXIF_AVAILABLE = True
except ImportError:
    PIEXIF_AVAILABLE = False


class MetadataExtractor:
    """Extracts metadata from various image formats."""

    def __init__(self, verbose: bool = False):
        """Initialize the metadata extractor.

        Args:
            verbose: Enable verbose output
        """
        self.verbose = verbose
        self.supported_formats = {'.jpg', '.jpeg', '.png', '.tiff', '.tif', '.webp', '.heic', '.gif'}

    def extract(self, file_path: str) -> Dict[str, Any]:
        """Extract all metadata from an image file.

        Args:
            file_path: Path to the image file

        Returns:
            Dictionary containing all extracted metadata
        """
        result = {
            'filename': os.path.basename(file_path),
            'file_path': os.path.abspath(file_path),
            'timestamp': datetime.now().isoformat(),
            'basic_info': {},
            'exif': {},
            'gps': {},
            'iptc': {},
            'xmp': {},
            'png': {},
            'software': {},
            'file_info': {},
            'thumbnail': None
        }

        try:
            # Get basic file info
            result['file_info'] = self._get_file_info(file_path)

            # Open image and get basic info
            with Image.open(file_path) as img:
                result['basic_info'] = self._get_basic_image_info(img)

                # Extract EXIF data
                exif_data = self._extract_exif(img)
                result['exif'] = exif_data.get('exif', {})
                result['gps'] = exif_data.get('gps', {})

                # Check for thumbnail
                thumbnail = self._extract_thumbnail(img)
                if thumbnail:
                    result['thumbnail'] = thumbnail

            # Extract additional metadata based on file type
            ext = Path(file_path).suffix.lower()
            if ext in {'.jpg', '.jpeg', '.tiff', '.tif'}:
                self._extract_advanced_exif(file_path, result)
            elif ext == '.png':
                self._extract_png_metadata(file_path, result)

            # Extract IPTC if available
            self._extract_iptc(file_path, result)

        except Exception as e:
            result['error'] = str(e)
            if self.verbose:
                print(f"Error extracting metadata: {e}")

        return result

    def _get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Get file system information."""
        stat = os.stat(file_path)
        return {
            'size_bytes': stat.st_size,
            'size_human': self._format_size(stat.st_size),
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'accessed': datetime.fromtimestamp(stat.st_atime).isoformat()
        }

    def _format_size(self, size: int) -> str:
        """Format file size to human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"

    def _get_basic_image_info(self, img: Image.Image) -> Dict[str, Any]:
        """Extract basic image information."""
        info = {
            'format': img.format,
            'mode': img.mode,
            'width': img.width,
            'height': img.height,
            'dimensions': f"{img.width} x {img.height}",
            'aspect_ratio': round(img.width / img.height, 2) if img.height > 0 else 0
        }

        # Get DPI info if available
        if hasattr(img, 'info'):
            dpi = img.info.get('dpi')
            if dpi:
                info['dpi'] = dpi

        return info

    def _extract_exif(self, img: Image.Image) -> Dict[str, Any]:
        """Extract EXIF data from image."""
        result = {'exif': {}, 'gps': {}}

        exif_data = img.getexif()
        if not exif_data:
            return result

        for tag_id, value in exif_data.items():
            tag = TAGS.get(tag_id, tag_id)

            # Handle GPS data separately
            if tag == 'GPSInfo':
                gps_data = {}
                if isinstance(value, dict):
                    for gps_tag_id, gps_value in value.items():
                        gps_tag = GPSTAGS.get(gps_tag_id, gps_tag_id)
                        gps_data[gps_tag] = gps_value
                elif hasattr(value, 'items'):
                    try:
                        for gps_tag_id, gps_value in value.items():
                            gps_tag = GPSTAGS.get(gps_tag_id, gps_tag_id)
                            gps_data[gps_tag] = gps_value
                    except:
                        pass
                result['gps'] = self._process_gps_data(gps_data)
            else:
                # Convert bytes to readable format
                if isinstance(value, bytes):
                    try:
                        value = value.decode('utf-8', errors='ignore')
                    except:
                        value = f"<{len(value)} bytes>"
                result['exif'][tag] = str(value)

        return result

    def _process_gps_data(self, gps_data: Dict) -> Dict[str, Any]:
        """Process GPS data and convert to decimal coordinates."""
        processed = {}

        for key, value in gps_data.items():
            if key == 'GPSLatitude':
                processed['latitude'] = self._convert_gps_coordinate(value)
            elif key == 'GPSLatitudeRef':
                processed['latitude_ref'] = value
            elif key == 'GPSLongitude':
                processed['longitude'] = self._convert_gps_coordinate(value)
            elif key == 'GPSLongitudeRef':
                processed['longitude_ref'] = value
            elif key == 'GPSAltitude':
                processed['altitude'] = str(value)
            elif key == 'GPSAltitudeRef':
                processed['altitude_ref'] = 'Above sea level' if value == 0 else 'Below sea level'
            elif key == 'GPSTimeStamp':
                processed['timestamp'] = str(value)
            elif key == 'GPSDateStamp':
                processed['datestamp'] = str(value)
            else:
                processed[key] = str(value)

        # Calculate decimal coordinates if possible
        if 'latitude' in processed and 'longitude' in processed:
            lat = processed.get('latitude')
            lon = processed.get('longitude')
            lat_ref = processed.get('latitude_ref', 'N')
            lon_ref = processed.get('longitude_ref', 'E')

            if lat and lon:
                try:
                    lat_dec = self._gps_to_decimal(lat, lat_ref)
                    lon_dec = self._gps_to_decimal(lon, lon_ref)
                    processed['latitude_decimal'] = lat_dec
                    processed['longitude_decimal'] = lon_dec
                except:
                    pass

        return processed

    def _convert_gps_coordinate(self, coord: tuple) -> str:
        """Convert GPS coordinate tuple to string."""
        if isinstance(coord, tuple) and len(coord) == 3:
            return f"{coord[0]}/{coord[1]}/{coord[2]}"
        return str(coord)

    def _gps_to_decimal(self, coord_str: str, ref: str) -> Optional[float]:
        """Convert GPS coordinate to decimal degrees."""
        try:
            if '/' in coord_str:
                parts = coord_str.split('/')
                if len(parts) == 3:
                    degrees = int(parts[0])
                    minutes = int(parts[1])
                    seconds = int(parts[2])
                    decimal = degrees + minutes / 60 + seconds / 3600

                    if ref in ['S', 'W']:
                        decimal = -decimal
                    return decimal
        except:
            pass
        return None

    def _extract_advanced_exif(self, file_path: str, result: Dict) -> None:
        """Extract advanced EXIF using piexif for JPEG files."""
        if not PIEXIF_AVAILABLE:
            return

        try:
            exif_dict = piexif.load(file_path)

            # Extract software/make info
            if '0th' in exif_dict:
                zeroth = exif_dict['0th']
                software_tags = [piexif.ImageIFD.Software, piexif.ImageIFD.Make,
                                piexif.ImageIFD.Model, piexif.ImageIFD.Artist,
                                piexif.ImageIFD.Copyright]

                for tag in software_tags:
                    if tag in zeroth:
                        tag_name = piexif.TAGS['Image'].get(tag, {}).get('name', str(tag))
                        result['software'][tag_name] = str(zeroth[tag])

            # Extract XMP data
            if 'Exif' in exif_dict:
                exif_ifd = exif_dict['Exif']
                if piexif.ExifIFD.MakerNote in exif_ifd:
                    result['xmp']['MakerNote'] = str(exif_ifd[piexif.ExifIFD.MakerNote])[:100]

        except Exception as e:
            if self.verbose:
                print(f"Advanced EXIF extraction error: {e}")

    def _extract_png_metadata(self, file_path: str, result: Dict) -> None:
        """Extract PNG text chunks."""
        try:
            with Image.open(file_path) as img:
                if hasattr(img, 'info'):
                    # Extract common PNG metadata
                    png_fields = ['dpi', 'chromaticity', 'gamma', 'transparency']
                    result.setdefault('png', {})
                    for field in png_fields:
                        if field in img.info:
                            result['png'][field] = str(img.info[field])

                    # Extract text chunks
                    if hasattr(img, 'text'):
                        for key, value in img.text.items():
                            result['iptc'][key] = value

        except Exception as e:
            if self.verbose:
                print(f"PNG metadata extraction error: {e}")

    def _extract_iptc(self, file_path: str, result: Dict) -> None:
        """Extract IPTC metadata if available."""
        # IPTC data would typically be in the image info
        # This is a placeholder for more advanced IPTC extraction
        try:
            with Image.open(file_path) as img:
                if hasattr(img, 'info'):
                    # Check for common IPTC-like fields
                    iptc_keys = ['Author', 'Copyright', 'Description', 'Title']
                    for key in iptc_keys:
                        if key in img.info:
                            result['iptc'][key] = str(img.info[key])
        except:
            pass

    def _extract_thumbnail(self, img: Image.Image) -> Optional[str]:
        """Extract thumbnail if available."""
        try:
            if hasattr(img, '_getexif') and img._getexif():
                exif_data = img._getexif()
                if exif_data:
                    # Look for thumbnail in EXIF
                    for tag_id, value in exif_data.items():
                        if tag_id == 0x201:  # JPEGInterchangeFormat
                            # Thumbnail data present
                            return "Thumbnail data available"
        except:
            pass
        return None

    def is_supported(self, file_path: str) -> bool:
        """Check if file format is supported."""
        ext = Path(file_path).suffix.lower()
        return ext in self.supported_formats