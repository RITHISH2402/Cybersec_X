"""Forensic analysis module for image metadata."""

import os
from datetime import datetime
from typing import Dict, Any, List


class ForensicAnalyzer:
    """Performs forensic analysis on extracted image metadata."""

    # Common image editing software
    EDITING_SOFTWARE = [
        'Adobe Photoshop', 'GIMP', 'Paint.NET', 'CorelDRAW',
        'Illustrator', 'Lightroom', 'Capture One', 'Affinity Photo',
        'ImageMagick', 'GraphicConverter', 'Preview', 'Photos',
        'Paint', 'IrfanView', 'XnView', 'Aperture', 'Darktable'
    ]

    # Software indicators in EXIF
    SOFTWARE_INDICATORS = [
        'photoshop', 'gimp', 'paint', 'corel', 'adobe',
        'imagemagick', 'graphicconverter', 'affinity'
    ]

    def __init__(self, verbose: bool = False):
        """Initialize the forensic analyzer.

        Args:
            verbose: Enable verbose output
        """
        self.verbose = verbose
        self.risk_weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 1,
            'info': 0
        }

    def analyze(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive forensic analysis on metadata.

        Args:
            metadata: Extracted metadata dictionary

        Returns:
            Analysis results with anomalies and risk assessment
        """
        analysis = {
            'filename': metadata.get('filename'),
            'timestamp_analyzed': datetime.now().isoformat(),
            'risk_level': 'unknown',
            'risk_score': 0,
            'anomalies': [],
            'findings': [],
            'metadata_summary': {},
            'timeline': {},
            'indicators': {}
        }

        # Perform various checks
        self._check_timestamp_anomalies(metadata, analysis)
        self._check_gps_anomalies(metadata, analysis)
        self._check_software_indicators(metadata, analysis)
        self._check_file_structure(metadata, analysis)
        self._check_metadata_consistency(metadata, analysis)
        self._check_image_manipulation_indicators(metadata, analysis)
        self._check_dimensions_aspect_ratio(metadata, analysis)

        # Calculate risk score and level
        self._calculate_risk_level(analysis)

        # Build summary
        self._build_summary(metadata, analysis)

        return analysis

    def _check_timestamp_anomalies(self, metadata: Dict, analysis: Dict) -> None:
        """Check for timestamp inconsistencies."""
        exif = metadata.get('exif', {})
        file_info = metadata.get('file_info', {})

        timestamps = {}

        # Extract EXIF timestamps
        for key in ['DateTime', 'DateTimeOriginal', 'DateTimeDigitized']:
            if key in exif:
                timestamps[key] = exif[key]

        # Extract file timestamps
        for key in ['created', 'modified', 'accessed']:
            if key in file_info:
                timestamps[f'file_{key}'] = file_info[key]

        analysis['timeline'] = timestamps

        # Check for date anomalies
        try:
            date_time_orig = exif.get('DateTimeOriginal')
            date_time = exif.get('DateTime')
            file_modified = file_info.get('modified')

            if date_time_orig and file_modified:
                # Parse dates
                exif_date = self._parse_exif_datetime(date_time_orig)
                file_date = datetime.fromisoformat(file_modified.replace('Z', '+00:00'))

                if exif_date and file_date:
                    # Check if file modification is significantly before EXIF date
                    diff = (exif_date - file_date).days

                    if diff > 30:
                        analysis['anomalies'].append({
                            'type': 'Timestamp Anomaly',
                            'severity': 'medium',
                            'description': f"EXIF date is {diff} days after file modification - possible metadata tampering"
                        })
                    elif diff < -30:
                        analysis['anomalies'].append({
                            'type': 'Timestamp Anomaly',
                            'severity': 'medium',
                            'description': f"EXIF date is {abs(diff)} days before file modification"
                        })
        except Exception as e:
            if self.verbose:
                print(f"Timestamp analysis error: {e}")

        # Check for future dates
        future_dates = []
        current_time = datetime.now()

        for key, value in timestamps.items():
            if isinstance(value, str) and 'file_' not in key:
                try:
                    parsed = self._parse_exif_datetime(value)
                    if parsed and parsed > current_time:
                        future_dates.append(f"{key}: {value}")
                except:
                    pass

        if future_dates:
            analysis['anomalies'].append({
                'type': 'Future Timestamp',
                'severity': 'high',
                'description': f"Future dates detected: {', '.join(future_dates)}"
            })

        if not timestamps:
            analysis['findings'].append("No timestamp data available for analysis")

    def _parse_exif_datetime(self, dt_string: str) -> datetime:
        """Parse EXIF datetime string format."""
        try:
            # EXIF format: "YYYY:MM:DD HH:MM:SS"
            return datetime.strptime(dt_string, "%Y:%m:%d %H:%M:%S")
        except:
            try:
                return datetime.strptime(dt_string, "%Y-%m-%d %H:%M:%S")
            except:
                return None

    def _check_gps_anomalies(self, metadata: Dict, analysis: Dict) -> None:
        """Check for GPS data anomalies."""
        gps = metadata.get('gps', {})

        if not gps:
            analysis['findings'].append("No GPS data present")
            return

        # Check for GPS data
        lat = gps.get('latitude_decimal')
        lon = gps.get('longitude_decimal')

        if lat is None or lon is None:
            analysis['anomalies'].append({
                'type': 'GPS Data Incomplete',
                'severity': 'low',
                'description': 'GPS coordinates present but cannot be parsed to decimal format'
            })
            return

        # Check for invalid coordinates
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            analysis['anomalies'].append({
                'type': 'Invalid GPS Coordinates',
                'severity': 'critical',
                'description': f"GPS coordinates out of valid range: {lat}, {lon}"
            })

        # Check for common locations
        if self._is_suspicious_location(lat, lon):
            analysis['anomalies'].append({
                'type': 'Suspicious GPS Location',
                'severity': 'medium',
                'description': f"Coordinates point to suspicious or unusual location: {lat}, {lon}"
            })

        # Check for zero coordinates (often indicates no fix)
        if lat == 0 and lon == 0:
            analysis['anomalies'].append({
                'type': 'Zero Coordinates',
                'severity': 'low',
                'description': 'GPS coordinates are exactly 0,0 - likely no GPS fix'
            })

        # Check altitude anomalies
        altitude = gps.get('altitude')
        if altitude:
            try:
                alt_val = float(str(altitude).split('/')[0])
                if alt_val < -500 or alt_val > 50000:
                    analysis['anomalies'].append({
                        'type': 'Invalid Altitude',
                        'severity': 'medium',
                        'description': f"Unrealistic altitude: {alt_val} meters"
                    })
            except:
                pass

    def _is_suspicious_location(self, lat: float, lon: float) -> bool:
        """Check for suspicious locations."""
        # Check for locations in restricted areas or unusual locations
        suspicious_ranges = [
            # North pole area
            (85, 90, -180, 180),
            # South pole area
            (-90, -85, -180, 180),
        ]

        for lat_min, lat_max, lon_min, lon_max in suspicious_ranges:
            if lat_min <= lat <= lat_max and lon_min <= lon <= lon_max:
                return True

        return False

    def _check_software_indicators(self, metadata: Dict, analysis: Dict) -> None:
        """Check for image editing software indicators."""
        software = metadata.get('software', {})
        exif = metadata.get('exif', {})

        detected_software = []

        # Check software field
        software_value = software.get('Software', '')
        if software_value:
            for sw in self.EDITING_SOFTWARE:
                if sw.lower() in software_value.lower():
                    detected_software.append(sw)

        # Check EXIF for software hints
        for key, value in exif.items():
            if isinstance(value, str):
                value_lower = value.lower()
                for indicator in self.SOFTWARE_INDICATORS:
                    if indicator in value_lower:
                        detected_software.append(f"Detected: {indicator}")

        # Check for multiple processing
        processing_history = exif.get('ProcessingSoftware', '')
        if processing_history:
            detected_software.append(f"Processed by: {processing_history}")

        if detected_software:
            unique_software = list(set(detected_software))
            analysis['indicators']['editing_software'] = unique_software
            analysis['findings'].append(f"Editing software detected: {', '.join(unique_software)}")

            # Multiple software or complex workflow
            if len(unique_software) > 1:
                analysis['anomalies'].append({
                    'type': 'Multiple Software',
                    'severity': 'medium',
                    'description': f"Image processed by multiple software: {', '.join(unique_software)}"
                })

    def _check_file_structure(self, metadata: Dict, analysis: Dict) -> None:
        """Check for file structure issues."""
        basic_info = metadata.get('basic_info', {})

        # Check image dimensions
        width = basic_info.get('width', 0)
        height = basic_info.get('height', 0)

        if width == 0 or height == 0:
            analysis['anomalies'].append({
                'type': 'Invalid Dimensions',
                'severity': 'critical',
                'description': 'Image has zero dimensions'
            })

        # Check for unusually small images
        if width < 50 or height < 50:
            analysis['anomalies'].append({
                'type': 'Unusually Small Image',
                'severity': 'low',
                'description': f'Image dimensions are unusually small: {width}x{height}'
            })

        # Check file size vs dimensions ratio
        file_size = metadata.get('file_info', {}).get('size_bytes', 0)
        if file_size > 0 and width > 0 and height > 0:
            pixels = width * height
            bytes_per_pixel = file_size / pixels

            # Extremely low bytes per pixel might indicate heavy compression
            if bytes_per_pixel < 0.1:
                analysis['findings'].append(f"Image heavily compressed: {bytes_per_pixel:.3f} bytes/pixel")

            # Unusually high might indicate embedded data
            if bytes_per_pixel > 50:
                analysis['anomalies'].append({
                    'type': 'Unusual File Size',
                    'severity': 'medium',
                    'description': f"File size unusually large for dimensions: {bytes_per_pixel:.1f} bytes/pixel"
                })

    def _check_metadata_consistency(self, metadata: Dict, analysis: Dict) -> None:
        """Check metadata field consistency."""
        exif = metadata.get('exif', {})

        # Check make/model consistency
        make = exif.get('Make', '')
        model = exif.get('Model', '')

        if make and model:
            # Check if model contains make (common inconsistency)
            if make.lower() not in model.lower() and model.lower() not in make.lower():
                analysis['anomalies'].append({
                    'type': 'Make/Model Mismatch',
                    'severity': 'low',
                    'description': f"Make '{make}' and Model '{model}' may be inconsistent"
                })

        # Check for missing expected fields
        expected_fields = ['Make', 'Model', 'DateTime']
        missing = [f for f in expected_fields if f not in exif]

        if missing:
            analysis['findings'].append(f"Missing expected metadata: {', '.join(missing)}")

    def _check_image_manipulation_indicators(self, metadata: Dict, analysis: Dict) -> None:
        """Check for potential image manipulation indicators."""
        exif = metadata.get('exif', {})

        indicators = []

        # Check for specific manipulation indicators
        if exif.get('Software'):
            indicators.append(f"Software: {exif['Software']}")

        # Check for modified EXIF
        if 'Software' in exif:
            indicators.append("EXIF Software field present (possible editing)")

        # Check for unusual tags
        unusual_tags = ['MakerNote', 'UserComment', 'ImageDescription']
        present_unusual = [t for t in unusual_tags if t in exif]

        if present_unusual:
            indicators.append(f"Unusual metadata tags found: {', '.join(present_unusual)}")

        if indicators:
            analysis['indicators']['manipulation'] = indicators

            if len(indicators) >= 2:
                analysis['anomalies'].append({
                    'type': 'Potential Manipulation',
                    'severity': 'medium',
                    'description': 'Multiple manipulation indicators detected'
                })

    def _check_dimensions_aspect_ratio(self, metadata: Dict, analysis: Dict) -> None:
        """Check aspect ratio for common manipulation patterns."""
        basic_info = metadata.get('basic_info', {})

        width = basic_info.get('width', 0)
        height = basic_info.get('height', 0)
        aspect_ratio = basic_info.get('aspect_ratio', 0)

        if width == 0 or height == 0:
            return

        # Check for common aspect ratios
        common_ratios = {
            (1, 1): "1:1 (Square)",
            (4, 3): "4:3 (Standard)",
            (16, 9): "16:9 (Widescreen)",
            (3, 2): "3:2 (Photo)",
            (21, 9): "21:9 (Ultrawide)"
        }

        # Find closest common ratio
        for (w, h), name in common_ratios.items():
            expected = w / h
            if abs(aspect_ratio - expected) < 0.05:
                analysis['findings'].append(f"Aspect ratio: {name}")
                break

    def _calculate_risk_level(self, analysis: Dict) -> None:
        """Calculate overall risk level based on anomalies."""
        total_score = 0

        for anomaly in analysis['anomalies']:
            severity = anomaly.get('severity', 'info')
            total_score += self.risk_weights.get(severity, 0)

        analysis['risk_score'] = total_score

        if total_score >= 15:
            analysis['risk_level'] = 'critical'
        elif total_score >= 10:
            analysis['risk_level'] = 'high'
        elif total_score >= 5:
            analysis['risk_level'] = 'medium'
        elif total_score >= 1:
            analysis['risk_level'] = 'low'
        else:
            analysis['risk_level'] = 'minimal'

    def _build_summary(self, metadata: Dict, analysis: Dict) -> None:
        """Build metadata summary."""
        exif = metadata.get('exif', {})
        gps = metadata.get('gps', {})
        basic_info = metadata.get('basic_info', {})

        summary = {
            'total_exif_fields': len(exif),
            'has_gps': bool(gps and 'latitude_decimal' in gps),
            'has_editing_software': bool(metadata.get('software', {})),
            'anomalies_count': len(analysis['anomalies']),
            'findings_count': len(analysis['findings']),
            'image_dimensions': basic_info.get('dimensions', 'Unknown')
        }

        analysis['metadata_summary'] = summary