# Image Metadata Extraction and Analysis System

A comprehensive digital forensic investigation tool for extracting, analyzing, and reporting on image metadata.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Extract metadata from image
python -m image_forensics extract photo.jpg

# Analyze with forensic checks
python -m image_forensics analyze photo.jpg

# Generate report
python -m image_forensics report photo.jpg -o report.html --format html

# Hash calculation
python -m image_forensics hash photo.jpg
```

## Features

- EXIF, IPTC, XMP metadata extraction
- GPS coordinate analysis
- Forensic anomaly detection
- Batch processing
- Multiple output formats (JSON, HTML, CSV, Table)