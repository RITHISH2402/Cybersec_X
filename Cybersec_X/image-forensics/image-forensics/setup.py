"""Setup script for Image Forensics Analyzer."""

from setuptools import setup, find_packages
from pathlib import Path

# Read long description from README
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text() if readme_file.exists() else ""

setup(
    name="image-forensics",
    version="1.0.0",
    description="Image Metadata Extraction and Analysis System for Digital Forensic Investigation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Digital Forensics Team",
    author_email="forensics@example.com",
    url="https://github.com/example/image-forensics",
    packages=find_packages(),
    install_requires=[
        "pillow>=10.0.0",
        "piexif>=1.0.3",
        "python-magic>=0.4.27",
        "colorama>=0.4.6",
        "click>=8.1.0",
        "tqdm>=4.65.0",
        "jinja2>=3.1.0",
    ],
    entry_points={
        "console_scripts": [
            "image-forensics=image_forensics.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Legal Industry",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: GIS",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
)