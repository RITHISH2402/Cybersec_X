"""Unit tests for MetadataExtractor and other core modules."""

import unittest
import os
from pathlib import Path
from image_forensics.core.extractor import MetadataExtractor
from image_forensics.core.analyzer import ForensicAnalyzer
from image_forensics.core.hasher import FileHasher
from image_forensics.utils.validators import validate_image_file, validate_coordinates, validate_hash


class TestImageForensics(unittest.TestCase):
    """Test suite for Image Forensics Analyzer."""

    def setUp(self):
        self.test_dir = Path(__file__).parent.parent.parent
        self.test_image = self.test_dir / "test_image.jpg"
        self.extractor = MetadataExtractor()
        self.analyzer = ForensicAnalyzer()
        self.hasher = FileHasher()

    def test_validators(self):
        """Test validation utility functions."""
        # Test image file validator
        is_valid, err = validate_image_file(str(self.test_image))
        self.assertTrue(is_valid)
        self.assertIsNone(err)

        is_valid, err = validate_image_file("nonexistent.jpg")
        self.assertFalse(is_valid)
        self.assertIn("File not found", err)

        # Test coordinates validator
        is_valid, err = validate_coordinates(45.0, -93.0)
        self.assertTrue(is_valid)
        self.assertIsNone(err)

        is_valid, err = validate_coordinates(100.0, -93.0)
        self.assertFalse(is_valid)
        self.assertIn("Invalid latitude", err)

        # Test hash validator
        is_valid, err = validate_hash("8d9042924e9c916cc2e1bd6d92a0870b", "md5")
        self.assertTrue(is_valid)
        self.assertIsNone(err)

        is_valid, err = validate_hash("invalid-hash", "md5")
        self.assertFalse(is_valid)

    def test_metadata_extraction(self):
        """Test extraction of metadata from the test image."""
        if not self.test_image.exists():
            self.skipTest("test_image.jpg not found in root directory")

        metadata = self.extractor.extract(str(self.test_image))
        self.assertEqual(metadata["filename"], "test_image.jpg")
        self.assertIn("basic_info", metadata)
        self.assertEqual(metadata["basic_info"]["format"], "JPEG")
        self.assertIn("exif", metadata)
        self.assertEqual(metadata["exif"].get("Model"), "EOS 80D")

    def test_forensic_analyzer(self):
        """Test analysis functions on the metadata."""
        if not self.test_image.exists():
            self.skipTest("test_image.jpg not found in root directory")

        metadata = self.extractor.extract(str(self.test_image))
        analysis = self.analyzer.analyze(metadata)
        self.assertEqual(analysis["filename"], "test_image.jpg")
        self.assertIn("risk_level", analysis)
        self.assertIn("risk_score", analysis)
        self.assertIn("anomalies", analysis)

        # Anomaly verification
        anomalies = [a["type"] for a in analysis["anomalies"]]
        self.assertIn("Potential Manipulation", anomalies)

    def test_file_hasher(self):
        """Test hashing functionalities."""
        if not self.test_image.exists():
            self.skipTest("test_image.jpg not found in root directory")

        hashes = self.hasher.hash_file(str(self.test_image))
        self.assertIn("md5", hashes)
        self.assertIn("sha256", hashes)
        self.assertEqual(hashes["md5"], "8d9042924e9c916cc2e1bd6d92a0870b")

        # Verify hash function
        self.assertTrue(self.hasher.verify_hash(str(self.test_image), hashes["md5"], "md5"))
        self.assertTrue(self.hasher.verify_hash(str(self.test_image), hashes["sha256"], "sha256"))

    def test_png_extraction(self):
        """Test extraction of metadata from a PNG image."""
        from PIL import Image
        temp_png = self.test_dir / "temp_test_image.png"
        try:
            # Create a simple 1x1 PNG image
            img = Image.new("RGB", (1, 1), color="red")
            img.save(temp_png, "PNG")

            # Extract metadata
            metadata = self.extractor.extract(str(temp_png))
            self.assertEqual(metadata["filename"], "temp_test_image.png")
            self.assertIn("basic_info", metadata)
            self.assertEqual(metadata["basic_info"]["format"], "PNG")
            self.assertIn("png", metadata)
            self.assertNotIn("error", metadata)
        finally:
            if temp_png.exists():
                temp_png.unlink()


if __name__ == "__main__":
    unittest.main()
