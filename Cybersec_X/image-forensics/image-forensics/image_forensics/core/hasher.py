"""File hashing module for chain of custody."""

import hashlib
import os
from typing import Dict, List, Tuple


class FileHasher:
    """Calculates cryptographic hashes of files for forensic chain of custody."""

    SUPPORTED_ALGORITHMS = ['md5', 'sha1', 'sha256', 'sha512']

    def __init__(self):
        """Initialize the file hasher."""
        pass

    def hash_file(self, file_path: str, algorithms: List[str] = None) -> Dict[str, str]:
        """Calculate hashes for a file.

        Args:
            file_path: Path to the file
            algorithms: List of hash algorithms to use (default: all)

        Returns:
            Dictionary of algorithm -> hash value
        """
        if algorithms is None:
            algorithms = self.SUPPORTED_ALGORITHMS

        # Validate algorithms
        algorithms = [a.lower() for a in algorithms if a.lower() in self.SUPPORTED_ALGORITHMS]

        if not algorithms:
            raise ValueError(f"No valid algorithms specified. Supported: {self.SUPPORTED_ALGORITHMS}")

        # Initialize hash objects
        hashes = {}
        for algo in algorithms:
            hashes[algo] = hashlib.new(algo)

        # Calculate hashes
        with open(file_path, 'rb') as f:
            while chunk := f.read(65536):  # 64KB chunks
                for algo in algorithms:
                    hashes[algo].update(chunk)

        # Return hex digest for each algorithm
        return {algo: hashes[algo].hexdigest() for algo in algorithms}

    def verify_hash(self, file_path: str, expected_hash: str, algorithm: str = 'sha256') -> bool:
        """Verify a file's hash matches expected value.

        Args:
            file_path: Path to the file
            expected_hash: Expected hash value
            algorithm: Hash algorithm used

        Returns:
            True if hash matches, False otherwise
        """
        if algorithm.lower() not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        computed = self.hash_file(file_path, [algorithm])
        return computed[algorithm.lower()] == expected_hash.lower()

    def hash_directory(self, directory: str, recursive: bool = True) -> Dict[str, Dict[str, str]]:
        """Calculate hashes for all files in a directory.

        Args:
            directory: Path to directory
            recursive: Whether to scan subdirectories

        Returns:
            Dictionary of file paths to their hashes
        """
        results = {}

        if recursive:
            for root, _, files in os.walk(directory):
                for filename in files:
                    file_path = os.path.join(root, filename)
                    try:
                        results[file_path] = self.hash_file(file_path)
                    except Exception as e:
                        results[file_path] = {'error': str(e)}
        else:
            for filename in os.listdir(directory):
                file_path = os.path.join(directory, filename)
                if os.path.isfile(file_path):
                    try:
                        results[file_path] = self.hash_file(file_path)
                    except Exception as e:
                        results[file_path] = {'error': str(e)}

        return results

    def compare_files(self, file1: str, file2: str, algorithm: str = 'sha256') -> bool:
        """Compare two files by hash.

        Args:
            file1: First file path
            file2: Second file path
            algorithm: Hash algorithm to use

        Returns:
            True if files are identical, False otherwise
        """
        hash1 = self.hash_file(file1, [algorithm])
        hash2 = self.hash_file(file2, [algorithm])

        return hash1[algorithm] == hash2[algorithm]

    def get_algorithms(self) -> List[str]:
        """Get list of supported hash algorithms.

        Returns:
            List of algorithm names
        """
        return self.SUPPORTED_ALGORITHMS.copy()