import hashlib
from pathlib import Path


def calculate_sha256(file_path):
    """Calculate SHA-256 hash of a file."""

    digest = hashlib.sha256()

    with Path(file_path).open("rb") as source:
        for block in iter(lambda: source.read(4096), b""):
            digest.update(block)

    return digest.hexdigest()


def compare_hashes(original_hash, current_hash):
    """Compare two SHA-256 hash values."""

    return original_hash.lower() == current_hash.lower()
