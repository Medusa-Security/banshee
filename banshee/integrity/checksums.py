"""
Checksum utilities for memory entry integrity verification.
"""

import hashlib
from typing import Literal

HashAlgorithm = Literal["sha256", "sha512", "blake2b"]


def compute_checksum(content: str, algorithm: HashAlgorithm = "sha256") -> str:
    """Compute a cryptographic checksum of a memory entry's content.

    Args:
        content: The raw text content to hash.
        algorithm: Hash algorithm to use. Defaults to sha256.

    Returns:
        Hex-encoded digest string.

    Raises:
        ValueError: If an unsupported algorithm is specified.
    """
    content_bytes = content.encode("utf-8")

    match algorithm:
        case "sha256":
            digest = hashlib.sha256(content_bytes).hexdigest()
        case "sha512":
            digest = hashlib.sha512(content_bytes).hexdigest()
        case "blake2b":
            digest = hashlib.blake2b(content_bytes).hexdigest()
        case _:
            raise ValueError(f"Unsupported hash algorithm: {algorithm!r}")

    return f"{algorithm}:{digest}"


def verify_checksum(content: str, expected_checksum: str) -> bool:
    """Verify a content string matches its expected checksum.

    Args:
        content: The content to verify.
        expected_checksum: Previously stored checksum in the format ``algorithm:digest``.

    Returns:
        True if the checksum matches, False otherwise.

    Raises:
        ValueError: If the checksum format is invalid.
    """
    if ":" not in expected_checksum:
        raise ValueError(
            f"Invalid checksum format {expected_checksum!r}. Expected 'algorithm:digest'."
        )

    algorithm, _ = expected_checksum.split(":", 1)
    actual = compute_checksum(content, algorithm=algorithm)  # type: ignore[arg-type]
    return actual == expected_checksum
