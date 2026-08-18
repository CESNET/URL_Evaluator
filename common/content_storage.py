"""
File-system content storage for URL Evaluator.

Binary payloads (downloaded URL content / malware samples) are stored on
disk, deduplicated by their SHA-256 digest. The database only keeps metadata
plus the relative ``storage_path`` produced here, so identical content served
by multiple URLs results in a single on-disk file.

Layout:
    <base_dir>/<aa>/<bb>/<full_sha256>.blob

where ``aa``/``bb`` are the first two pairs of hex characters of the digest.
Files are immutable — the same content is never written twice.
"""

import os
import hashlib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

BLOB_SUFFIX = ".blob"


def compute_hashes(content: bytes):
    """Return (sha1, sha256) hex digests of *content*."""
    sha1 = hashlib.sha1(content).hexdigest()
    sha256 = hashlib.sha256(content).hexdigest()
    return sha1, sha256


def storage_path(base_dir, content_hash: str) -> Path:
    """Return the absolute :class:`Path` where *content_hash* would be stored.

    The path is derived purely from the hash, so it is stable and independent
    of when/by whom the content was downloaded.
    """
    rel = relative_storage_path(content_hash)
    return Path(base_dir) / rel


def relative_storage_path(content_hash: str) -> str:
    """Return the relative storage path (``aa/bb/<hash>.blob``) for *content_hash*."""
    if not content_hash or len(content_hash) < 4:
        raise ValueError(f"content_hash too short to build storage path: {content_hash!r}")
    return os.path.join(content_hash[0:2], content_hash[2:4], content_hash + BLOB_SUFFIX)


def content_exists(base_dir, content_hash: str) -> bool:
    """Return True if a blob for *content_hash* already exists on disk."""
    return storage_path(base_dir, content_hash).is_file()


def save_content(base_dir, content: bytes):
    """Persist *content* under *base_dir*, deduplicated by SHA-256.

    :param base_dir: base storage directory (from config ``content_storage_path``)
    :param content: raw downloaded bytes
    :returns: ``(sha256, sha1, relative_path, is_new)`` where ``is_new`` is True
              when a file was actually written (False on dedup-hit).
    """
    logger.debug(f"save_content: hashing {len(content)} bytes")
    sha1, sha256 = compute_hashes(content)
    dest = storage_path(base_dir, sha256)
    rel = relative_storage_path(sha256)
    logger.debug(f"save_content: sha256={sha256}, target={dest}")

    if dest.is_file():
        logger.debug(f"Content deduplicated (already stored): {sha256}")
        return sha256, sha1, rel, False

    dest.parent.mkdir(parents=True, exist_ok=True)
    # Write atomically: tmp file then rename, so concurrent readers never see a
    # partially-written blob.
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    logger.debug(f"save_content: writing tmp file {tmp}")
    with open(tmp, "wb") as fh:
        fh.write(content)
    os.replace(tmp, dest)
    logger.info(f"Stored new content blob: {rel} ({len(content)} bytes)")
    logger.debug(f"save_content: atomically moved to {dest}")
    return sha256, sha1, rel, True


def load_content(base_dir, content_hash: str) -> bytes:
    """Read and return the stored bytes for *content_hash*.

    :raises FileNotFoundError: if no blob exists for the given hash.
    """
    path = storage_path(base_dir, content_hash)
    with open(path, "rb") as fh:
        return fh.read()


def delete_content(base_dir, content_hash: str) -> bool:
    """Remove the blob for *content_hash* if present. Returns True when removed.

    Prune any now-empty parent directories as well.
    """
    path = storage_path(base_dir, content_hash)
    if not path.is_file():
        return False
    path.unlink()
    # Try to clean up the (now possibly empty) aa/bb directories.
    for parent in (path.parent, path.parent.parent):
        try:
            parent.rmdir()
        except OSError:
            pass
    return True
