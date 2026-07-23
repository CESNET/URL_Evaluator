import hashlib
import os
from pathlib import Path
import logging

logger = logging.getLogger("content_storage")

def storage_path(base_dir: str, content_hash: str) -> Path:
    """
    Derive storage path from SHA-256 hash: first two hex chars / next two hex chars / rest of hash + .blob
    Example: abcdef1234... -> content/ab/cd/abcdef1234...blob
    """
    if not content_hash or len(content_hash) < 4:
        raise ValueError("Invalid content hash")

    content_hash = content_hash.lower()

    # SHA-256 hashes are 64 hex characters; validate the whole string.
    if len(content_hash) != 64 or not all(c in "0123456789abcdef" for c in content_hash):
        raise ValueError("Invalid SHA-256 content hash")

    dir1 = content_hash[0:2]
    dir2 = content_hash[2:4]
    filename = f"{content_hash}.blob"

    return Path(base_dir) / dir1 / dir2 / filename

def save_content(base_dir: str, content: bytes) -> tuple[str, str, str, bool]:
    """
    Save content to disk using SHA-256 deduplication.
    Returns: (sha256, sha1, relative_path, is_new)
    """
    sha256 = hashlib.sha256(content).hexdigest()
    sha1 = hashlib.sha1(content).hexdigest()
    
    path = storage_path(base_dir, sha256)
    
    is_new = False
    if not path.exists():
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "wb") as f:
                f.write(content)
            is_new = True
            logger.debug(f"Saved new content snapshot: {sha256} to {path}")
        except Exception as e:
            logger.exception(f"Error saving content to {path}: {e}")
            raise
    else:
        logger.debug(f"Content snapshot {sha256} already exists")

    return sha256, sha1, str(path.relative_to(base_dir)), is_new

def load_content(base_dir: str, content_hash: str) -> bytes:
    """
    Load content from disk.
    """
    path = storage_path(base_dir, content_hash)
    if not path.exists():
        raise FileNotFoundError(f"Content snapshot {content_hash} not found at {path}")
    
    with open(path, "rb") as f:
        return f.read()

def content_exists(base_dir: str, content_hash: str) -> bool:
    """
    Check if content exists on disk.
    """
    return storage_path(base_dir, content_hash).exists()


def delete_content(base_dir: str, content_hash: str) -> bool:
    """
    Delete a stored content snapshot from disk.

    Returns True if the file existed and was removed, False otherwise.
    Parent directories created by the storage layout are removed if empty.
    """
    path = storage_path(base_dir, content_hash)
    if not path.exists():
        return False

    try:
        path.unlink()
        logger.debug(f"Deleted content snapshot: {content_hash} from {path}")
    except Exception as e:
        logger.exception(f"Error deleting content {content_hash}: {e}")
        raise

    # Clean up empty parent directories (up to base_dir).
    try:
        for parent in path.parents:
            if parent == Path(base_dir).resolve():
                break
            try:
                parent.rmdir()
            except OSError:
                # Directory not empty or already removed; stop ascending.
                break
    except Exception:
        # Non-fatal cleanup; the snapshot itself is already gone.
        pass

    return True
