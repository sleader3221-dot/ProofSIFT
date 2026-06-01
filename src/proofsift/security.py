from __future__ import annotations

import hashlib
import os
from pathlib import Path


class PolicyViolation(RuntimeError):
    pass


class SafePathPolicy:
    """Read evidence from approved roots and write only into the case output area."""

    def __init__(self, evidence_roots: list[Path], output_root: Path):
        self.evidence_roots = [p.resolve() for p in evidence_roots]
        self.output_root = output_root.resolve()
        self.output_root.mkdir(parents=True, exist_ok=True)

    def validate_read(self, path: Path) -> Path:
        resolved = path.resolve()
        if not any(_is_relative_to(resolved, root) for root in self.evidence_roots):
            raise PolicyViolation(f"read path is outside registered evidence roots: {resolved}")
        if not resolved.exists():
            raise PolicyViolation(f"read path does not exist: {resolved}")
        return resolved

    def validate_write(self, path: Path) -> Path:
        resolved = path.resolve()
        if not _is_relative_to(resolved, self.output_root):
            raise PolicyViolation(f"write path is outside output root: {resolved}")
        resolved.parent.mkdir(parents=True, exist_ok=True)
        return resolved

    def assert_no_evidence_write(self) -> bool:
        probe = self.evidence_roots[0] / ".proofsift_write_probe"
        try:
            self.validate_write(probe)
        except PolicyViolation:
            return True
        raise PolicyViolation("evidence write probe was unexpectedly allowed")


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def file_mode(path: Path) -> str:
    try:
        mode = os.stat(path).st_mode
    except FileNotFoundError:
        return "missing"
    return oct(mode & 0o777)

