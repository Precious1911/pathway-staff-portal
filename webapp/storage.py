from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from .config import get_settings


class StorageBackend(Protocol):
    def save(self, client_id: int, filename: str, content: bytes) -> str: ...
    def read(self, storage_key: str) -> bytes: ...


@dataclass
class LocalStorageBackend:
    root: Path

    def __post_init__(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, client_id: int, filename: str, content: bytes) -> str:
        safe_name = filename.replace("/", "_")
        key = f"clients/{client_id}/{uuid4().hex}_{safe_name}"
        path = self.root / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return key

    def read(self, storage_key: str) -> bytes:
        path = self.root / storage_key
        return path.read_bytes()


@dataclass
class S3StorageBackend:
    bucket: str
    region: str

    def save(self, client_id: int, filename: str, content: bytes) -> str:
        # Placeholder for hosted deployment integration.
        safe_name = filename.replace("/", "_")
        return f"s3://{self.bucket}/clients/{client_id}/{uuid4().hex}_{safe_name}"

    def read(self, storage_key: str) -> bytes:
        raise NotImplementedError("Direct S3 reads are not implemented in this baseline")


def build_storage(root: Path) -> StorageBackend:
    settings = get_settings(root)
    if settings.storage_backend == "s3":
        return S3StorageBackend(bucket=settings.s3_bucket, region=settings.s3_region)
    return LocalStorageBackend(root=settings.storage_root)
