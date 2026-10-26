from __future__ import annotations

from pathlib import Path


class LocalSecureStorage:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.documents_dir = self.root / "documents"
        self.documents_dir.mkdir(parents=True, exist_ok=True)

    def store_document_placeholder(self, filename: str, text: str) -> str:
        safe_filename = filename.replace("/", "_")
        path = self.documents_dir / safe_filename
        path.write_text(text, encoding="utf-8")
        return str(path.relative_to(self.root))
