from __future__ import annotations

from dataclasses import dataclass, field

FORMAT_MAP: dict[str, str] = {
    "ROA": "der",
    "MFT": "der",
    "CRL": "der",
    "CER": "der",
    "ASPA": "der",
    "SNAPSHOT": "xml",
    "NOTIFICATION": "xml",
    "DELTA": "xml",
}

SERIALIZATION_KEYS = ("preserve_cms_digest", "preserve_cms_signature", "preserve_object_signature")
PUBLICATION_KEYS = ("scaffold_mode", "append_filename", "sync_notification_with_ca", "bump_victim_rrdp")


def serialization_options(metadata: dict) -> dict[str, bool]:
    return {key: metadata.get(key, False) for key in SERIALIZATION_KEYS}

@dataclass
class TestInput:
    data: bytes
    object_type: str
    format: str
    metadata: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.object_type = self.object_type.upper()
        if self.format not in ("der", "xml"):
            raise ValueError(f"invalid format {self.format!r}, expected 'der' or 'xml'")

    @classmethod
    def from_bytes(cls, data: bytes, object_type: str, **extra_meta: object) -> TestInput:
        otype = object_type.upper()
        fmt = FORMAT_MAP.get(otype)
        if fmt is None:
            raise ValueError(f"unknown object type {otype!r}")
        return cls(data=data, object_type=otype, format=fmt, metadata=dict(extra_meta))
