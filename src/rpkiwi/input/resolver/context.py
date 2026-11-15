from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

@dataclass(frozen=True)
class ExpandContext:

    ca_cert: x509.Certificate
    ca_key: rsa.RSAPrivateKey
    now: datetime
    build_dir: Path
    ca_name: str
    base_domain: str
    extras: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_rpki_config(cls, config, *, now: datetime | None = None) -> "ExpandContext":
        from src.rpkiwi.input.builders.ca_cert import load_ca_cert_and_key

        ca_cert, ca_key = load_ca_cert_and_key(
            config.ca_source_cert_path, config.ca_source_key_path
        )
        return cls(
            ca_cert=ca_cert,
            ca_key=ca_key,
            now=now or datetime.now(timezone.utc).replace(microsecond=0),
            build_dir=Path(config.build_dir),
            ca_name=config.ca_name,
            base_domain=config.base_domain,
        )
