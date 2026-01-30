from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone


def b64_der(der: bytes) -> str:
    return base64.b64encode(der).decode("ascii")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def dt_to_utc_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

