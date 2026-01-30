from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .fetch import fetch_presented_chain


def _write_output(out_path: str | None, payload: Any) -> None:
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    if out_path:
        Path(out_path).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="tls-trust-analyzer",
        description="Analyze TLS certificate chains and explain trust decisions.",
    )
    p.add_argument("target", help="Target in the form host:port (e.g., example.com:443)")
    p.add_argument("--sni", help="Override SNI/server name (default: host)")
    p.add_argument("--timeout", type=int, default=10, help="Connect timeout seconds (default: 10)")
    p.add_argument("--out", "-o", help="Write JSON output to file (default: stdout)")
    p.add_argument(
        "--store",
        choices=["mozilla", "system"],
        default="mozilla",
        help="Trust store to use (default: mozilla)",
    )
    p.add_argument(
        "--no-aia",
        action="store_true",
        help="Do not fetch intermediates via AIA (default: fetch allowed later)",
    )
    p.add_argument("--version", action="store_true", help="Print version and exit")
    return p.parse_args(argv)


def _parse_target(target: str) -> tuple[str, int]:
    if ":" not in target:
        raise ValueError("target must be in the form host:port (e.g., example.com:443)")
    host, port_s = target.rsplit(":", 1)
    host = host.strip()
    port_s = port_s.strip()
    if not host:
        raise ValueError("host is empty")
    if not port_s.isdigit():
        raise ValueError("port must be a number")
    port = int(port_s)
    if not (1 <= port <= 65535):
        raise ValueError("port out of range")
    return host, port


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)

    if args.version:
        print(__version__)
        return 0

    try:
        host, port = _parse_target(args.target)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    sni = args.sni or host

    fetched = fetch_presented_chain(host=host, port=port, sni=sni, timeout_seconds=args.timeout)

    payload = {
        "target": {"host": host, "port": port, "sni": sni},
        "version": __version__,
        "trust_store": args.store,
        "aia_fetch": not args.no_aia,
        "result": fetched if fetched.get("ok") else None,
        "errors": [] if fetched.get("ok") else [fetched.get("error", "unknown error")],
    }

    _write_output(args.out, payload)
    return 0 if fetched.get("ok") else 3


if __name__ == "__main__":
    raise SystemExit(main())

