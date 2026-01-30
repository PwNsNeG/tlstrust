from __future__ import annotations

import socket
import ssl
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .utils import b64_der, dt_to_utc_iso, sha256_hex


def _name_to_str(name: x509.Name) -> str:
    # RFC4514
    try:
        return name.rfc4514_string()
    except Exception:
        return str(name)


def _get_san_dns(cert: x509.Certificate) -> list[str]:
    out: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        out = list(ext.value.get_values_for_type(x509.DNSName))
    except Exception:
        pass
    return out


def _get_ski(cert: x509.Certificate) -> str | None:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        return ext.value.digest.hex()
    except Exception:
        return None


def _get_aki(cert: x509.Certificate) -> str | None:
    try:
        ext = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        if ext.value.key_identifier is None:
            return None
        return ext.value.key_identifier.hex()
    except Exception:
        return None


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        return bool(bc.ca)
    except Exception:
        return False


def _key_usage(cert: x509.Certificate) -> list[str]:
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        flags = []
        if ku.digital_signature: flags.append("digital_signature")
        if ku.content_commitment: flags.append("content_commitment")
        if ku.key_encipherment: flags.append("key_encipherment")
        if ku.data_encipherment: flags.append("data_encipherment")
        if ku.key_agreement: flags.append("key_agreement")
        if ku.key_cert_sign: flags.append("key_cert_sign")
        if ku.crl_sign: flags.append("crl_sign")
        if ku.encipher_only: flags.append("encipher_only")
        if ku.decipher_only: flags.append("decipher_only")
        return flags
    except Exception:
        return []


def _ext_key_usage(cert: x509.Certificate) -> list[str]:
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        return [oid.dotted_string for oid in eku]
    except Exception:
        return []


def _pubkey_type(cert: x509.Certificate) -> str | None:
    try:
        pk = cert.public_key()
        name = pk.__class__.__name__
        return name
    except Exception:
        return None


def _sig_alg(cert: x509.Certificate) -> str | None:
    try:
        return cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    except Exception:
        return None


def fetch_presented_chain(
    *,
    host: str,
    port: int,
    sni: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    """
    Fetch the server-presented TLS certificate (leaf reliably).
    Chain retrieval beyond leaf is environment-dependent using stdlib ssl.
    We'll return whatever we can, consistently.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                tls_version = ssock.version()
                cipher = ssock.cipher()
                # Leaf DER
                leaf_der: bytes = ssock.getpeercert(binary_form=True)

                # Attempt to get full chain
                chain_ders: list[bytes] = []
                if hasattr(ssock, "get_verified_chain"):
                    # not expected here because of disabled verification
                    try:
                        chain = ssock.get_verified_chain()  # type: ignore[attr-defined]
                        chain_ders = [c.public_bytes(serialization.Encoding.DER) for c in chain]
                    except Exception:
                        chain_ders = []
                elif hasattr(ssock, "getpeercertchain"):
                    try:
                        chain_ders = ssock.getpeercertchain()  # type: ignore[attr-defined]
                    except Exception:
                        chain_ders = []
                elif hasattr(ssock, "get_peer_cert_chain"):
                    try:
                        chain = ssock.get_peer_cert_chain()  # type: ignore[attr-defined]
                        chain_ders = [c.to_cryptography().public_bytes(serialization.Encoding.DER) for c in chain]
                    except Exception:
                        chain_ders = []

        # Normalize: ensure leaf is first and included
        ders: list[bytes] = []
        if leaf_der:
            ders.append(leaf_der)
        for d in chain_ders:
            if d and d != leaf_der:
                ders.append(d)

        certs: list[dict[str, Any]] = []
        for der in ders:
            c = x509.load_der_x509_certificate(der)
            certs.append(
                {
                    "sha256": sha256_hex(der),
                    "der_b64": b64_der(der),
                    "summary": {
                        "subject": _name_to_str(c.subject),
                        "issuer": _name_to_str(c.issuer),
                        "serial_number": hex(c.serial_number),
                        "not_before": dt_to_utc_iso(c.not_valid_before),
                        "not_after": dt_to_utc_iso(c.not_valid_after),
                        "san_dns": _get_san_dns(c),
                        "is_ca": _is_ca(c),
                        "key_usage": _key_usage(c),
                        "ext_key_usage": _ext_key_usage(c),
                        "ski": _get_ski(c),
                        "aki": _get_aki(c),
                        "signature_algorithm": _sig_alg(c),
                        "public_key_type": _pubkey_type(c),
                    },
                }
            )

        return {
            "ok": True,
            "tls": {
                "version": tls_version,
                "cipher": cipher[0] if cipher else None,
            },
            "chain": {
                "presented_count": len(certs),
                "certs": certs,
                "note": (
                    "Presented chain length depends on server and Python/OpenSSL support; "
                    "leaf is always included."
                ),
            },
        }

    except Exception as e:
        return {"ok": False, "error": str(e)}

