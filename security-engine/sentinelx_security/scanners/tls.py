"""TLS endpoint analysis.

Connects only to the pinned addresses (never re-resolves the name) and sends the
target hostname as SNI. For each address it:

1. Retrieves the certificate without validation (so invalid certificates can be
   inspected) and records the negotiated protocol and cipher.
2. Repeats the handshake with full validation against the system trust store and
   hostname checking, recording the verification error if any.
3. Probes each protocol version (TLS 1.0 to 1.3) individually. Versions the local
   OpenSSL build cannot offer are reported as ``not_testable`` rather than
   "unsupported", so the report never claims more than was observed.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import warnings
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, ClassVar, Final

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

from sentinelx_security.scanners.base import (
    Evidence,
    Observation,
    RawOutput,
    ScanContext,
    ScanError,
    Scanner,
    ScannerName,
    UnsupportedTargetError,
)
from sentinelx_security.scope import AssetType, Technique
from sentinelx_security.scope.targets import IPAddress, parse_target

MAX_ADDRESSES: Final = 4
EXPIRY_WARNING_DAYS: Final = 30
MIN_RSA_BITS: Final = 2048
# Probing legacy versions is the point of the check; their enum members are
# deprecated in the stdlib, so the warning is silenced here deliberately.
with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    PROTOCOLS: Final[Mapping[str, ssl.TLSVersion]] = {
        "TLSv1.0": ssl.TLSVersion.TLSv1,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
    }
    _LEGACY_VERSIONS: Final = frozenset({ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1})
LEGACY_PROTOCOLS: Final = ("TLSv1.0", "TLSv1.1")

# OpenSSL X509_V_ERR_* codes we name explicitly.
_VERIFY_CODES: Final = {
    10: "certificate_expired",
    9: "certificate_not_yet_valid",
    18: "self_signed_certificate",
    19: "self_signed_in_chain",
    20: "untrusted_issuer",
    21: "untrusted_issuer",
    62: "hostname_mismatch",
    64: "hostname_mismatch",
}


def _unverified_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _version_context(version: ssl.TLSVersion) -> ssl.SSLContext:
    context = _unverified_context()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        context.minimum_version = version
        context.maximum_version = version
    if version in _LEGACY_VERSIONS:
        # Allow legacy ciphers for the probe only; this context never carries data.
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    return context


async def _handshake(
    address: IPAddress, port: int, sni: str | None, context: ssl.SSLContext, timeout_seconds: float
) -> ssl.SSLObject:
    _, writer = await asyncio.wait_for(
        asyncio.open_connection(
            address.compressed,
            port,
            ssl=context,
            server_hostname=sni,
            ssl_handshake_timeout=timeout_seconds,
        ),
        timeout=timeout_seconds,
    )
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        if not isinstance(ssl_object, ssl.SSLObject):  # pragma: no cover - asyncio invariant
            raise ScanError("tls_error", "TLS session information is unavailable.")
        return ssl_object
    finally:
        writer.close()
        with contextlib.suppress(ssl.SSLError, ConnectionError, OSError):
            await writer.wait_closed()


def _name(cert_name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    values = cert_name.get_attributes_for_oid(oid)
    return str(values[0].value) if values else None


def describe_certificate(der: bytes, now: datetime) -> dict[str, Any]:
    cert = x509.load_der_x509_certificate(der)
    key = cert.public_key()
    key_type, key_bits = "unknown", None
    if isinstance(key, rsa.RSAPublicKey):
        key_type, key_bits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_type, key_bits = f"EC ({key.curve.name})", key.curve.key_size
    elif isinstance(key, ed25519.Ed25519PublicKey | ed448.Ed448PublicKey):
        key_type = "EdDSA"
    elif isinstance(key, dsa.DSAPublicKey):
        key_type, key_bits = "DSA", key.key_size
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = [str(v) for v in san_ext.value.get_values_for_type(x509.DNSName)]
        sans += [str(v) for v in san_ext.value.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        sans = []
    not_after = cert.not_valid_after_utc
    signature = cert.signature_hash_algorithm
    return {
        "subject_cn": _name(cert.subject, NameOID.COMMON_NAME),
        "issuer_cn": _name(cert.issuer, NameOID.COMMON_NAME),
        "issuer_org": _name(cert.issuer, NameOID.ORGANIZATION_NAME),
        "subject_alt_names": sans,
        "serial_number": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": not_after.isoformat(),
        "days_remaining": (not_after - now).days,
        "self_issued": cert.issuer == cert.subject,
        "key_type": key_type,
        "key_bits": key_bits,
        "signature_algorithm": signature.name if signature else None,
        "pem": cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
    }


class TlsScanner(Scanner):
    name: ClassVar[ScannerName] = ScannerName.TLS
    technique: ClassVar[Technique] = Technique.ACTIVE
    description: ClassVar[str] = (
        "Certificate validity, expiry, hostname match, protocol support and weak configuration."
    )
    supported_asset_types = frozenset(
        {
            AssetType.DOMAIN,
            AssetType.SUBDOMAIN,
            AssetType.IP_ADDRESS,
            AssetType.SERVICE,
            AssetType.WEB_APPLICATION,
            AssetType.API_ENDPOINT,
        }
    )

    @classmethod
    def target_for(cls, asset_type: AssetType, value: str) -> str:
        super().target_for(asset_type, value)
        target = parse_target(value)
        if target.scheme == "http":
            raise UnsupportedTargetError("The application is registered with http, not https.")
        if target.scheme == "https" or target.port is not None:
            return value
        return f"{target.host_for_netloc}:443"

    async def _probe(
        self, address: IPAddress, port: int, sni: str | None, timeout_seconds: float
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        ssl_object = await _handshake(address, port, sni, _unverified_context(), timeout_seconds)
        der = ssl_object.getpeercert(binary_form=True)
        if not der:
            raise ScanError("no_certificate", "The server did not present a certificate.")
        cipher = ssl_object.cipher()
        result: dict[str, Any] = {
            "address": address.compressed,
            "port": port,
            "sni": sni,
            "negotiated_protocol": ssl_object.version(),
            "cipher": cipher[0] if cipher else None,
            "certificate": describe_certificate(der, now),
        }

        verify_name = sni or address.compressed
        try:
            await _handshake(
                address, port, verify_name, ssl.create_default_context(), timeout_seconds
            )
            result["trusted"], result["verification_error"] = True, None
        except ssl.SSLCertVerificationError as exc:
            result["trusted"] = False
            result["verification_error"] = _VERIFY_CODES.get(exc.verify_code, "verification_failed")
            result["verification_detail"] = exc.verify_message
        except ssl.SSLError:
            result["trusted"], result["verification_error"] = False, "handshake_failed"

        protocols: dict[str, str] = {}
        for label, version in PROTOCOLS.items():
            try:
                context = _version_context(version)
            except (ValueError, ssl.SSLError):
                protocols[label] = "not_testable"
                continue
            try:
                await _handshake(address, port, sni, context, timeout_seconds)
                protocols[label] = "supported"
            except ssl.SSLError as exc:
                local = "NO_PROTOCOLS_AVAILABLE" in str(exc) or "UNSUPPORTED_PROTOCOL" in str(exc)
                protocols[label] = (
                    "not_testable" if local and label in LEGACY_PROTOCOLS else "not_supported"
                )
            except (ConnectionError, TimeoutError, OSError):
                protocols[label] = "not_supported"
        result["protocols"] = protocols
        return result

    async def execute(self, ctx: ScanContext) -> RawOutput:
        port = ctx.target.effective_port or 443
        sni = None if ctx.target.is_ip else ctx.target.host
        if not ctx.pinned_addresses:
            raise ScanError("no_addresses", "No authorized addresses to connect to.")
        per_probe = max(3.0, ctx.timeout_seconds / (len(ctx.pinned_addresses[:MAX_ADDRESSES]) * 7))
        endpoints = [
            await self._probe(address, port, sni, per_probe)
            for address in ctx.pinned_addresses[:MAX_ADDRESSES]
        ]
        return RawOutput(
            data={"endpoints": endpoints}, tool_versions={"openssl": ssl.OPENSSL_VERSION}
        )

    def normalize_results(self, raw: RawOutput) -> list[Observation]:
        observations: list[Observation] = []
        for endpoint in raw.data["endpoints"]:
            cert = {k: v for k, v in endpoint["certificate"].items() if k != "pem"}
            attention: list[str] = []
            if endpoint["verification_error"]:
                attention.append(endpoint["verification_error"])
            if cert["days_remaining"] < 0 and "certificate_expired" not in attention:
                attention.append("certificate_expired")
            elif 0 <= cert["days_remaining"] < EXPIRY_WARNING_DAYS:
                attention.append("certificate_expiring_soon")
            if cert["key_type"] == "RSA" and (cert["key_bits"] or 0) < MIN_RSA_BITS:
                attention.append("weak_rsa_key")
            if cert["signature_algorithm"] in {"md5", "sha1"}:
                attention.append("weak_signature_algorithm")
            attention.extend(
                f"legacy_protocol_{label.lower().replace('.', '_')}"
                for label in LEGACY_PROTOCOLS
                if endpoint["protocols"].get(label) == "supported"
            )
            observations.append(
                Observation(
                    kind="tls_endpoint",
                    key=f"{endpoint['address']}:{endpoint['port']}",
                    data={
                        "address": endpoint["address"],
                        "port": endpoint["port"],
                        "sni": endpoint["sni"],
                        "negotiated_protocol": endpoint["negotiated_protocol"],
                        "cipher": endpoint["cipher"],
                        "trusted": endpoint["trusted"],
                        "verification_error": endpoint["verification_error"],
                        "protocols": endpoint["protocols"],
                        "certificate": cert,
                    },
                    attention=tuple(dict.fromkeys(attention)),
                )
            )
        return observations

    def record_evidence(self, raw: RawOutput) -> list[Evidence]:
        return [
            Evidence.bounded(
                f"Certificate presented by {e['address']}:{e['port']}",
                e["certificate"]["pem"],
                "application/x-pem-file",
            )
            for e in raw.data["endpoints"]
        ]
