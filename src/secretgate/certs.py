"""CA certificate generation and per-domain cert caching for TLS MITM."""

from __future__ import annotations

import datetime
import ipaddress
import ssl
from pathlib import Path

import structlog
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

logger = structlog.get_logger()

_CA_VALID_DAYS = 365
_DOMAIN_VALID_HOURS = 24


def _san_for_domain(domain: str) -> list[x509.GeneralName]:
    """Return the appropriate SAN entry — IPAddress for IPs, DNSName for hostnames."""
    try:
        addr = ipaddress.ip_address(domain)
        return [x509.IPAddress(addr)]
    except ValueError:
        return [x509.DNSName(domain)]


class CertAuthority:
    """Manages a local CA for TLS MITM interception."""

    def __init__(self, certs_dir: Path | None = None):
        self._certs_dir = certs_dir or Path.home() / ".secretgate" / "certs"
        self._ca_key: rsa.RSAPrivateKey | None = None
        self._ca_cert: x509.Certificate | None = None
        self._domain_cache: dict[str, ssl.SSLContext] = {}

    @property
    def ca_cert_path(self) -> Path:
        return self._certs_dir / "ca.crt"

    @property
    def _ca_key_path(self) -> Path:
        return self._certs_dir / "ca.key"

    def ensure_ca(self) -> None:
        """Load existing CA or generate a new one."""
        self._certs_dir.mkdir(parents=True, exist_ok=True)

        if self.ca_cert_path.exists() and self._ca_key_path.exists():
            self._ca_key = serialization.load_pem_private_key(
                self._ca_key_path.read_bytes(), password=None
            )
            self._ca_cert = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
            logger.info("ca_loaded", path=str(self.ca_cert_path))
            return

        # Generate new CA
        self._ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "secretgate CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "secretgate"),
            ]
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        self._ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self._ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=_CA_VALID_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(self._ca_key, hashes.SHA256())
        )

        self._ca_key_path.write_bytes(
            self._ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        self._ca_key_path.chmod(0o600)
        self.ca_cert_path.write_bytes(self._ca_cert.public_bytes(serialization.Encoding.PEM))
        logger.info("ca_generated", path=str(self.ca_cert_path))

    def get_domain_context(self, domain: str) -> ssl.SSLContext:
        """Get an SSL context with a cert for the given domain, cached in memory."""
        if domain in self._domain_cache:
            return self._domain_cache[domain]

        assert self._ca_key is not None and self._ca_cert is not None, "Call ensure_ca() first"

        # Generate domain key + cert
        domain_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        domain_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
            .issuer_name(self._ca_cert.subject)
            .public_key(domain_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(hours=_DOMAIN_VALID_HOURS))
            .add_extension(
                x509.SubjectAlternativeName(_san_for_domain(domain)),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256())
        )

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # Load cert chain (domain cert + CA cert) and private key from memory
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as cert_f:
            cert_f.write(domain_cert.public_bytes(serialization.Encoding.PEM))
            cert_f.write(self._ca_cert.public_bytes(serialization.Encoding.PEM))
            cert_path = cert_f.name
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as key_f:
            key_f.write(
                domain_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )
            key_path = key_f.name

        ctx.load_cert_chain(cert_path, key_path)
        Path(cert_path).unlink()
        Path(key_path).unlink()

        self._domain_cache[domain] = ctx
        return ctx
