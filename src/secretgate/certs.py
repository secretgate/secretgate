"""CA certificate generation and per-domain cert caching for TLS MITM."""

from __future__ import annotations

import datetime
import ipaddress
import os
import ssl
import tempfile
from pathlib import Path

import structlog
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

logger = structlog.get_logger()

_CA_VALID_DAYS = 365
_DOMAIN_VALID_HOURS = 24


def _find_system_ca_bundle() -> Path | None:
    """Find the system CA certificate bundle (not our own CA cert)."""
    secretgate_dir = str(Path.home() / ".secretgate")

    # Common system locations first (most reliable)
    candidates = [
        "/etc/ssl/certs/ca-certificates.crt",  # Debian/Ubuntu
        "/etc/pki/tls/certs/ca-bundle.crt",  # RHEL/Fedora
        "/etc/ssl/cert.pem",  # macOS / Alpine
    ]
    for c in candidates:
        p = Path(c)
        if p.exists():
            return p

    # Try ssl module (but skip paths inside our own certs dir,
    # since SSL_CERT_FILE may already point to our CA)
    paths = ssl.get_default_verify_paths()
    for candidate in [paths.cafile, paths.openssl_cafile]:
        if candidate and Path(candidate).exists() and secretgate_dir not in str(candidate):
            return Path(candidate)

    # Try certifi as last resort
    try:
        import certifi

        return Path(certifi.where())
    except ImportError:
        return None


def _san_for_domain(domain: str) -> list[x509.GeneralName]:
    """Return the appropriate SAN entry — IPAddress for IPs, DNSName for hostnames."""
    try:
        addr = ipaddress.ip_address(domain)
        return [x509.IPAddress(addr)]
    except ValueError:
        return [x509.DNSName(domain)]


def _load_cert_chain_from_memory(ctx: ssl.SSLContext, cert_pem: bytes, key_pem: bytes) -> None:
    """Load a cert chain and private key into an SSLContext without writing to disk.

    Uses memfd_create (Linux) for anonymous in-memory files that never touch
    the filesystem. Falls back to temp files on other platforms.
    """
    if hasattr(os, "memfd_create"):
        cert_fd = os.memfd_create("domain_cert")
        key_fd = os.memfd_create("domain_key")
        try:
            os.write(cert_fd, cert_pem)
            os.write(key_fd, key_pem)
            ctx.load_cert_chain(f"/proc/self/fd/{cert_fd}", f"/proc/self/fd/{key_fd}")
        finally:
            os.close(cert_fd)
            os.close(key_fd)
    else:
        # Fallback for macOS/Windows: use temp files with restricted permissions
        cert_path = key_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as cert_f:
                cert_f.write(cert_pem)
                cert_path = cert_f.name
            os.chmod(cert_path, 0o600)
            with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as key_f:
                key_f.write(key_pem)
                key_path = key_f.name
            os.chmod(key_path, 0o600)
            ctx.load_cert_chain(cert_path, key_path)
        finally:
            if cert_path:
                Path(cert_path).unlink(missing_ok=True)
            if key_path:
                Path(key_path).unlink(missing_ok=True)


class CertAuthority:
    """Manages a local CA for TLS MITM interception."""

    def __init__(self, certs_dir: Path | None = None):
        self._certs_dir = certs_dir or Path.home() / ".secretgate" / "certs"
        self._ca_key: rsa.RSAPrivateKey | None = None
        self._ca_cert: x509.Certificate | None = None
        self._domain_cache: dict[str, tuple[ssl.SSLContext, datetime.datetime]] = {}

    @property
    def ca_cert_path(self) -> Path:
        return self._certs_dir / "ca.crt"

    @property
    def ca_bundle_path(self) -> Path:
        return self._certs_dir / "ca-bundle.crt"

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
            now = datetime.datetime.now(datetime.timezone.utc)
            if self._ca_cert.not_valid_after_utc <= now:
                logger.warning(
                    "ca_expired",
                    expired_at=self._ca_cert.not_valid_after_utc.isoformat(),
                    msg="CA certificate has expired — regenerating",
                )
                self.ca_cert_path.unlink(missing_ok=True)
                self._ca_key_path.unlink(missing_ok=True)
                self.ca_bundle_path.unlink(missing_ok=True)
                self._ca_key = None
                self._ca_cert = None
                # fall through to generation below
            else:
                logger.info("ca_loaded", path=str(self.ca_cert_path))
                if not self.ca_bundle_path.exists():
                    self.create_ca_bundle()
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
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self._ca_key.public_key()),
                critical=False,
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
        self.create_ca_bundle()

    def create_ca_bundle(self) -> Path | None:
        """Create a combined CA bundle with system CAs + secretgate CA.

        Returns the bundle path, or None if system CAs couldn't be found.
        """
        system_bundle = _find_system_ca_bundle()
        if system_bundle is None:
            logger.warning("no_system_ca_bundle", msg="could not find system CA bundle")
            return None

        bundle = system_bundle.read_text() + "\n" + self.ca_cert_path.read_text()
        self.ca_bundle_path.write_text(bundle)
        logger.info("ca_bundle_created", path=str(self.ca_bundle_path))
        return self.ca_bundle_path

    def get_domain_context(self, domain: str) -> ssl.SSLContext:
        """Get an SSL context with a cert for the given domain, cached in memory."""
        now = datetime.datetime.now(datetime.timezone.utc)
        if domain in self._domain_cache:
            ctx, expires_at = self._domain_cache[domain]
            if expires_at > now:
                return ctx
            # cert expired — regenerate
            del self._domain_cache[domain]

        assert self._ca_key is not None and self._ca_cert is not None, "Call ensure_ca() first"

        # Generate domain key + cert
        domain_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self._ca_key.public_key()),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256())
        )

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.set_alpn_protocols(["h2", "http/1.1"])

        cert_pem = domain_cert.public_bytes(
            serialization.Encoding.PEM
        ) + self._ca_cert.public_bytes(serialization.Encoding.PEM)
        key_pem = domain_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        _load_cert_chain_from_memory(ctx, cert_pem, key_pem)

        self._domain_cache[domain] = (ctx, now + datetime.timedelta(hours=_DOMAIN_VALID_HOURS))
        return ctx
