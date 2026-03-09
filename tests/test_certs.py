"""Tests for CA certificate generation and domain cert caching."""

from __future__ import annotations

import ssl

import pytest
from cryptography import x509

from secretgate.certs import CertAuthority


@pytest.fixture
def ca(tmp_path):
    """Create a CertAuthority with a temp directory."""
    authority = CertAuthority(tmp_path / "certs")
    authority.ensure_ca()
    return authority


def test_ca_generates_cert_and_key(tmp_path):
    """CA cert and key files are created on first call."""
    authority = CertAuthority(tmp_path / "certs")
    authority.ensure_ca()
    assert authority.ca_cert_path.exists()
    assert (tmp_path / "certs" / "ca.key").exists()


def test_ca_loads_existing(tmp_path):
    """Second call loads from disk instead of regenerating."""
    authority1 = CertAuthority(tmp_path / "certs")
    authority1.ensure_ca()
    cert1_bytes = authority1.ca_cert_path.read_bytes()

    authority2 = CertAuthority(tmp_path / "certs")
    authority2.ensure_ca()
    cert2_bytes = authority2.ca_cert_path.read_bytes()

    assert cert1_bytes == cert2_bytes


def test_ca_cert_is_valid_x509(ca):
    """The generated CA cert is a valid X.509 certificate."""
    cert = x509.load_pem_x509_certificate(ca.ca_cert_path.read_bytes())
    assert (
        cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        == "secretgate CA"
    )
    # Should be a CA cert
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.value.ca is True


def test_domain_cert_creates_valid_context(ca):
    """get_domain_context returns a usable SSL context."""
    ctx = ca.get_domain_context("example.com")
    assert isinstance(ctx, ssl.SSLContext)


def test_domain_cert_is_cached(ca):
    """Same domain returns the same SSL context object."""
    ctx1 = ca.get_domain_context("example.com")
    ctx2 = ca.get_domain_context("example.com")
    assert ctx1 is ctx2


def test_different_domains_get_different_contexts(ca):
    """Different domains get different SSL contexts."""
    ctx1 = ca.get_domain_context("example.com")
    ctx2 = ca.get_domain_context("other.com")
    assert ctx1 is not ctx2


def test_ca_key_permissions(tmp_path):
    """CA private key file should have restricted permissions."""
    import stat

    authority = CertAuthority(tmp_path / "certs")
    authority.ensure_ca()
    key_path = tmp_path / "certs" / "ca.key"
    mode = key_path.stat().st_mode
    assert stat.S_IMODE(mode) == 0o600
