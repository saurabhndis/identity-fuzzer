"""SSL/TLS certificate generation and configuration for LDAPS.

Provides utilities to generate self-signed certificates for the AD Simulator
LDAPS endpoint and to create Twisted SSL contexts.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# Twisted SSL import — optional at module level to allow testing
# without a running reactor
try:
    from twisted.internet import ssl as twisted_ssl

    _HAS_TWISTED_SSL = True
except ImportError:
    _HAS_TWISTED_SSL = False


def generate_server_certs(
    domain: str = "testlab.local",
    output_dir: str = ".",
    key_size: int = 2048,
    days_valid: int = 365,
) -> tuple[str, str]:
    """Generate a self-signed certificate and private key for LDAPS.

    Creates a CA-like self-signed certificate suitable for testing.
    The certificate includes the domain as both the Common Name and
    a Subject Alternative Name (DNS).

    Args:
        domain: The domain name for the certificate CN and SAN.
        output_dir: Directory to write the cert and key files.
        key_size: RSA key size in bits (default 2048).
        days_valid: Certificate validity period in days.

    Returns:
        A tuple of ``(cert_path, key_path)`` — absolute paths to the
        generated PEM files.
    """
    import datetime

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    cert_file = output_path / f"{domain}.crt"
    key_file = output_path / f"{domain}.key"

    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    # Build the certificate
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AD Simulator"),
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
        ]
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(domain),
                    x509.DNSName(f"*.{domain}"),
                    x509.DNSName("localhost"),
                    x509.IPAddress(
                        __import__("ipaddress").IPv4Address("127.0.0.1")
                    ),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    # Write private key
    with open(key_file, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Write certificate
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return str(cert_file.resolve()), str(key_file.resolve())


def get_ssl_context(cert_file: str, key_file: str) -> object:
    """Create a Twisted SSL context factory for the LDAPS server.

    Args:
        cert_file: Path to the PEM-encoded certificate file.
        key_file: Path to the PEM-encoded private key file.

    Returns:
        A Twisted ``ssl.DefaultOpenSSLContextFactory`` suitable for
        passing to ``reactor.listenSSL()``.

    Raises:
        RuntimeError: If Twisted SSL support is not available.
        FileNotFoundError: If the cert or key file does not exist.
    """
    if not _HAS_TWISTED_SSL:
        raise RuntimeError(
            "Twisted SSL support is not available. "
            "Install pyOpenSSL: pip install pyopenssl"
        )

    if not os.path.isfile(cert_file):
        raise FileNotFoundError(f"Certificate file not found: {cert_file}")
    if not os.path.isfile(key_file):
        raise FileNotFoundError(f"Key file not found: {key_file}")

    return twisted_ssl.DefaultOpenSSLContextFactory(
        key_file,
        cert_file,
    )
