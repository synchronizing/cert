"""
Connection functionalities.
"""
import asyncio
import ssl
from typing import Optional

from OpenSSL import crypto

import cert


def extract_ssl_object(writer: asyncio.StreamWriter) -> Optional[ssl.SSLObject]:
    """
    Extracts the SSLContext from an existing asyncio Stream connection.

    Args:
        writer: The writer of the client connection. Post-handshake.

    Returns:
        The SSLContext of the connection or None if the connection is not TLS.
    """
    transport = writer.transport
    return transport.get_extra_info("ssl_object")
    # return ssl_object.getpeercert()


def new_context(certificate: str, ca: cert.CertificateAuthority) -> ssl.SSLContext:
    """
    Creates a new SSLContext with the CA certificate.

    Args:
        cert_str: The certificate dump as a string.

    Returns:
        The SSLContext.
    """

    # Loads the certificate from the SSL object, and create a new PKey.
    X509 = crypto.load_certificate(crypto.FILETYPE_PEM, certificate)
    PKey = cert.PKey()

    # Assign new PKey to the certificate.
    X509.set_pubkey(PKey)
    X509.sign(PKey, "sha256")

    # Re-issues the certificate via the CA.
    ca.issue(X509)

    # Dump the cert and key.
    cert_dump = crypto.dump_certificate(crypto.FILETYPE_PEM, X509)
    key_dump = crypto.dump_privatekey(crypto.FILETYPE_PEM, PKey)

    # Store cert and key into file.
    cert_path, key_path = cert.__data__ / "temp.crt", cert.__data__ / "temp.key"
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    with cert_path.open("wb") as f:
        f.write(cert_dump)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    with key_path.open("wb") as f:
        f.write(key_dump)

    # Creates new SSLContext.
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)

    # Remove the temporary files.
    cert_path.unlink()
    key_path.unlink()

    return context
