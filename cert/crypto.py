"""
Cryptography functionalities.
"""
import random
import socket
from pathlib import Path
from typing import List, Optional, Union

from OpenSSL import crypto


class PKey(crypto.PKey):
    """
    Helpful interface to OpenSSL.crypto.PKey that adds init/save/load methods.
    """

    def __init__(self, bits: int = 2048):
        """
        Initializes the PKey object.
        """
        super().__init__()
        self.generate_key(crypto.TYPE_RSA, bits)

    def save(self, path: Union[str, Path]):
        """
        Saves the key to the specific path.

        Args:
            path: Path to save the certificate and key.
        """
        with open(path, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, self))

    @classmethod
    def load(cls, path: Union[str, Path]):
        """
        Loads the key from the specified path.

        Args:
            path: Path to load the key from.
        """
        with open(path, "rb") as f:
            return cls(crypto.load_privatekey(crypto.FILETYPE_PEM, f.read()))


class X509(crypto.X509):
    """
    Helpful interface to OpenSSL.crypto.X509 that adds init/save/load methods.
    """

    def __init__(
        self,
        country_name: str = "US",
        state_or_province_name: str = "New York",
        locality: str = "New York",
        organization_name: str = "cert",
        organization_unit_name: str = "cert",
        common_name: str = socket.gethostname(),
        serial_number: int = random.randint(0, 2 ** 64 - 1),
        time_not_before: int = 0,  # 0 means now.
        time_not_after: int = 2 * (365 * 24 * 60 * 60),  # 2 years.
        extensions: List[crypto.X509Extension] = [],
    ):
        """
        Initializes the X509 object.
        """
        super().__init__()
        self.get_subject().C = country_name
        self.get_subject().ST = state_or_province_name
        self.get_subject().L = locality
        self.get_subject().O = organization_name
        self.get_subject().OU = organization_unit_name
        self.get_subject().CN = common_name
        self.set_serial_number(serial_number)
        self.gmtime_adj_notBefore(time_not_before)
        self.gmtime_adj_notAfter(time_not_after)
        self.add_extensions(extensions)
        self.set_issuer(self.get_subject())

    @property
    def signed(self) -> bool:
        """
        Check if the certificate is signed.

        Returns:
            True if the certificate is signed, False otherwise.
        """
        try:
            self.get_signature_algorithm()
        except ValueError:
            return False
        else:
            return True

    def X509Req(self) -> crypto.X509Req:
        """
        Converts X509 to X509Req.
        """
        print(self.get_subject()._fields)

    def save(self, path: Union[str, Path]):
        """
        Saves the certificate and key to the specified path.

        Args:
            path: Path to save the certificate and key.
            key: Private key.
        """
        with open(path, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, self))

    @classmethod
    def load(cls, cert_path: Union[Path, str]):
        """
        Loads the certificate from the specified path.

        Args:
            cert_path: Path to the certificate.
        """
        with open(cert_path, "rb") as f:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
        return cert


class CertificateAuthority:
    """
    Certificate Authority interface.
    """

    def __init__(
        self,
        key: Optional[PKey] = None,
        cert: Optional[X509] = None,
    ):
        """
        Generates a certificate authority.

        Args:
            key: Private key of the CA. Will be generated if not provided.
            cert: Unsigned certificate of the CA. Will be generated if not provided.
        """
        if key is None:
            self.key = PKey()

        if cert is None:
            self.cert = X509()

        # Check if the certificate has already been signed.
        if self.cert.signed:
            raise ValueError("Certificate has already been signed.")

        try:
            self.cert.get_signature_algorithm()
        except ValueError:
            pass  # The certificate is not signed.
        else:
            raise ValueError("Certificate already signed. Cannot sign again.")

        # Adds extensions to make x509 certificate a CA.
        self.cert.add_extensions(
            [
                crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
                crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
                crypto.X509Extension(
                    b"subjectKeyIdentifier",
                    False,
                    b"hash",
                    subject=self.cert,
                ),
            ],
        )

        # Set the certificates public key, and sign it.
        self.cert.set_pubkey(self.key)
        self.cert.sign(self.key, "sha256")

    def issue(self, cert: X509) -> X509:
        """
        Issue a certificate.

        Args:
            cert: The certificate to issue.
        """
        cert.set_issuer(self.cert.get_subject())
        cert.sign(self.key, "sha256")
        return cert

    def save(self, cert_path: Union[Path, str], key_path: Union[Path, str]):
        """
        Saves the certificate authority and its private key to disk.

        Args:
            cert_path: Path to the certificate file.
            key_path: Path to the key file.
        """
        cert_path, key_path = Path(cert_path), Path(key_path)
        self.cert.save(cert_path)
        self.key.save(key_path)

    @classmethod
    def load(cls, cert_path: Union[Path, str], key_path: Union[Path, str]):
        """
        Loads the certificate authority and its private key from disk.

        Args:
            cert_path: Path to the certificate file.
            key_path: Path to the key file.
        """
        cert_path, key_path = Path(cert_path), Path(key_path)
        key = PKey.load(key_path)
        cert = X509.load(cert_path)
        return cls(key, cert)
