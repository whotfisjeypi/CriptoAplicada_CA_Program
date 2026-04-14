from pathlib import Path
from datetime import datetime, timedelta, timezone
import argparse

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa


CERTS_DIR = Path("certs")


def ensure_dirs() -> None:
    CERTS_DIR.mkdir(exist_ok=True)


def save_pem_private_key(path: Path, private_key) -> None:
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)


def save_pem_certificate(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def load_private_key(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def load_certificate(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def generate_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def create_ca(common_name: str = "MiniNotario CA") -> None:
    ensure_dirs()

    ca_key_path = CERTS_DIR / "ca_key.pem"
    ca_cert_path = CERTS_DIR / "ca_cert.pem"

    if ca_key_path.exists() or ca_cert_path.exists():
        print("La CA ya existe en certs/ca_key.pem y certs/ca_cert.pem")
        return

    ca_key = generate_rsa_key()

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "MX"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mini Notario Digital"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.now(timezone.utc)

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    save_pem_private_key(ca_key_path, ca_key)
    save_pem_certificate(ca_cert_path, ca_cert)

    print("CA creada correctamente:")
    print(f"  - Clave: {ca_key_path}")
    print(f"  - Certificado: {ca_cert_path}")


def issue_user_certificate(username: str) -> None:
    ensure_dirs()

    ca_key_path = CERTS_DIR / "ca_key.pem"
    ca_cert_path = CERTS_DIR / "ca_cert.pem"

    if not ca_key_path.exists() or not ca_cert_path.exists():
        raise FileNotFoundError("Primero debes crear la CA con: python ca.py init")

    user_key_path = CERTS_DIR / f"{username}_key.pem"
    user_cert_path = CERTS_DIR / f"{username}_cert.pem"

    if user_key_path.exists() or user_cert_path.exists():
        print(f"El usuario '{username}' ya tiene archivos en certs/")
        return

    ca_key = load_private_key(ca_key_path)
    ca_cert = load_certificate(ca_cert_path)

    user_key = generate_rsa_key()

    user_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "MX"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mini Notario Digital Users"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])

    now = datetime.now(timezone.utc)

    user_cert = (
        x509.CertificateBuilder()
        .subject_name(user_subject)
        .issuer_name(ca_cert.subject)
        .public_key(user_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    save_pem_private_key(user_key_path, user_key)
    save_pem_certificate(user_cert_path, user_cert)

    print(f"Certificado emitido para '{username}':")
    print(f"  - Clave privada: {user_key_path}")
    print(f"  - Certificado: {user_cert_path}")


def main():
    parser = argparse.ArgumentParser(description="CA simple para Mini Notario Digital")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Crear la CA")
    init_parser.add_argument("--cn", default="MiniNotario CA", help="Common Name de la CA")

    issue_parser = subparsers.add_parser("issue", help="Emitir certificado a un usuario")
    issue_parser.add_argument("username", help="Nombre del usuario")

    args = parser.parse_args()

    if args.command == "init":
        create_ca(args.cn)
    elif args.command == "issue":
        issue_user_certificate(args.username)


if __name__ == "__main__":
    main()