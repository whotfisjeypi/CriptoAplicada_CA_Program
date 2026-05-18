from pathlib import Path
from datetime import datetime, timedelta, timezone
import argparse
import json
import os
import re
from getpass import getpass

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa


CERTS_DIR = Path("certs")
DB_DIR = Path("db")
REVOKED_FILE = DB_DIR / "revoked.json"
ISSUED_FILE = DB_DIR / "issued.json"
CRL_FILE = CERTS_DIR / "ca_crl.pem"
CA_KEY_FILE = CERTS_DIR / "ca_key.pem"
CA_CERT_FILE = CERTS_DIR / "ca_cert.pem"


def ensure_dirs() -> None:
    CERTS_DIR.mkdir(exist_ok=True)
    DB_DIR.mkdir(exist_ok=True)

    if not REVOKED_FILE.exists():
        REVOKED_FILE.write_text("[]", encoding="utf-8")

    if not ISSUED_FILE.exists():
        ISSUED_FILE.write_text("[]", encoding="utf-8")


def load_json(path: Path):
    if not path.exists():
        return []

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        raise ValueError(f"El archivo JSON está dañado: {path}")


def save_json(path: Path, data) -> None:
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )


def ask_password(label: str, confirm: bool = False) -> bytes:
    password = getpass(label)

    if not password:
        raise ValueError("La contraseña no puede estar vacía.")

    if confirm:
        password_confirm = getpass("Confirma la contraseña: ")

        if password != password_confirm:
            raise ValueError("Las contraseñas no coinciden.")

    return password.encode("utf-8")


def password_from_args(value: str | None, prompt: str, confirm: bool = False) -> bytes:
    if value:
        return value.encode("utf-8")

    return ask_password(prompt, confirm=confirm)


def sanitize_filename(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9_-]+", "_", value)

    return value.strip("_") or "usuario"


def save_pem_private_key(path: Path, private_key, password: bytes) -> None:
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )

    path.write_bytes(pem)

    try:
        os.chmod(path, 0o600)
    except PermissionError:
        pass


def save_pem_certificate(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def load_private_key(path: Path, password: bytes):
    return serialization.load_pem_private_key(
        path.read_bytes(),
        password=password
    )


def load_certificate(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def generate_rsa_key(key_size: int):
    if key_size < 2048:
        raise ValueError("El tamaño mínimo recomendado para RSA es 2048 bits.")

    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )


def create_initial_crl(ca_cert: x509.Certificate, ca_key) -> None:
    now = datetime.now(timezone.utc)

    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + timedelta(days=30))
        .add_extension(x509.CRLNumber(1), critical=False)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    CRL_FILE.write_bytes(crl.public_bytes(serialization.Encoding.PEM))


def create_ca(
    common_name: str = "MiniNotario Root CA",
    key_size: int = 4096,
    days: int = 3650,
    password: str | None = None
) -> None:
    ensure_dirs()

    if CA_KEY_FILE.exists() or CA_CERT_FILE.exists():
        print("La CA ya existe en certs/ca_key.pem y certs/ca_cert.pem")
        return

    ca_password = password_from_args(
        password,
        "Contraseña para proteger la clave privada de la CA: ",
        confirm=True
    )

    ca_key = generate_rsa_key(key_size)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "MX"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mini Notario Digital"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Autoridad Certificadora"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.now(timezone.utc)

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True
        )
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
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    save_pem_private_key(CA_KEY_FILE, ca_key, ca_password)
    save_pem_certificate(CA_CERT_FILE, ca_cert)
    create_initial_crl(ca_cert, ca_key)

    print("CA creada correctamente:")
    print(f"  - Clave privada cifrada: {CA_KEY_FILE}")
    print(f"  - Certificado raíz: {CA_CERT_FILE}")
    print(f"  - CRL inicial: {CRL_FILE}")
    print(f"  - Serial CA: {ca_cert.serial_number}")


def issue_user_certificate(
    username: str,
    email: str | None = None,
    org: str = "Mini Notario Digital Users",
    days: int = 365,
    key_size: int = 3072,
    ca_password: str | None = None,
    user_password: str | None = None
) -> None:
    ensure_dirs()

    if not CA_KEY_FILE.exists() or not CA_CERT_FILE.exists():
        raise FileNotFoundError("Primero debes crear la CA con: python ca.py init")

    safe_name = sanitize_filename(username)
    user_key_path = CERTS_DIR / f"{safe_name}_key.pem"
    user_cert_path = CERTS_DIR / f"{safe_name}_cert.pem"

    if user_key_path.exists() or user_cert_path.exists():
        print(f"El usuario '{username}' ya tiene archivos en certs/")
        return

    ca_pass = password_from_args(
        ca_password,
        "Contraseña de la clave privada de la CA: "
    )

    user_pass = password_from_args(
        user_password,
        f"Contraseña para proteger la clave privada de {username}: ",
        confirm=True
    )

    ca_key = load_private_key(CA_KEY_FILE, ca_pass)
    ca_cert = load_certificate(CA_CERT_FILE)
    user_key = generate_rsa_key(key_size)

    subject_attributes = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "MX"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ]

    if email:
        subject_attributes.append(
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, email)
        )

    user_subject = x509.Name(subject_attributes)
    now = datetime.now(timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(user_subject)
        .issuer_name(ca_cert.subject)
        .public_key(user_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
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
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=False
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(user_key.public_key()),
            critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False
        )
    )

    if email:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(email)]),
            critical=False
        )

    user_cert = builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256()
    )

    save_pem_private_key(user_key_path, user_key, user_pass)
    save_pem_certificate(user_cert_path, user_cert)

    issued = load_json(ISSUED_FILE)
    issued.append({
        "username": username,
        "email": email,
        "serial_number": str(user_cert.serial_number),
        "fingerprint_sha256": user_cert.fingerprint(hashes.SHA256()).hex(),
        "cert_path": str(user_cert_path),
        "issued_at": now.isoformat(),
        "expires_at": user_cert.not_valid_after_utc.isoformat(),
        "key_size": key_size,
        "signature_algorithm": "sha256WithRSAEncryption",
    })

    save_json(ISSUED_FILE, issued)

    print(f"Certificado emitido para '{username}':")
    print(f"  - Clave privada cifrada: {user_key_path}")
    print(f"  - Certificado: {user_cert_path}")
    print(f"  - Serial: {user_cert.serial_number}")
    print(f"  - Huella SHA-256: {user_cert.fingerprint(hashes.SHA256()).hex()}")


def list_certificates() -> None:
    ensure_dirs()
    issued = load_json(ISSUED_FILE)

    if not issued:
        print("No hay certificados emitidos.")
        return

    print("Certificados emitidos:")

    for item in issued:
        print("-" * 50)
        print(f"Usuario: {item.get('username')}")
        print(f"Email: {item.get('email')}")
        print(f"Serial: {item.get('serial_number')}")
        print(f"Fingerprint SHA-256: {item.get('fingerprint_sha256')}")
        print(f"Certificado: {item.get('cert_path')}")
        print(f"Emitido: {item.get('issued_at')}")
        print(f"Expira: {item.get('expires_at')}")


def main():
    parser = argparse.ArgumentParser(description="CA robusta para Mini Notario Digital")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Crear la CA raíz")
    init_parser.add_argument("--cn", default="MiniNotario Root CA", help="Common Name de la CA")
    init_parser.add_argument("--key-size", type=int, default=4096, help="Tamaño de clave RSA de la CA")
    init_parser.add_argument("--days", type=int, default=3650, help="Vigencia de la CA en días")
    init_parser.add_argument("--password", help="Contraseña de la CA; si se omite se pedirá de forma segura")

    issue_parser = subparsers.add_parser("issue", help="Emitir certificado a un usuario")
    issue_parser.add_argument("username", help="Nombre común del usuario")
    issue_parser.add_argument("--email", help="Correo del usuario")
    issue_parser.add_argument("--org", default="Mini Notario Digital Users", help="Organización del usuario")
    issue_parser.add_argument("--days", type=int, default=365, help="Vigencia del certificado en días")
    issue_parser.add_argument("--key-size", type=int, default=3072, help="Tamaño de clave RSA del usuario")
    issue_parser.add_argument("--ca-password", help="Contraseña de la clave privada de la CA")
    issue_parser.add_argument("--user-password", help="Contraseña de la clave privada del usuario")

    subparsers.add_parser("list", help="Listar certificados emitidos")

    args = parser.parse_args()

    if args.command == "init":
        create_ca(args.cn, args.key_size, args.days, args.password)

    elif args.command == "issue":
        issue_user_certificate(
            args.username,
            args.email,
            args.org,
            args.days,
            args.key_size,
            args.ca_password,
            args.user_password
        )

    elif args.command == "list":
        list_certificates()


if __name__ == "__main__":
    main()