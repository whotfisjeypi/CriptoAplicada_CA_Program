from pathlib import Path
from datetime import datetime, timedelta, timezone
import argparse
import json
from getpass import getpass

from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.primitives import serialization, hashes


CERTS_DIR = Path("certs")
DB_DIR = Path("db")
REVOKED_FILE = DB_DIR / "revoked.json"
CA_KEY_FILE = CERTS_DIR / "ca_key.pem"
CA_CERT_FILE = CERTS_DIR / "ca_cert.pem"
CRL_FILE = CERTS_DIR / "ca_crl.pem"


REASON_MAP = {
    "unspecified": x509.ReasonFlags.unspecified,
    "key_compromise": x509.ReasonFlags.key_compromise,
    "ca_compromise": x509.ReasonFlags.ca_compromise,
    "affiliation_changed": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
    "certificate_hold": x509.ReasonFlags.certificate_hold,
    "privilege_withdrawn": x509.ReasonFlags.privilege_withdrawn,
}


def ensure_files():
    CERTS_DIR.mkdir(exist_ok=True)
    DB_DIR.mkdir(exist_ok=True)

    if not REVOKED_FILE.exists():
        REVOKED_FILE.write_text("[]", encoding="utf-8")


def load_json(path: Path):
    if not path.exists():
        return []

    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data) -> None:
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )


def load_certificate(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def load_private_key(path: Path, password: bytes):
    return serialization.load_pem_private_key(
        path.read_bytes(),
        password=password
    )


def ask_password(value: str | None) -> bytes:
    if value:
        return value.encode("utf-8")

    password = getpass("Contraseña de la clave privada de la CA: ")

    if not password:
        raise ValueError("La contraseña no puede estar vacía.")

    return password.encode("utf-8")


def read_crl_number() -> int:
    if not CRL_FILE.exists():
        return 0

    crl = x509.load_pem_x509_crl(CRL_FILE.read_bytes())

    try:
        return crl.extensions.get_extension_for_oid(
            ExtensionOID.CRL_NUMBER
        ).value.crl_number

    except x509.ExtensionNotFound:
        return 0


def generate_crl(
    ca_cert: x509.Certificate,
    ca_key,
    revoked_records: list[dict]
) -> None:
    now = datetime.now(timezone.utc)

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + timedelta(days=30))
        .add_extension(
            x509.CRLNumber(read_crl_number() + 1),
            critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()
            ),
            critical=False
        )
    )

    for item in revoked_records:
        reason_value = REASON_MAP.get(
            item.get("reason", "unspecified"),
            x509.ReasonFlags.unspecified
        )

        revoked_at = datetime.fromisoformat(item["revoked_at"])

        revoked_cert = (
            x509.RevokedCertificateBuilder()
            .serial_number(int(item["serial_number"]))
            .revocation_date(revoked_at)
            .add_extension(
                x509.CRLReason(reason_value),
                critical=False
            )
            .build()
        )

        builder = builder.add_revoked_certificate(revoked_cert)

    crl = builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256()
    )

    CRL_FILE.write_bytes(crl.public_bytes(serialization.Encoding.PEM))


def revoke_certificate(
    cert_path: Path,
    reason: str = "unspecified",
    ca_password: str | None = None
) -> None:
    ensure_files()

    if reason not in REASON_MAP:
        valid = ", ".join(REASON_MAP.keys())
        raise ValueError(f"Razón no válida. Usa una de estas: {valid}")

    if not cert_path.exists():
        raise FileNotFoundError(f"No existe el certificado: {cert_path}")

    if not CA_KEY_FILE.exists() or not CA_CERT_FILE.exists():
        raise FileNotFoundError("No existe la CA. Deben existir certs/ca_key.pem y certs/ca_cert.pem")

    cert = load_certificate(cert_path)
    ca_cert = load_certificate(CA_CERT_FILE)
    ca_key = load_private_key(CA_KEY_FILE, ask_password(ca_password))

    revoked = load_json(REVOKED_FILE)
    serial = str(cert.serial_number)

    if cert.issuer != ca_cert.subject:
        raise ValueError("El certificado no fue emitido por esta CA.")

    for item in revoked:
        if item["serial_number"] == serial:
            print("Ese certificado ya está revocado.")
            return

    revoked.append({
        "serial_number": serial,
        "subject": cert.subject.rfc4514_string(),
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "revoked_at": datetime.now(timezone.utc).isoformat(),
        "reason": reason,
        "cert_path": str(cert_path),
    })

    save_json(REVOKED_FILE, revoked)
    generate_crl(ca_cert, ca_key, revoked)

    print("Certificado revocado correctamente.")
    print(f"Serial: {serial}")
    print(f"Motivo: {reason}")
    print(f"CRL actualizada: {CRL_FILE}")


def list_revoked() -> None:
    ensure_files()
    revoked = load_json(REVOKED_FILE)

    if not revoked:
        print("No hay certificados revocados.")
        return

    print("Certificados revocados:")

    for item in revoked:
        print("-" * 50)
        print(f"Serial: {item.get('serial_number')}")
        print(f"Subject: {item.get('subject')}")
        print(f"Fingerprint SHA-256: {item.get('fingerprint_sha256')}")
        print(f"Fecha: {item.get('revoked_at')}")
        print(f"Motivo: {item.get('reason')}")


def main():
    parser = argparse.ArgumentParser(description="Revocar certificados y generar CRL X.509")
    subparsers = parser.add_subparsers(dest="command", required=True)

    revoke_parser = subparsers.add_parser("add", help="Revocar un certificado")
    revoke_parser.add_argument("cert", help="Ruta al certificado PEM")
    revoke_parser.add_argument(
        "--reason",
        default="unspecified",
        choices=list(REASON_MAP.keys()),
        help="Motivo de revocación"
    )
    revoke_parser.add_argument(
        "--ca-password",
        help="Contraseña de la clave privada de la CA"
    )

    subparsers.add_parser("list", help="Listar certificados revocados")

    args = parser.parse_args()

    if args.command == "add":
        revoke_certificate(
            Path(args.cert),
            args.reason,
            args.ca_password
        )

    elif args.command == "list":
        list_revoked()


if __name__ == "__main__":
    main()


if __name__ == "__main__":
    main()