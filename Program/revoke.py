from pathlib import Path
from datetime import datetime, timezone
import argparse
import json

from cryptography import x509


CERTS_DIR = Path("certs")
DB_DIR = Path("db")
REVOKED_FILE = DB_DIR / "revoked.json"


def ensure_files():
    DB_DIR.mkdir(exist_ok=True)
    if not REVOKED_FILE.exists():
        REVOKED_FILE.write_text("[]", encoding="utf-8")


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def load_certificate(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def revoke_certificate(cert_path: Path, reason: str = "unspecified") -> None:
    ensure_files()

    if not cert_path.exists():
        raise FileNotFoundError(f"No existe el certificado: {cert_path}")

    cert = load_certificate(cert_path)
    revoked = load_json(REVOKED_FILE)

    serial = str(cert.serial_number)

    for item in revoked:
        if item["serial_number"] == serial:
            print("Ese certificado ya está revocado.")
            return

    revoked.append({
        "serial_number": serial,
        "subject": cert.subject.rfc4514_string(),
        "revoked_at": datetime.now(timezone.utc).isoformat(),
        "reason": reason,
        "cert_path": str(cert_path),
    })

    save_json(REVOKED_FILE, revoked)

    print("Certificado revocado correctamente.")
    print(f"Serial: {serial}")
    print(f"Motivo: {reason}")


def list_revoked() -> None:
    ensure_files()
    revoked = load_json(REVOKED_FILE)

    if not revoked:
        print("No hay certificados revocados.")
        return

    print("Certificados revocados:")
    for item in revoked:
        print("-" * 40)
        print(f"Serial: {item['serial_number']}")
        print(f"Subject: {item['subject']}")
        print(f"Fecha: {item['revoked_at']}")
        print(f"Motivo: {item['reason']}")


def main():
    parser = argparse.ArgumentParser(description="Revocar certificados")
    subparsers = parser.add_subparsers(dest="command", required=True)

    revoke_parser = subparsers.add_parser("add", help="Revocar un certificado")
    revoke_parser.add_argument("cert", help="Ruta al certificado PEM")
    revoke_parser.add_argument("--reason", default="unspecified", help="Motivo de revocación")

    subparsers.add_parser("list", help="Listar certificados revocados")

    args = parser.parse_args()

    if args.command == "add":
        revoke_certificate(Path(args.cert), args.reason)
    elif args.command == "list":
        list_revoked()


if __name__ == "__main__":
    main()