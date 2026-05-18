from pathlib import Path
from datetime import datetime, timezone
import argparse
import json
import base64
from getpass import getpass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def load_private_key(path: Path, password: bytes):
    return serialization.load_pem_private_key(
        path.read_bytes(),
        password=password
    )


def load_certificate(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def sha256_hex(data: bytes) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)

    return digest.finalize().hex()


def ask_password(value: str | None) -> bytes:
    if value:
        return value.encode("utf-8")

    password = getpass("Contraseña de la clave privada del usuario: ")

    if not password:
        raise ValueError("La contraseña no puede estar vacía.")

    return password.encode("utf-8")


def sign_file(
    file_path: Path,
    key_path: Path,
    cert_path: Path,
    output_sig: Path,
    password: str | None
) -> None:
    if not file_path.exists():
        raise FileNotFoundError(f"No existe el archivo a firmar: {file_path}")

    if not key_path.exists():
        raise FileNotFoundError(f"No existe la clave privada: {key_path}")

    if not cert_path.exists():
        raise FileNotFoundError(f"No existe el certificado del usuario: {cert_path}")

    data = file_path.read_bytes()
    private_key = load_private_key(key_path, ask_password(password))
    cert = load_certificate(cert_path)

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    payload = {
        "version": "2.0",
        "file": str(file_path),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "algorithm": {
            "signature": "RSA-PSS",
            "hash": "SHA-256",
            "mgf": "MGF1-SHA256",
            "salt_length": "MAX_LENGTH",
        },
        "file_sha256": sha256_hex(data),
        "signer": {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial_number": str(cert.serial_number),
            "certificate_fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        },
        "signature_base64": base64.b64encode(signature).decode("utf-8"),
    }

    output_sig.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print("Archivo firmado correctamente:")
    print(f"  - Archivo: {file_path}")
    print(f"  - SHA-256: {payload['file_sha256']}")
    print(f"  - Firma: {output_sig}")


def main():
    parser = argparse.ArgumentParser(description="Firmar un archivo con RSA-PSS y SHA-256")
    parser.add_argument("file", help="Archivo a firmar")
    parser.add_argument("key", help="Clave privada PEM cifrada del usuario")
    parser.add_argument("cert", help="Certificado PEM del usuario")
    parser.add_argument("--out", help="Archivo de salida para la firma", default=None)
    parser.add_argument("--password", help="Contraseña de la clave privada; si se omite se pedirá de forma segura")

    args = parser.parse_args()

    file_path = Path(args.file)
    key_path = Path(args.key)
    cert_path = Path(args.cert)
    output_sig = Path(args.out) if args.out else Path(f"{args.file}.sig.json")

    sign_file(
        file_path,
        key_path,
        cert_path,
        output_sig,
        args.password
    )


if __name__ == "__main__":
    main()