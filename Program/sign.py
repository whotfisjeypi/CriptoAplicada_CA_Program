from pathlib import Path
from datetime import datetime, timezone
import argparse
import json
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def load_private_key(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def sign_file(file_path: Path, key_path: Path, output_sig: Path) -> None:
    if not file_path.exists():
        raise FileNotFoundError(f"No existe el archivo a firmar: {file_path}")

    if not key_path.exists():
        raise FileNotFoundError(f"No existe la clave privada: {key_path}")

    data = file_path.read_bytes()
    private_key = load_private_key(key_path)

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    payload = {
        "file": str(file_path),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "signature": base64.b64encode(signature).decode("utf-8"),
    }

    output_sig.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    print("Archivo firmado correctamente:")
    print(f"  - Archivo: {file_path}")
    print(f"  - Firma: {output_sig}")


def main():
    parser = argparse.ArgumentParser(description="Firmar un archivo")
    parser.add_argument("file", help="Archivo a firmar")
    parser.add_argument("key", help="Clave privada PEM del usuario")
    parser.add_argument("--out", help="Archivo de salida para la firma", default=None)

    args = parser.parse_args()

    file_path = Path(args.file)
    key_path = Path(args.key)
    output_sig = Path(args.out) if args.out else Path(f"{args.file}.sig.json")

    sign_file(file_path, key_path, output_sig)


if __name__ == "__main__":
    main()