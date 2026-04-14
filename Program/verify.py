from pathlib import Path
import argparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def load_certificate(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def verify_certificate(user_cert: x509.Certificate, ca_cert: x509.Certificate) -> None:
    ca_public_key = ca_cert.public_key()

    ca_public_key.verify(
        user_cert.signature,
        user_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        user_cert.signature_hash_algorithm,
    )


def verify_file_signature(file_path: Path, signature_path: Path, user_cert: x509.Certificate) -> None:
    data = file_path.read_bytes()
    signature = signature_path.read_bytes()
    user_public_key = user_cert.public_key()

    user_public_key.verify(
        signature,
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def main():
    parser = argparse.ArgumentParser(description="Verificar firma digital")
    parser.add_argument("file", help="Archivo original")
    parser.add_argument("signature", help="Archivo .sig")
    parser.add_argument("user_cert", help="Certificado PEM del usuario")
    parser.add_argument("ca_cert", help="Certificado PEM de la CA")

    args = parser.parse_args()

    file_path = Path(args.file)
    signature_path = Path(args.signature)
    user_cert_path = Path(args.user_cert)
    ca_cert_path = Path(args.ca_cert)

    for p in [file_path, signature_path, user_cert_path, ca_cert_path]:
        if not p.exists():
            raise FileNotFoundError(f"No existe: {p}")

    user_cert = load_certificate(user_cert_path)
    ca_cert = load_certificate(ca_cert_path)

    try:
        verify_certificate(user_cert, ca_cert)
        print("Certificado del usuario: VÁLIDO (firmado por la CA)")
    except Exception as e:
        print("Certificado del usuario: INVÁLIDO")
        print(f"Detalle: {e}")
        return

    try:
        verify_file_signature(file_path, signature_path, user_cert)
        print("Firma del archivo: VÁLIDA")
    except Exception as e:
        print("Firma del archivo: INVÁLIDA")
        print(f"Detalle: {e}")


if __name__ == "__main__":
    main()