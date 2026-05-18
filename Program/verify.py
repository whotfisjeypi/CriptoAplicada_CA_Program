from pathlib import Path
from datetime import datetime, timezone
import argparse
import base64
import json

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature


DEFAULT_CRL_FILE = Path("certs/ca_crl.pem")


def load_certificate(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def load_crl(path: Path) -> x509.CertificateRevocationList:
    return x509.load_pem_x509_crl(path.read_bytes())


def sha256_hex(data: bytes) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)

    return digest.finalize().hex()


def verify_ca_is_valid(ca_cert: x509.Certificate) -> None:
    now = datetime.now(timezone.utc)

    if now < ca_cert.not_valid_before_utc or now > ca_cert.not_valid_after_utc:
        raise ValueError("El certificado de la CA no está vigente.")

    basic = ca_cert.extensions.get_extension_for_class(
        x509.BasicConstraints
    ).value

    if not basic.ca:
        raise ValueError("El certificado de la CA no tiene BasicConstraints(ca=True).")

    usage = ca_cert.extensions.get_extension_for_class(
        x509.KeyUsage
    ).value

    if not usage.key_cert_sign or not usage.crl_sign:
        raise ValueError("La CA no tiene permisos para firmar certificados y CRL.")

    ca_public_key = ca_cert.public_key()

    ca_public_key.verify(
        ca_cert.signature,
        ca_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        ca_cert.signature_hash_algorithm,
    )


def verify_certificate_signature(
    user_cert: x509.Certificate,
    ca_cert: x509.Certificate
) -> None:
    if user_cert.issuer != ca_cert.subject:
        raise ValueError("El issuer del certificado del usuario no coincide con la CA.")

    ca_public_key = ca_cert.public_key()

    ca_public_key.verify(
        user_cert.signature,
        user_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        user_cert.signature_hash_algorithm,
    )


def verify_certificate_profile(user_cert: x509.Certificate) -> None:
    public_key = user_cert.public_key()

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("El certificado del usuario no usa RSA.")

    if public_key.key_size < 2048:
        raise ValueError("La clave RSA del usuario es menor a 2048 bits.")

    basic = user_cert.extensions.get_extension_for_class(
        x509.BasicConstraints
    ).value

    if basic.ca:
        raise ValueError("El certificado del usuario no debe ser una CA.")

    usage = user_cert.extensions.get_extension_for_class(
        x509.KeyUsage
    ).value

    if not usage.digital_signature:
        raise ValueError("El certificado del usuario no permite firma digital.")

    try:
        eku = user_cert.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value

        if ExtendedKeyUsageOID.CODE_SIGNING not in eku:
            raise ValueError("El certificado no tiene ExtendedKeyUsage de firma de código/documentos.")

    except x509.ExtensionNotFound:
        raise ValueError("El certificado no tiene ExtendedKeyUsage.")


def verify_certificate_validity(user_cert: x509.Certificate) -> None:
    now = datetime.now(timezone.utc)

    if now < user_cert.not_valid_before_utc:
        raise ValueError("El certificado aún no es válido.")

    if now > user_cert.not_valid_after_utc:
        raise ValueError("El certificado ya expiró.")


def verify_crl(
    crl: x509.CertificateRevocationList,
    ca_cert: x509.Certificate,
    user_cert: x509.Certificate
) -> None:
    if crl.issuer != ca_cert.subject:
        raise ValueError("La CRL no fue emitida por la CA esperada.")

    now = datetime.now(timezone.utc)

    if now > crl.next_update_utc:
        raise ValueError("La CRL está vencida; debe regenerarse.")

    ca_cert.public_key().verify(
        crl.signature,
        crl.tbs_certlist_bytes,
        padding.PKCS1v15(),
        crl.signature_hash_algorithm,
    )

    revoked = crl.get_revoked_certificate_by_serial_number(
        user_cert.serial_number
    )

    if revoked is not None:
        reason = "unspecified"

        try:
            reason = revoked.extensions.get_extension_for_class(
                x509.CRLReason
            ).value.reason.name
        except x509.ExtensionNotFound:
            pass

        raise ValueError(f"El certificado está revocado en la CRL. Motivo: {reason}")


def verify_signature_payload(
    payload: dict,
    file_path: Path,
    user_cert: x509.Certificate
) -> bytes:
    data = file_path.read_bytes()
    current_hash = sha256_hex(data)

    if payload.get("file_sha256") and payload["file_sha256"] != current_hash:
        raise ValueError("El hash SHA-256 del archivo no coincide con el guardado en la firma.")

    signer = payload.get("signer", {})

    if signer.get("serial_number") and signer["serial_number"] != str(user_cert.serial_number):
        raise ValueError("El serial del certificado no coincide con el serial registrado en la firma.")

    if (
        signer.get("certificate_fingerprint_sha256")
        and signer["certificate_fingerprint_sha256"] != user_cert.fingerprint(hashes.SHA256()).hex()
    ):
        raise ValueError("La huella del certificado no coincide con la registrada en la firma.")

    signature_b64 = payload.get("signature_base64") or payload.get("signature")

    if not signature_b64:
        raise ValueError("El archivo de firma no contiene una firma válida.")

    return base64.b64decode(signature_b64)


def verify_file_signature(
    file_path: Path,
    signature_path: Path,
    user_cert: x509.Certificate
) -> None:
    data = file_path.read_bytes()
    payload = json.loads(signature_path.read_text(encoding="utf-8"))
    signature = verify_signature_payload(payload, file_path, user_cert)
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

    print(f"Timestamp de firma UTC: {payload.get('timestamp_utc') or payload.get('timestamp')}")


def main():
    parser = argparse.ArgumentParser(description="Verificar firma digital, certificado y CRL")
    parser.add_argument("file", help="Archivo original")
    parser.add_argument("signature", help="Archivo .sig.json")
    parser.add_argument("user_cert", help="Certificado PEM del usuario")
    parser.add_argument("ca_cert", help="Certificado PEM de la CA")
    parser.add_argument("--crl", default=str(DEFAULT_CRL_FILE), help="CRL PEM emitida por la CA")

    args = parser.parse_args()

    file_path = Path(args.file)
    signature_path = Path(args.signature)
    user_cert_path = Path(args.user_cert)
    ca_cert_path = Path(args.ca_cert)
    crl_path = Path(args.crl)

    for p in [file_path, signature_path, user_cert_path, ca_cert_path, crl_path]:
        if not p.exists():
            raise FileNotFoundError(f"No existe: {p}")

    user_cert = load_certificate(user_cert_path)
    ca_cert = load_certificate(ca_cert_path)
    crl = load_crl(crl_path)

    checks = [
        ("CA raíz", lambda: verify_ca_is_valid(ca_cert)),
        ("Firma del certificado del usuario", lambda: verify_certificate_signature(user_cert, ca_cert)),
        ("Perfil criptográfico del certificado", lambda: verify_certificate_profile(user_cert)),
        ("Vigencia del certificado", lambda: verify_certificate_validity(user_cert)),
        ("Estado de revocación por CRL", lambda: verify_crl(crl, ca_cert, user_cert)),
        ("Firma del archivo", lambda: verify_file_signature(file_path, signature_path, user_cert)),
    ]

    for label, check in checks:
        try:
            check()
            print(f"{label}: VÁLIDO")

        except InvalidSignature:
            print(f"{label}: INVÁLIDO")
            print("Detalle: la firma criptográfica no coincide.")
            return

        except Exception as e:
            print(f"{label}: INVÁLIDO")
            print(f"Detalle: {e}")
            return

    print("Resultado final: FIRMA Y CERTIFICADO VÁLIDOS")


if __name__ == "__main__":
    main()