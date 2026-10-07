"""Local HTTPS-only hosted-mode verification server; never deploy this test helper."""
import ipaddress
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import uvicorn
from alembic import command
from alembic.config import Config
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

root = Path(__file__).resolve().parents[1]
directory = root / "data" / "hosted-verification"
directory.mkdir(parents=True, exist_ok=True, mode=0o700)
os.environ.update(
    WEBSCOPE_DEPLOYMENT="hosted",
    WEBSCOPE_PUBLIC_ORIGIN="https://127.0.0.1:8877",
    WEBSCOPE_DATA_DIR=str(directory),
    WEBSCOPE_FRONTEND_DIR=str(root / "frontend" / "dist"),
)
config = Config(str(root / "backend" / "alembic.ini"))
config.set_main_option("script_location", str(root / "backend" / "alembic"))
command.upgrade(config, "head")
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "WebScope local HTTPS test")])
now = datetime.now(timezone.utc)
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
        .sign(key, hashes.SHA256()))
cert_path, key_path = directory / "test-cert.pem", directory / "test-key.pem"
cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
key_path.chmod(0o600)
uvicorn.run("app.main:create_app", factory=True, host="127.0.0.1", port=8877, access_log=False,
            ssl_certfile=str(cert_path), ssl_keyfile=str(key_path))
