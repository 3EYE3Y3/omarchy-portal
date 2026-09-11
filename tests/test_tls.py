from __future__ import annotations

import io
import os
import ssl
import subprocess
import tempfile
import threading
import unittest
from contextlib import redirect_stderr
from pathlib import Path

from portal.backend import FakeBackend
from portal.core import PortalCore
from portal.service import (
    CERTIFICATE_RSA_BITS,
    Handler,
    PortalHTTPServer,
    _certificate_is_compatible,
    create_tls_context,
    ensure_certificate,
    tls_failure_category,
)
from tests.helpers import Clock


ROOT = Path(__file__).resolve().parents[1]


def openssl(*args: str, input_text: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["openssl", *args],
        input=input_text,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )


class CertificateProfileTests(unittest.TestCase):
    def test_certificate_has_interoperable_server_profile(self):
        with tempfile.TemporaryDirectory() as temp:
            cert, key = ensure_certificate(Path(temp), "192.168.4.33")
            details = openssl("x509", "-in", str(cert), "-noout", "-text")
            names = openssl(
                "x509",
                "-in",
                str(cert),
                "-noout",
                "-subject",
                "-issuer",
                "-nameopt",
                "RFC2253",
            )

            self.assertEqual(details.returncode, 0, details.stderr)
            self.assertEqual(names.returncode, 0, names.stderr)
            self.assertIn("subject=CN=Portal Local", names.stdout)
            self.assertIn("issuer=CN=Portal Local", names.stdout)
            self.assertIn("Public Key Algorithm: rsaEncryption", details.stdout)
            self.assertIn(f"Public-Key: ({CERTIFICATE_RSA_BITS} bit)", details.stdout)
            self.assertIn("Signature Algorithm: sha256WithRSAEncryption", details.stdout)
            self.assertIn("CA:FALSE", details.stdout)
            self.assertIn("Digital Signature", details.stdout)
            self.assertIn("TLS Web Server Authentication", details.stdout)
            self.assertIn("IP Address:192.168.4.33", details.stdout)
            self.assertIn("IP Address:127.0.0.1", details.stdout)
            self.assertIn("DNS:localhost", details.stdout)
            self.assertEqual(os.stat(cert).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(key).st_mode & 0o777, 0o600)
            self.assertTrue(_certificate_is_compatible(cert, key, "192.168.4.33"))

    def test_legacy_ed25519_certificate_is_replaced(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp)
            cert, key = state / "tls.crt", state / "tls.key"
            legacy = openssl(
                "req",
                "-x509",
                "-newkey",
                "ed25519",
                "-nodes",
                "-days",
                "30",
                "-subj",
                "/CN=Portal Local",
                "-addext",
                "subjectAltName=IP:192.168.4.33,IP:127.0.0.1",
                "-keyout",
                str(key),
                "-out",
                str(cert),
            )
            self.assertEqual(legacy.returncode, 0, legacy.stderr)
            old_certificate = cert.read_bytes()

            ensure_certificate(state, "192.168.4.33")

            self.assertNotEqual(cert.read_bytes(), old_certificate)
            details = openssl("x509", "-in", str(cert), "-noout", "-text")
            self.assertIn("Public Key Algorithm: rsaEncryption", details.stdout)
            self.assertTrue(_certificate_is_compatible(cert, key, "192.168.4.33"))


class TLSHandshakeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        state = Path(self.temp.name)
        cert, key = ensure_certificate(state, "127.0.0.1")
        core = PortalCore(
            state,
            FakeBackend(),
            Clock(),
            "https://127.0.0.1",
        )
        self.server = PortalHTTPServer(
            ("127.0.0.1", 0), Handler, core, ROOT / "web"
        )
        self.server.allowed_origins = {"https://127.0.0.1"}
        self.server.tls_context = create_tls_context(cert, key)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        self.temp.cleanup()

    def client(self, *args: str) -> subprocess.CompletedProcess[str]:
        return openssl(
            "s_client",
            "-connect",
            f"127.0.0.1:{self.port}",
            "-noservername",
            *args,
            input_text=(
                "GET /api/health HTTP/1.1\r\n"
                "Host: 127.0.0.1\r\n"
                "Connection: close\r\n\r\n"
            ),
        )

    def test_rsa_signature_client_negotiates_tls13_without_sni(self):
        result = self.client(
            "-tls1_3",
            "-sigalgs",
            "rsa_pss_rsae_sha256:rsa_pkcs1_sha256",
            "-alpn",
            "h2,http/1.1",
            "-brief",
        )
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        self.assertIn("Protocol version: TLSv1.3", output)
        self.assertIn("Ciphersuite: TLS_AES_", output)

    def test_rsa_signature_client_negotiates_modern_tls12(self):
        result = self.client(
            "-tls1_2",
            "-cipher",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "-sigalgs",
            "rsa_pss_rsae_sha256:rsa_pkcs1_sha256",
            "-brief",
        )
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        self.assertIn("Protocol version: TLSv1.2", output)
        self.assertIn("ECDHE-RSA-AES128-GCM-SHA256", output)

    def test_context_keeps_strong_defaults_and_http11_alpn(self):
        context = self.server.tls_context
        self.assertIsNotNone(context)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertEqual(context.maximum_version, ssl.TLSVersion.MAXIMUM_SUPPORTED)
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)
        self.assertGreaterEqual(context.security_level, 2)

        result = self.client("-alpn", "h2,http/1.1")
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        self.assertIn("ALPN protocol: http/1.1", output)

    def test_signature_mismatch_is_logged_without_clienthello_data(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = self.client(
                "-tls1_3",
                "-sigalgs",
                "ecdsa_secp256r1_sha256",
                "-brief",
            )

        self.assertNotEqual(result.returncode, 0)
        log = stderr.getvalue()
        self.assertIn("portal-tls peer=127.0.0.1", log)
        self.assertIn("category=cipher_or_signature", log)
        self.assertIn("reason=NO_SUITABLE_SIGNATURE_ALGORITHM", log)
        self.assertNotIn("ClientHello", log)

    def test_tls_failure_categories_cover_diagnostic_boundaries(self):
        self.assertEqual(
            tls_failure_category("NO_SHARED_CIPHER"), "cipher_or_signature"
        )
        self.assertEqual(
            tls_failure_category("UNSUPPORTED_PROTOCOL"), "unsupported_protocol"
        )
        self.assertEqual(
            tls_failure_category("HTTP_REQUEST"), "malformed_handshake"
        )
        self.assertEqual(
            tls_failure_category("PEER_DID_NOT_RETURN_A_CERTIFICATE"), "certificate"
        )
        self.assertEqual(tls_failure_category("SSL_INTERNAL_ERROR"), "other_ssl_error")


if __name__ == "__main__":
    unittest.main()
