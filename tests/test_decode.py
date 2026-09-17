import base64
import binascii
import gzip
import io
import json
import os
import tarfile
import time
import zipfile

from afterprompt import decode
from tests.helpers import TempDirTest, write

SECRET = b"SECRET_VALUE_Z9q8w7e6r5t4y3"


def expanded(data):
    out = []
    decode.expand(data, 0, out.append)
    return b"\n".join(out)


class DecodeTests(TempDirTest):
    def test_unicode_escape(self):  # U-DEC-1
        self.assertIn(SECRET, expanded(b'{"t": "\\u0041' + SECRET + b'\\n"}'))

    def test_url(self):  # U-DEC-2
        self.assertIn(SECRET, expanded(b"q=token%3D" + SECRET + b"%26x%3D1"))

    def test_base64_variants(self):  # U-DEC-3
        self.assertIn(SECRET, expanded(base64.b64encode(b"key=" + SECRET + b" more text here")))
        urlsafe = base64.urlsafe_b64encode(b"\xfb\xff" + b"key=" + SECRET + b"~~~~ tail text").rstrip(b"=")
        self.assertIn(SECRET, expanded(b"x " + urlsafe + b" y"))
        self.assertIn(b"pw:Hunter2024", expanded(b" " + base64.b64encode(b"pw:Hunter2024") + b" "))

    def test_hex(self):  # U-DEC-4
        self.assertIn(SECRET, expanded(binascii.hexlify(b"key=" + SECRET)))

    def test_gzip_in_base64(self):  # U-DEC-5
        self.assertIn(SECRET, expanded(base64.b64encode(gzip.compress(b"key=" + SECRET + b" " * 50))))

    def test_archives(self):  # U-DEC-6
        z = os.path.join(self.tmp, "a.zip")
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("inner.txt", b"key=" + SECRET)
        t = os.path.join(self.tmp, "a.tar")
        with tarfile.open(t, "w") as tf:
            data = b"key=" + SECRET
            info = tarfile.TarInfo("inner.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        g = write(os.path.join(self.tmp, "a.gz"), gzip.compress(b"key=" + SECRET), "wb")
        for p in (z, t, g):
            with self.subTest(archive=p):
                out = os.path.join(self.tmp, os.path.basename(p) + ".out")
                status, n = decode.decode_path(p, out, 10 ** 6, 60)
                with open(out, "rb") as fh:
                    self.assertIn(SECRET, fh.read())

    def test_jwt_payload(self):  # U-DEC-7
        payload = base64.urlsafe_b64encode(json.dumps({"api_key": SECRET.decode()}).encode()).rstrip(b"=")
        tok = b"eyJhbGciOiJIUzI1NiJ9." + payload + b".sig"
        self.assertIn(SECRET, expanded(b" " + tok + b" "))

    def test_depth_limit(self):  # U-DEC-8
        data = b"key=" + SECRET
        for _ in range(6):
            data = base64.b64encode(data + b" padding text")
        self.assertNotIn(SECRET, expanded(data))

    def test_output_cap(self):  # U-DEC-9
        src = write(os.path.join(self.tmp, "big.txt"), (base64.b64encode(os.urandom(3000)).decode() + "\n") * 50 +
                    (base64.b64encode(b"plain readable text " * 50).decode() + "\n") * 50)
        status, n = decode.decode_path(src, os.path.join(self.tmp, "o.txt"), 100, 60)
        self.assertEqual(status, "output-cap")

    def test_deadline(self):  # U-DEC-10
        src = write(os.path.join(self.tmp, "t.txt"), base64.b64encode(b"readable text " * 100).decode())
        real = time.monotonic
        start = real()
        calls = {"n": 0}

        def fake():
            calls["n"] += 1
            return start if calls["n"] == 1 else start + 10_000
        decode.time.monotonic = fake
        try:
            status, _ = decode.decode_path(src, os.path.join(self.tmp, "o.txt"), 10 ** 6, 5)
        finally:
            decode.time.monotonic = real
        self.assertEqual(status, "timeout")
