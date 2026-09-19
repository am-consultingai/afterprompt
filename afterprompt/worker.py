"""Worker protocol (M1): one JSON object per line on the worker's stdout.

A worker is an ordinary scan started with --worker. It scans the environment it runs in and reports back to the
orchestrator that started it. It never orchestrates.

    {"afterprompt": 1, "type": "hello",  "version": "0.3.0", "platform": "wsl", "other_homes": ["bob"]}
    {"afterprompt": 1, "type": "say",    "text": "[3/9] Listing files …"}
    {"afterprompt": 1, "type": "result", "exit": 10, "findings": {…findings.json…}}
    {"afterprompt": 1, "type": "error",  "exit": 5, "message": "…"}

stdout rather than a socket: nothing else on the machine can connect to a worker, and no port or firewall is
involved. Any other line on stdout (the launcher's own messages, such as a ripgrep download) is not protocol and
is shown as plain text. Only masked values and hashes ever travel this way, never a plaintext secret.
"""
import json
import sys
import threading

PROTOCOL = 1
KEY = "afterprompt"


def encode(kind, **fields):
    msg = {KEY: PROTOCOL, "type": kind}
    msg.update(fields)
    return json.dumps(msg, ensure_ascii=True, separators=(",", ":"))


def decode(line):
    """The message on this line, or None when the line is not protocol."""
    if isinstance(line, bytes):
        line = line.decode("utf-8", "replace")
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        msg = json.loads(line)
    except ValueError:
        return None
    if not isinstance(msg, dict) or msg.get(KEY) != PROTOCOL or not isinstance(msg.get("type"), str):
        return None
    return msg


class Emitter:
    """Writes protocol lines to the real stdout, whole lines only, from any thread."""

    def __init__(self, stream=None):
        self.stream = stream or sys.stdout
        self.lock = threading.Lock()

    def __call__(self, kind, **fields):
        line = encode(kind, **fields) + "\n"
        with self.lock:
            self.stream.write(line)
            self.stream.flush()
