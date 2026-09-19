"""M1: the worker line protocol."""
import io
import json
import threading
import unittest

from afterprompt import worker


class ProtocolTests(unittest.TestCase):
    def test_round_trip(self):  # U-WRK-1
        line = worker.encode("result", exit=10, findings={"rotate": [{"masked": "sk-ant…DEMO"}]})
        self.assertNotIn("\n", line)
        msg = worker.decode(line + "\n")
        self.assertEqual(msg["type"], "result")
        self.assertEqual(msg["exit"], 10)
        self.assertEqual(msg["findings"]["rotate"][0]["masked"], "sk-ant…DEMO")
        self.assertEqual(worker.decode(line.encode("utf-8")), msg)

    def test_one_line_even_for_awkward_text(self):  # U-WRK-2
        # Newlines and non-ASCII must never split a message across lines or depend on the pipe's encoding.
        line = worker.encode("say", text="line one\nline two · ✓  ")
        self.assertEqual(len(line.splitlines()), 1)
        self.assertTrue(line.isascii())
        self.assertEqual(worker.decode(line)["text"], "line one\nline two · ✓  ")

    def test_non_protocol_lines(self):  # U-WRK-3
        # The launcher prints its own lines (a ripgrep download) on the same stdout: they are text, not messages.
        for line in ("ripgrep not found; downloading ripgrep 15.2.0…", "", "   ", "{not json", "[1, 2]",
                     json.dumps({"type": "result"}), json.dumps({"afterprompt": 2, "type": "result"}),
                     json.dumps({"afterprompt": 1, "type": 5}), b"\xff\xfe garbage"):
            with self.subTest(line=line):
                self.assertIsNone(worker.decode(line))

    def test_emitter_writes_whole_lines_from_threads(self):  # U-WRK-4
        buf = io.StringIO()
        emit = worker.Emitter(buf)
        threads = [threading.Thread(target=lambda i=i: [emit("say", text=f"t{i}-{n}" * 50) for n in range(50)])
                   for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        lines = buf.getvalue().splitlines()
        self.assertEqual(len(lines), 400)
        self.assertTrue(all(worker.decode(l)["type"] == "say" for l in lines))
