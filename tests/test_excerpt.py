"""The reader: where a credential sits in a file, with every secret around it masked, or why it will not show it.

The line these tests hold above all is that nothing the reader returns contains a secret in full — not the
credential asked about, not another finding that happens to sit next to it, not a value a pattern would catch,
not a random-looking token, and not part of one cut at a window's edge. Each test serialises the whole answer and
looks for the raw values in it, because that is what reaches the browser.
"""
import json
import os
import sqlite3

from afterprompt import excerpt, triage
from afterprompt.util import mask, sha16
from tests.helpers import TempDirTest, write
from tests.samples import SecretFactory

S = SecretFactory(7)
KEY = S.sample("anthropic_key")
OTHER = S.sample("github_token")
RANDOM_TOKEN = "Zq8vT3kLm9Xw2Rb7Yp4Nc6Hd1Gf5Js0A"       # no pattern names it; the net must still mask it


def slurp(path):
    with open(path, "rb") as fh:
        return fh.read()


def finding(value, display, side="linux", patterns=("anthropic_key",), **extra):
    """A finding shaped the way triage writes one."""
    b = value.encode()
    row = {"hash": sha16(b), "match_hashes": [sha16(b)], "masked": mask(b), "length": len(b),
           "patterns": list(patterns), "label": "Anthropic API key", "category": "pattern",
           "locations": [{"display": display, "tool": "Claude Code", "side": side, "count": 1, "decoded": False}]}
    row.update(extra)
    return row


class Base(TempDirTest):
    def setUp(self):
        super().setUp()
        self.home = os.path.join(self.tmp, "home")

    def report(self, *rows, review=()):
        return {"platform": {"kind": "linux"}, "environments": [{"kind": "host", "side": "linux"}],
                "rotate": list(rows), "review": list(review), "finished": "2026-09-26T10:00:00"}

    def open(self, data, f, index=0, **kw):
        return excerpt.open_location(data, f["hash"], index, plat="linux", home=self.home, **kw)

    def assert_nothing_raw(self, out, *values):
        blob = json.dumps(out)
        for v in values:
            self.assertNotIn(v, blob, "a full secret reached the answer")
            # Nor any run of it long enough to be most of one.
            for i in range(0, len(v) - 12):
                self.assertNotIn(v[i:i + 12], blob, f"part of a secret reached the answer: {v[i:i + 12]}")

    def text(self, hit, part="text"):
        return "".join(p["t"] for p in hit[part] or [])


class TextFileTests(Base):
    def write_transcript(self, *lines):
        return write(os.path.join(self.home, ".claude", "projects", "p", "s.jsonl"), "".join(l + "\n" for l in lines))

    def test_finds_the_value_and_masks_it(self):
        self.write_transcript(json.dumps({"type": "user", "message": {"role": "user", "content": "hello"}}),
                              json.dumps({"type": "user", "message": {"role": "user",
                                                                      "content": f"use this key {KEY} please"}}),
                              json.dumps({"type": "assistant", "message": {"role": "assistant", "content": "ok"}}))
        f = finding(KEY, "~/.claude/projects/p/s.jsonl")
        out = self.open(self.report(f), f)
        self.assertTrue(out["ok"], out)
        self.assertEqual((out["kind"], out["total"]), ("text", 1))
        hit = out["hits"][0]
        self.assertEqual(hit["line"], 2)
        self.assertEqual(hit["who"], "user")
        targets = [p for p in hit["text"] if p.get("k") == "target"]
        self.assertEqual([p["t"] for p in targets], [f["masked"]])
        self.assertIn("use this key", self.text(hit))
        self.assertIn("hello", self.text(hit, "before"))           # the line before, as context
        self.assertIn("ok", self.text(hit, "after"))
        self.assert_nothing_raw(out, KEY)

    def test_every_other_secret_in_the_window_is_masked_too(self):
        """Another finding, a value a pattern names, and a random token no pattern names: none is shown."""
        line = f"key {KEY} and a github token {OTHER} and a session {RANDOM_TOKEN} end"
        self.write_transcript(line)
        f = finding(KEY, "~/.claude/projects/p/s.jsonl")
        other = finding(OTHER, "~/.claude/projects/p/s.jsonl", patterns=("github_token",), label="GitHub token")
        out = self.open(self.report(f, other), f)
        kinds = {p.get("k") for p in out["hits"][0]["text"]}
        self.assertLessEqual({"target", "other", "hidden"}, kinds)
        linked = [p for p in out["hits"][0]["text"] if p.get("k") == "other"]
        self.assertEqual(linked[0]["hash"], other["hash"])         # the page can open that finding from here
        self.assert_nothing_raw(out, KEY, OTHER, RANDOM_TOKEN)

    def test_a_window_never_cuts_a_secret_in_half(self):
        """The value's line is kept to a window either side; a token straddling that edge is not shown in part."""
        pad = "x " * 80
        edge = pad + RANDOM_TOKEN + " " + ("y " * 5) + KEY + " " + ("z " * 5) + RANDOM_TOKEN[::-1] + " " + pad
        self.write_transcript(edge)
        f = finding(KEY, "~/.claude/projects/p/s.jsonl")
        out = self.open(self.report(f), f)
        self.assertTrue(out["ok"])
        self.assert_nothing_raw(out, KEY, RANDOM_TOKEN, RANDOM_TOKEN[::-1])

    def test_an_edge_moves_off_a_token_no_detector_names(self):
        """A password with too little entropy for the net and no pattern of its own: if the window's edge lands in
        it, the edge moves off it, so it is shown whole or not at all — never in part."""
        weak = "summersummersummer2026winter"
        self.assertFalse(excerpt.looks_random(weak.encode()))
        for shift in range(0, len(weak), 3):
            with self.subTest(shift=shift):
                line = "a " * 100 + weak + " " * (excerpt.AROUND - len(weak) + shift) + KEY + " b" * 100
                self.write_transcript(line)
                f = finding(KEY, "~/.claude/projects/p/s.jsonl")
                text = self.text(self.open(self.report(f), f)["hits"][0])
                if weak not in text:
                    for i in range(1, len(weak) - 3):
                        self.assertFalse(text.lstrip().startswith(weak[i:i + 4]), f"cut at {i}: {text[:40]!r}")

    def test_a_long_line_is_windowed_and_says_so(self):
        self.write_transcript("a" * 5000 + " " + KEY + " " + "b" * 5000)
        f = finding(KEY, "~/.claude/projects/p/s.jsonl")
        hit = self.open(self.report(f), f)["hits"][0]
        self.assertTrue(hit["cut_before"] and hit["cut_after"])
        self.assertLess(len(self.text(hit)), 2 * excerpt.AROUND + 100)

    def test_names_stay_readable_beside_a_masked_value(self):
        self.write_transcript(f"ANTHROPIC_API_KEY={KEY}")
        f = finding(KEY, "~/.claude/projects/p/s.jsonl")
        text = self.text(self.open(self.report(f), f)["hits"][0])
        self.assertIn("ANTHROPIC_API_KEY=", text)
        self.assertIn(f["masked"], text)

    def test_uuids_are_identifiers_and_stay_readable(self):
        self.write_transcript(f'{{"sessionId": "29e27164-3b8c-4249-9e6f-6b3d1791b65e", "k": "{KEY}"}}')
        f = finding(KEY, "~/.claude/projects/p/s.jsonl")
        self.assertIn("29e27164-3b8c-4249-9e6f-6b3d1791b65e", self.text(self.open(self.report(f), f)["hits"][0]))

    def test_a_json_line_reads_as_text(self):
        self.write_transcript(json.dumps({"text": f"line one\nline two \"quoted\" {KEY}"}))
        f = finding(KEY, "~/.claude/projects/p/s.jsonl")
        text = self.text(self.open(self.report(f), f)["hits"][0])
        self.assertIn('line one\nline two "quoted"', text)

    def test_found_by_pattern_when_the_masked_form_carries_no_prefix(self):
        """A short value is masked as abc***, so there is no prefix to search for; the scan's pattern finds it."""
        self.write_transcript(f"here {KEY} there")
        f = finding(KEY, "~/.claude/projects/p/s.jsonl", masked="sk-***")
        out = self.open(self.report(f), f)
        self.assertTrue(out["ok"], out)
        self.assert_nothing_raw(out, KEY)

    def test_many_places_are_counted_and_the_first_shown(self):
        self.write_transcript(*[f"n{i} {KEY}" for i in range(excerpt.MAX_HITS + 7)])
        f = finding(KEY, "~/.claude/projects/p/s.jsonl")
        out = self.open(self.report(f), f)
        self.assertEqual(out["total"], excerpt.MAX_HITS + 7)
        self.assertEqual(len(out["hits"]), excerpt.MAX_HITS)
        self.assertEqual([h["line"] for h in out["hits"][:3]], [1, 2, 3])


class RefusalTests(Base):
    """Each way a place cannot be shown comes back as a code the page explains, never as an error or a blank."""

    def code(self, out):
        self.assertFalse(out["ok"])
        return out["code"]

    def test_stale_page(self):
        write(os.path.join(self.home, "a.jsonl"), KEY)
        f = finding(KEY, "~/a.jsonl")
        for index in (1, -1, True, "0", None):
            with self.subTest(index=index):
                self.assertEqual(self.code(self.open(self.report(f), f, index=index)), "stale")
        self.assertEqual(self.code(excerpt.open_location(self.report(f), "f" * 16, 0)), "stale")

    def test_decoded_conversation_and_elsewhere(self):
        write(os.path.join(self.home, "a.jsonl"), KEY)
        cases = {"decoded": {"display": "~/a.jsonl", "side": "linux", "decoded": True},
                 "conversation": {"display": "Cursor chat, 2026-04-15", "side": "", "tool": "Cursor"},
                 "elsewhere": {"display": "~/a.jsonl", "side": "docker:api"}}
        for code, loc in cases.items():
            with self.subTest(code=code):
                f = finding(KEY, "~/a.jsonl")
                f["locations"] = [dict({"count": 1, "decoded": False, "tool": "Claude Code"}, **loc)]
                out = self.open(self.report(f), f)
                self.assertEqual(self.code(out), code)
                self.assertEqual(out["display"], loc["display"])     # the popup names the place it is about
        f = finding(KEY, "Cursor chat, 2026-04-15", side="", tool="Cursor")
        f["locations"][0]["tool"] = "Cursor"
        self.assertEqual(self.open(self.report(f), f)["params"]["where"], "Cursor chat, 2026-04-15")
        f["locations"][0]["tool"] = ""
        self.assertEqual(self.open(self.report(f), f)["tool"], "Cursor")          # named from the place

    def test_elsewhere_names_the_environment(self):
        f = finding(KEY, "~/a.jsonl", side="docker:api")
        data = self.report(f)
        data["environments"].append({"kind": "docker", "side": "docker:api", "label": "Docker: api"})
        self.assertEqual(self.open(data, f)["params"]["env"], "Docker: api")

    def test_gone_and_not_in_file(self):
        f = finding(KEY, "~/a.jsonl")
        self.assertEqual(self.code(self.open(self.report(f), f)), "gone")
        write(os.path.join(self.home, "a.jsonl"), "cleaned up\n")
        self.assertEqual(self.code(self.open(self.report(f), f)), "not_in_file")

    def test_too_large_and_binary(self):
        write(os.path.join(self.home, "a.jsonl"), "x" * 5000 + KEY)
        f = finding(KEY, "~/a.jsonl")
        out = self.open(self.report(f), f, cap=1000)
        self.assertEqual(self.code(out), "too_large")
        self.assertEqual((out["params"]["size"], out["params"]["limit"]), (5000 + len(KEY), 1000))
        write(os.path.join(self.home, "b.bin"), b"\0\1\2" + KEY.encode(), "wb")
        f = finding(KEY, "~/b.bin")
        self.assertEqual(self.code(self.open(self.report(f), f)), "binary")

    def test_cannot_locate_without_prefix_or_pattern(self):
        write(os.path.join(self.home, "a.jsonl"), KEY)
        f = finding(KEY, "~/a.jsonl", masked="sk-***", patterns=())
        self.assertEqual(self.code(self.open(self.report(f), f)), "cannot_locate")

    def test_unreadable_says_what_the_system_said(self):
        if os.name == "nt" or os.geteuid() == 0:
            self.skipTest("permissions are not enforced here")
        path = write(os.path.join(self.home, "a.jsonl"), KEY)
        os.chmod(path, 0)
        try:
            f = finding(KEY, "~/a.jsonl")
            out = self.open(self.report(f), f)
        finally:
            os.chmod(path, 0o600)
        self.assertEqual(self.code(out), "unreadable")
        self.assertIn("ermission", out["params"]["error"])


class DatabaseTests(Base):
    def db(self, rows):
        path = os.path.join(self.home, ".config", "Cursor", "state.vscdb")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        con = sqlite3.connect(path)
        con.execute("create table ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)")
        con.execute("create table cursorDiskKV (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)")
        for k, v in rows:
            con.execute("insert into cursorDiskKV values (?, ?)", (k, json.dumps(v).encode()))
        con.commit()
        con.close()
        return path

    def finding(self, records=None):
        f = finding(KEY, "~/.config/Cursor/state.vscdb (chat database)", tool="Cursor")
        if records is not None:
            f["locations"][0]["records"] = records
        return f

    def test_a_noted_record_is_fetched_by_key(self):
        self.db([("bubbleId:a", {"text": "nothing here"}), ("bubbleId:b", {"text": f"my key is {KEY}"})])
        f = self.finding([{"table": "cursorDiskKV", "key": "bubbleId:b"}])
        out = self.open(self.report(f), f)
        self.assertTrue(out["ok"], out)
        self.assertEqual((out["kind"], out["total"]), ("database", 1))
        self.assertEqual(out["hits"][0]["where"], "bubbleId:b")
        self.assertIn("my key is", self.text(out["hits"][0]))
        self.assert_nothing_raw(out, KEY)

    def test_a_record_that_no_longer_holds_it(self):
        self.db([("bubbleId:b", {"text": "edited"})])
        f = self.finding([{"table": "cursorDiskKV", "key": "bubbleId:b"}])
        self.assertEqual(self.open(self.report(f), f)["code"], "record_changed")

    def test_a_table_name_is_never_taken_from_the_report(self):
        """Only tables the database itself lists are queried: a record naming another is ignored, not run."""
        self.db([("bubbleId:b", {"text": KEY})])
        f = self.finding([{"table": 'cursorDiskKV" ; drop table cursorDiskKV; --', "key": "bubbleId:b"}])
        out = self.open(self.report(f), f)
        self.assertTrue(out["ok"])                    # fell back to searching, and found it
        con = sqlite3.connect(os.path.join(self.home, ".config", "Cursor", "state.vscdb"))
        self.assertEqual(con.execute("select count(*) from cursorDiskKV").fetchone()[0], 1)
        con.close()

    def test_an_older_report_is_searched_and_the_search_has_a_limit(self):
        self.db([(f"bubbleId:{i}", {"text": "filler " * 50}) for i in range(300)] + [("bubbleId:x", {"t": KEY})])
        f = self.finding()
        out = self.open(self.report(f), f)
        self.assertTrue(out["ok"], out)
        self.assertEqual(out["hits"][0]["where"], "bubbleId:x")
        path = os.path.join(self.home, ".config", "Cursor", "state.vscdb")
        ticks = iter(range(0, 10 ** 6, 5))
        out = excerpt.read_database(path, f, f["locations"][0], excerpt.Others({}), seconds=1,
                                    clock=lambda: next(ticks), steps=1)
        self.assertEqual(out["code"], "db_timeout")
        self.assertEqual(out["params"]["seconds"], 1)

    def test_a_database_is_never_changed(self):
        path = self.db([("bubbleId:b", {"text": KEY})])
        before = os.path.getmtime(path), os.path.getsize(path)
        f = self.finding([{"table": "cursorDiskKV", "key": "bubbleId:b"}])
        self.open(self.report(f), f)
        self.assertEqual((os.path.getmtime(path), os.path.getsize(path)), before)
        self.assertFalse(os.path.exists(path + "-journal") or os.path.exists(path + "-wal"))


class RecordTests(TempDirTest):
    """The scan notes which database row a value was in, so the reader can fetch it instead of searching."""

    def test_record_at_reads_the_row_a_hit_sits_in(self):
        dump = write(os.path.join(self.tmp, "extracted", "db", "000_00.txt"),
                     "### SOURCE /x/state.vscdb\n"
                     "### ItemTable | key=workbench | value={}\n"
                     f"### cursorDiskKV | key=bubbleId:c1:b2 | value={{\"text\": \"{KEY}\"}}\n")
        offset = slurp(dump).index(KEY.encode())
        self.assertEqual(triage.record_at(dump, offset), {"table": "cursorDiskKV", "key": "bubbleId:c1:b2"})
        self.assertIsNone(triage.record_at(dump, 3))                  # the SOURCE header is not a row
        self.assertIsNone(triage.record_at(os.path.join(self.tmp, "missing.txt"), 10))

    def test_locations_keep_a_few_records_each(self):
        ext = os.path.join(self.tmp, "extracted", "db")
        rows = "".join(f"### cursorDiskKV | key=bubbleId:{i} | value={KEY}\n" for i in range(9))
        dump = write(os.path.join(ext, "000_00.txt"), rows)
        blob = slurp(dump)
        at, hits = 0, []
        for _ in range(9):
            at = blob.index(KEY.encode(), at + 1)
            hits.append({"display": "C:\\x\\state.vscdb (chat database)", "decoded": False, "tool": "Cursor",
                         "side": "windows", "f": dump, "o": at})
        locs = triage.summarize_locations(hits, ext)
        self.assertEqual(locs[0]["count"], 9)
        self.assertEqual([r["key"] for r in locs[0]["records"]], [f"bubbleId:{i}" for i in range(5)])
        # Outside the extracted dumps there is no record to note.
        self.assertNotIn("records", triage.summarize_locations(hits, os.path.join(self.tmp, "elsewhere"))[0])
