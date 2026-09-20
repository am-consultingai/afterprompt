"""The watchdog and the per-exposure status.

The watchdog answers one question — is this value still in a file on this disk — and the point of these
tests is that it answers it honestly: it finds a value that is still there, sees it go when the file is
cleaned, and says "unknown" rather than "gone" when it could not look.
"""
import json
import os
import time

from afterprompt import exposures, watch
from afterprompt.util import sha16
from tests.helpers import TempDirTest, write
from tests.samples import SecretFactory

KEY = SecretFactory(11).sample("anthropic_key")


def finding(home, name="s1.jsonl", value=KEY, **extra):
    """A finding shaped the way triage writes one, for a value we put in a file ourselves."""
    from afterprompt.vendor import value_part
    match = value.encode()
    row = {"hash": sha16(value_part("anthropic_key", match)), "match_hashes": [sha16(match)],
           "patterns": ["anthropic_key"], "category": "pattern", "label": "Anthropic API key",
           "locations": [{"display": "~/" + name, "tool": "Claude Code", "side": "linux", "count": 1,
                          "decoded": False}],
           "still_on_disk": [], "decoded_only": False}
    row.update(extra)
    return row


class CheckTests(TempDirTest):
    def setUp(self):
        super().setUp()
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)

    def test_it_finds_the_value_that_is_still_there(self):  # U-WAT-1
        write(os.path.join(self.home, "s1.jsonl"), '{"text": "here is my key %s ok"}\n' % KEY)
        r = watch.check(finding(self.home), self.home)
        self.assertEqual(r["state"], watch.PRESENT)
        self.assertEqual([os.path.basename(p) for p in r["in"]], ["s1.jsonl"])
        self.assertIsNotNone(r["checked"])

    def test_it_sees_the_value_go(self):  # U-WAT-2
        path = os.path.join(self.home, "s1.jsonl")
        write(path, '{"text": "here is my key %s ok"}\n' % KEY)
        f = finding(self.home)
        self.assertEqual(watch.check(f, self.home)["state"], watch.PRESENT)
        write(path, '{"text": "here is my key [removed] ok"}\n')
        r = watch.check(f, self.home)
        self.assertEqual(r["state"], watch.GONE)
        self.assertEqual(r["in"], [])

    def test_a_deleted_file_counts_as_gone(self):  # U-WAT-3
        path = os.path.join(self.home, "s1.jsonl")
        write(path, KEY)
        f = finding(self.home)
        os.remove(path)
        self.assertEqual(watch.check(f, self.home)["state"], watch.GONE)

    def test_another_environment_is_unknown_not_gone(self):  # U-WAT-4
        """A WSL distro's files are not reachable from here, and saying "gone" would be a lie."""
        f = finding(self.home)
        f["locations"][0]["side"] = "wsl:Ubuntu"
        r = watch.check(f, self.home, side="linux")
        self.assertEqual(r["state"], watch.UNKNOWN)
        self.assertIn("another environment", r["why"])

    def test_a_decoded_only_finding_is_unknown(self):  # U-WAT-5
        """It was never in the raw file as plain text, so not finding it there proves nothing."""
        write(os.path.join(self.home, "s1.jsonl"), "nothing to see")
        f = finding(self.home, decoded_only=True)
        f["locations"][0]["decoded"] = True
        r = watch.check(f, self.home)
        self.assertEqual(r["state"], watch.UNKNOWN)
        self.assertIn("decoded", r["why"])

    def test_a_file_too_large_is_not_read(self):  # U-WAT-6
        write(os.path.join(self.home, "s1.jsonl"), KEY)
        r = watch.check(finding(self.home), self.home, cap=4)
        self.assertEqual(r["state"], watch.UNKNOWN)
        self.assertIn("no file", r["why"])

    def test_it_checks_the_store_the_live_value_sits_in(self):  # U-WAT-7
        write(os.path.join(self.home, "s1.jsonl"), "no key here")
        env = os.path.join(self.home, ".env")
        write(env, "ANTHROPIC_API_KEY=%s\n" % KEY)
        f = finding(self.home, still_on_disk=[{"store": "~/.env", "key": "ANTHROPIC_API_KEY"}])
        r = watch.check(f, self.home)
        self.assertEqual(r["state"], watch.PRESENT)
        self.assertEqual([os.path.basename(p) for p in r["in"]], [".env"])

    def test_one_pass_reads_a_shared_file_once(self):  # U-WAT-8
        other = SecretFactory(12).sample("anthropic_key")
        write(os.path.join(self.home, "s1.jsonl"), "%s and %s\n" % (KEY, other))
        reads = []
        real = watch.hashes_in

        def counted(path, names, cap=watch.CAP):
            reads.append(path)
            return real(path, names, cap)

        watch.hashes_in = counted
        try:
            out = watch.check_all({"rotate": [finding(self.home), finding(self.home, value=other)],
                                   "review": []}, self.home)
        finally:
            watch.hashes_in = real
        self.assertEqual(len(reads), 1, "the same file was re-read for the second finding")
        self.assertEqual({r["state"] for r in out.values()}, {watch.PRESENT})

    def test_no_plaintext_is_written_anywhere(self):  # U-WAT-9
        write(os.path.join(self.home, "s1.jsonl"), KEY)
        f = finding(self.home)
        exposures.record_seen(self.tmp, {f["hash"]: watch.check(f, self.home)})
        with open(exposures.path(self.tmp), encoding="utf-8") as fh:
            saved = fh.read()
        self.assertNotIn(KEY, saved)
        self.assertIn(f["hash"], saved)


class StatusTests(TempDirTest):
    def test_only_a_real_status_on_a_real_hash(self):  # U-EXP-1
        h = "a" * 16
        self.assertIsNone(exposures.set_status(self.tmp, h, "vanished"))
        self.assertIsNone(exposures.set_status(self.tmp, "nope", exposures.ROTATED))
        self.assertIsNone(exposures.set_status(self.tmp, "../../etc/passwd", exposures.ROTATED))
        self.assertEqual(exposures.load(self.tmp), {})
        row = exposures.set_status(self.tmp, h, exposures.ROTATING)
        self.assertEqual(row["status"], "rotating")
        self.assertEqual(exposures.load(self.tmp)[h]["status"], "rotating")

    def test_what_you_decided_and_what_was_observed_stay_apart(self):  # U-EXP-2
        """Rotating a key does not delete the transcript: "rotated, still on disk" has to be sayable."""
        h = "b" * 16
        exposures.set_status(self.tmp, h, exposures.ROTATED)
        exposures.record_seen(self.tmp, {h: {"state": "present", "in": ["/home/u/.claude/history.jsonl"],
                                             "checked": 1789000000, "why": None}})
        row = exposures.load(self.tmp)[h]
        self.assertEqual(row["status"], "rotated")
        self.assertEqual(row["seen"]["state"], "present")
        self.assertEqual(row["seen"]["in"], ["/home/u/.claude/history.jsonl"])

    def test_a_change_of_what_is_seen_is_reported(self):  # U-EXP-3
        h = "c" * 16
        exposures.record_seen(self.tmp, {h: {"state": "present", "checked": 1}})
        self.assertEqual(exposures.record_seen(self.tmp, {h: {"state": "present", "checked": 2}}), {})
        self.assertEqual(exposures.record_seen(self.tmp, {h: {"state": "gone", "checked": 3}}), {h: "gone"})

    def test_a_tick_from_an_older_version_means_rotated(self):  # U-EXP-4
        h = "d" * 16
        with open(os.path.join(self.tmp, "checklist.json"), "w", encoding="utf-8") as fh:
            json.dump({h: True, "e" * 16: False, "bad": True}, fh)
        self.assertEqual(exposures.adopt_checklist(self.tmp), 1)
        items = exposures.load(self.tmp)
        self.assertEqual(items[h]["status"], "rotated")
        self.assertNotIn("e" * 16, items)
        self.assertEqual(exposures.adopt_checklist(self.tmp), 0)      # and it does not undo a later change

    def test_a_hostile_file_degrades_to_nothing(self):  # U-EXP-5
        write(exposures.path(self.tmp), "{ not json")
        self.assertEqual(exposures.load(self.tmp), {})
        write(exposures.path(self.tmp), json.dumps({"items": {"f" * 16: {"status": "rotated", "updated": "soon",
                                                                        "seen": {"state": "made up"}},
                                                              "../etc": {"status": "rotated"}}}))
        items = exposures.load(self.tmp)
        self.assertEqual(list(items), ["f" * 16])
        self.assertEqual(items["f" * 16]["status"], "rotated")
        self.assertIsNone(items["f" * 16]["updated"])
        self.assertNotIn("seen", items["f" * 16])
