"""Blast-radius ranking: the data behind it stays in step with patterns.json, and it orders the list."""
import unittest

from afterprompt import impact, triage
from afterprompt.patterns import GROUPS, REVOKE, RULES


def rotate_rec(label, patterns=(), keys=(), category="live_credential", tier="A", files=1, occurrences=1):
    rec = {"label": label, "category": category, "tier": tier, "files": files, "occurrences": occurrences,
           "patterns": list(patterns)}
    rec["impact"] = impact.rank(rec["patterns"], keys)
    return rec


class ImpactDataTests(unittest.TestCase):
    """The tables are data about 140 patterns; a rename in patterns.json must fail here, not go quiet."""

    def test_every_group_has_a_rank(self):  # U-IMP-1
        missing = sorted({g for g in GROUPS.values() if g not in impact.GROUP_RANK})
        self.assertEqual(missing, [], "patterns.json groups with no rank in impact.GROUP_RANK")

    def test_every_override_names_a_real_pattern(self):  # U-IMP-2
        known = {p["name"] for p in RULES}
        self.assertEqual(sorted(set(impact.NAME_RANK) - known), [])

    def test_ranks_are_known(self):  # U-IMP-3
        for name, rank in list(impact.NAME_RANK.items()) + list(impact.GROUP_RANK.items()):
            self.assertIn(rank, impact.RANKS, name)
        for rank in impact.RANKS:
            self.assertIn(rank, impact.LABELS)
            self.assertIn(rank, impact.NOTES)

    def test_every_pattern_gets_a_rank(self):  # U-IMP-4
        for p in RULES:
            self.assertIn(impact.rank([p["name"]]), impact.RANKS, p["name"])


class ImpactRankTests(unittest.TestCase):
    def test_worst_signal_wins(self):  # U-IMP-5
        self.assertEqual(impact.rank(["brave_api_key", "aws_access_key_id"]), "money")
        self.assertEqual(impact.rank(["brave_api_key"]), "service")

    def test_a_shape_does_not_outvote_the_vendor(self):  # U-IMP-5b
        """A Brave key written as BRAVE_API_KEY=… matches env_assignment too; the `=` knows nothing."""
        self.assertEqual(impact.rank(["brave_api_key_ctx", "brave_api_key", "env_assignment"],
                                     ["mcpServers.brave-search.env.BRAVE_API_KEY"]), "service")
        # With no vendor pattern to go on, the shape is all there is, and it still counts.
        self.assertEqual(impact.rank(["env_assignment"]), "access")

    def test_unknown_ranks_last_rather_than_loudest(self):  # U-IMP-6
        self.assertEqual(impact.rank(["no_such_pattern"], ["NO_SUCH_THING"]), "service")

    def test_variable_names_rank_live_credentials(self):  # U-IMP-7
        # A live credential in a .env has no pattern behind it: its name is all there is.
        self.assertEqual(impact.rank([], ["AZURE_STORAGE_CONNECTION_STRING"]), "data")
        self.assertEqual(impact.rank([], ["GOOGLE_CLIENT_SECRET"]), "access")
        self.assertEqual(impact.rank([], ["ANTHROPIC_API_KEY"]), "money")
        self.assertEqual(impact.rank([], ["DATABASE_URL"]), "data")

    def test_storage_is_data_not_spend(self):  # U-IMP-8
        """Both words are in AZURE_STORAGE_ACCOUNT_KEY; what the key opens is storage."""
        self.assertEqual(impact.rank([], ["AZURE_STORAGE_ACCOUNT_KEY"]), "data")
        self.assertEqual(impact.rank(["azure_storage_key"]), "data")


class RotateOrderTests(unittest.TestCase):
    def test_the_real_scan_order(self):  # U-IMP-9
        """From the report that prompted this: a search key led a list holding storage and OAuth secrets."""
        brave = rotate_rec("Brave Search API key", ["brave_api_key"], ["BRAVE_API_KEY"], files=8, occurrences=9)
        azure = rotate_rec("Azure Storage account key", [], ["AZURE_STORAGE_CONNECTION_STRING"], occurrences=59)
        oauth = rotate_rec("Google OAuth client secret", ["gcp_client_secret"], ["GOOGLE_CLIENT_SECRET"])
        order = [r["label"] for r in sorted([brave, azure, oauth], key=triage.rotate_key)]
        self.assertEqual(order, ["Azure Storage account key", "Google OAuth client secret",
                                 "Brave Search API key"])

    def test_counts_still_break_ties(self):  # U-IMP-10
        few = rotate_rec("Anthropic API key", ["anthropic_key"], files=1, occurrences=1)
        many = rotate_rec("OpenAI API key", ["openai_project_key"], files=4, occurrences=9)
        self.assertEqual([r["label"] for r in sorted([few, many], key=triage.rotate_key)],
                         ["OpenAI API key", "Anthropic API key"])

    def test_a_record_from_an_older_version_still_sorts(self):  # U-IMP-11
        old = {"label": "Old", "category": "pattern", "tier": "A", "files": 1, "occurrences": 1}
        new = rotate_rec("New", ["aws_access_key_id"])
        self.assertEqual([r["label"] for r in sorted([old, new], key=triage.rotate_key)], ["New", "Old"])


class KeyRevokeTests(unittest.TestCase):
    """Every rotate finding should end at a page, not at a question."""

    def test_the_names_from_the_real_report(self):  # U-IMP-12
        for key in ("GOOGLE_CLIENT_SECRET", "AZURE_STORAGE_CONNECTION_STRING", "AZURE_FOUNDRY_API_KEY",
                    "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "BRAVE_API_KEY"):
            hint = triage.key_revoke(key)
            self.assertIsNotNone(hint, key)
            self.assertTrue(str(hint["url"]).startswith("https://"), key)

    def test_every_mapping_points_at_a_pattern_that_knows_where(self):  # U-IMP-13
        for rx, name in triage.KEY_REVOKE:
            self.assertIn(name, REVOKE, f"{rx} points at {name}, which has no revoke url in patterns.json")

    def test_shapes_without_a_vendor_still_say_what_to_do(self):  # U-IMP-14
        self.assertIn("database password", triage.key_revoke("DATABASE_URL")["where"])
        self.assertIn("key pair", triage.key_revoke("SSH_PRIVATE_KEY")["where"])
        self.assertIsNone(triage.key_revoke("DATABASE_URL")["url"])

    def test_the_fallback_answers_instead_of_asking(self):  # U-IMP-15
        hint = triage.store_hint("/home/me/app/.env", "WIDGETCO_SECRET")
        self.assertNotEqual(hint["where"], "The service that issued WIDGETCO_SECRET")
        self.assertIn("WIDGETCO_SECRET", hint["where"])
        self.assertIn("revoke", hint["where"].lower())

    def test_a_store_file_still_wins_over_the_name(self):  # U-IMP-16
        self.assertEqual(triage.store_hint("/home/me/.aws/credentials", "GITHUB_TOKEN")["where"],
                         "AWS IAM security credentials")


if __name__ == "__main__":
    unittest.main()
