"""Project Rules keep binding priority order unless date sort is explicit."""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path


os.environ["ATTACCA_OWNER"] = ""
ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "attacca_rule_order_pagination_under_test", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


class RuleOrderPaginationTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = c.connect(Path(self.tmp.name) / "rules.db")
        c.project_init(
            self.conn, "owner", "human", path=self.tmp.name,
            project_id="rules", name="Rules")
        self.actor = "rules.director.codex.red"
        c.agent_register(
            self.conn, "rules", self.actor, "agent", role="director",
            runtime="codex", persona="red")

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_default_paged_rules_preserve_priority_but_explicit_sort_is_date(self):
        low = c.rule_create(
            self.conn, "rules", self.actor, "agent", "Priority 10", "low",
            scope="everyone", priority=10)["rule"]
        high = c.rule_create(
            self.conn, "rules", self.actor, "agent", "Priority 20", "high",
            scope="director", priority=20)["rule"]
        # Move the higher-priority-number rule to the newest timestamp so a
        # manufactured newest sort would reverse the binding order.
        c.rule_update(
            self.conn, "rules", self.actor, "agent", high["rule_id"],
            {"body": "newest"}, expected_version=1)

        default_page = c.rule_list(
            self.conn, "rules", self.actor, "agent", limit=60)
        self.assertEqual(
            [row["rule_id"] for row in default_page["rules"]],
            [c.DEFAULT_AUTHORITY_RULE_ID, low["rule_id"], high["rule_id"]])

        newest_page = c.rule_list(
            self.conn, "rules", self.actor, "agent", limit=60,
            sort="newest")
        self.assertEqual(
            [row["rule_id"] for row in newest_page["rules"]],
            [high["rule_id"], low["rule_id"],
             c.DEFAULT_AUTHORITY_RULE_ID])

    def test_role_scope_history_filters_full_history_and_caps_at_sixty(self):
        matching_versions = []
        for index in range(75):
            marker = "cobalt" if index % 7 == 0 else "plain"
            result = c.role_scope_set(
                self.conn, "rules", self.actor, "agent", "director",
                "role scope %s %03d" % (marker, index),
                expected_version=index)
            if marker == "cobalt":
                matching_versions.append(result["role_scope"]["version"])

        page = c.role_scope_history(
            self.conn, "rules", "director", actor_id=self.actor,
            actor_type="agent", query="role cobalt", limit=5, offset=2,
            sort="oldest")
        self.assertEqual(page["unfiltered_total"], 75)
        self.assertEqual(page["total"], len(matching_versions))
        self.assertEqual(page["limit"], 5)
        self.assertEqual(page["offset"], 2)
        self.assertEqual(
            [row["version"] for row in page["versions"]],
            matching_versions[2:7])
        self.assertEqual(
            page["has_more"], 2 + len(page["versions"]) <
            len(matching_versions))

        capped = c.role_scope_history(
            self.conn, "rules", "director", actor_id=self.actor,
            actor_type="agent", limit=999)
        self.assertEqual(capped["unfiltered_total"], 75)
        self.assertEqual(capped["total"], 75)
        self.assertEqual((capped["limit"], len(capped["versions"])),
                         (60, 60))
        self.assertTrue(capped["has_more"])

    def test_enabled_total_is_exact_before_status_query_and_page(self):
        disabled = 0
        for index in range(75):
            created = c.rule_create(
                self.conn, "rules", self.actor, "agent",
                "Inventory marker %03d" % index, "body",
                scope="everyone", priority=100)
            if index % 5 == 0:
                disabled += 1
                c.rule_update(
                    self.conn, "rules", self.actor, "agent",
                    created["rule"]["rule_id"], {"enabled": False},
                    expected_version=1)

        page = c.rule_list(
            self.conn, "rules", self.actor, "agent",
            include_disabled=True, include_all=True,
            query="inventory marker", status="disabled",
            limit=5, offset=5, sort="oldest")
        # The default authority rule plus the 60 enabled fixture rules are
        # authorized, regardless of this disabled-only query and page.
        self.assertEqual(page["enabled_total"], 61)
        self.assertEqual(page["unfiltered_total"], 76)
        self.assertEqual(page["total"], disabled)
        self.assertEqual(len(page["rules"]), 5)
        self.assertTrue(page["has_more"])


if __name__ == "__main__":
    unittest.main()
