"""Cloud Context -> AGENTS.md/CLAUDE.md marker block: versioned, sha-stamped,
auto-refreshed in place, preserving all content outside the markers."""
import importlib.util
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

os.environ["ATTACCA_OWNER"] = ""
ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("attacca", ROOT / "attacca.py")
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)

hook_spec = importlib.util.spec_from_file_location(
    "attacca_cloud_context_hook_under_test",
    ROOT / "hooks" / "session_start.py")
hook = importlib.util.module_from_spec(hook_spec)
hook_spec.loader.exec_module(hook)


class CloudContextBlockTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "t.db"
        self.conn = c.connect(self.db)
        self.repo = Path(self.tmp.name) / "repo"
        self.repo.mkdir()
        c.project_init(self.conn, "h", "human", path=str(self.repo),
                       project_id="p1", name="P1")
        c.agent_register(self.conn, "p1", "p1.director.claude", "agent",
                         role="director", runtime="claude")
        (self.repo / "AGENTS.md").write_text("# Mine\n\nLocal note.\n")

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def _set(self, text):
        c.cloud_context_set(self.conn, "p1", "p1.director.claude", "agent", text)

    def _refresh(self, create=False):
        return c.refresh_cloud_context_block(
            self.conn, "p1", str(self.repo), files=["AGENTS.md"], create=create)

    def test_not_forced_without_opt_in(self):
        self._set("# Ctx")
        r = self._refresh(create=False)
        self.assertEqual(r["files"][0]["status"], "absent")
        self.assertNotIn("ATTACCA_CLOUD_CONTEXT",
                         (self.repo / "AGENTS.md").read_text())

    def test_create_then_current_then_updated_preserving_local(self):
        self._set("# Ctx\nProd only.")
        self.assertEqual(self._refresh(create=True)["files"][0]["status"],
                         "created")
        self.assertEqual(self._refresh(create=True)["files"][0]["status"],
                         "current")
        self._set("# Ctx v2\nChanged.")
        # once the block exists it refreshes even without create
        self.assertEqual(self._refresh(create=False)["files"][0]["status"],
                         "updated")
        text = (self.repo / "AGENTS.md").read_text()
        self.assertIn("Local note.", text)          # local content preserved
        self.assertIn("Ctx v2", text)               # refreshed body
        present, ver, sha = c.cloud_context_block_present(text)
        self.assertTrue(present)
        self.assertEqual(ver, "2")

    def test_sha_in_cloud_context_and_block(self):
        self._set("hello")
        cc = c.cloud_context_get(self.conn, "p1")["cloud_context"]
        self.assertIn("sha256", cc)
        block = c.cloud_context_block(cc, "p1")
        self.assertIn("sha=%s" % cc["sha256"][:16], block)
        self.assertIn("ATTACCA_CLOUD_CONTEXT:END", block)

    def test_payload_refresh_is_exact_noop_and_fails_closed_on_bad_markers(self):
        self._set("# Exact\nKeep trailing spaces.  \n")
        cc = c.cloud_context_get(self.conn, "p1")["cloud_context"]
        first = c.refresh_cloud_context_block_payload(
            cc, "p1", self.repo, files=["AGENTS.md"], create=True)
        self.assertTrue(first["changed"])
        path = self.repo / "AGENTS.md"
        before = path.stat()
        exact = path.read_bytes()

        second = c.refresh_cloud_context_block_payload(
            cc, "p1", self.repo, files=["AGENTS.md"], create=True)
        self.assertFalse(second["changed"])
        self.assertEqual(second["files"][0]["status"], "current")
        self.assertEqual(path.read_bytes(), exact)
        self.assertEqual(path.stat().st_ino, before.st_ino)

        malformed = exact.decode() + "\n" + c.CLOUD_CONTEXT_END + "\n"
        path.write_text(malformed)
        result = c.refresh_cloud_context_block_payload(
            cc, "p1", self.repo, files=["AGENTS.md"], create=True)
        self.assertFalse(result["ok"])
        self.assertEqual(result["files"][0]["status"], "malformed")
        self.assertEqual(path.read_text(), malformed)

    def test_payload_rejects_content_hash_mismatch(self):
        with self.assertRaisesRegex(c.AttaccaError, "sha256"):
            c.refresh_cloud_context_block_payload(
                {"content": "trusted", "version": 3, "sha256": "0" * 64},
                "p1", self.repo, files=["AGENTS.md"], create=True)
        self.assertNotIn("trusted", (self.repo / "AGENTS.md").read_text())

    def test_content_rejects_raw_marker_tokens_at_write_and_render_boundaries(self):
        for token in ("ATTACCA_CLOUD_CONTEXT:BEGIN",
                      "ATTACCA_CLOUD_CONTEXT:END"):
            with self.subTest(token=token):
                with self.assertRaisesRegex(c.AttaccaError, "marker token"):
                    c.cloud_context_set(
                        self.conn, "p1", "p1.director.claude", "agent",
                        "ordinary text\n%s\nordinary text" % token)
                with self.assertRaisesRegex(c.AttaccaError, "marker token"):
                    c.refresh_cloud_context_block_payload(
                        {"content": token, "version": 1,
                         "sha256": c.sha256_hex(token)},
                        "p1", self.repo, files=["AGENTS.md"], create=True)

    def test_local_cloud_version_is_monotonic_and_same_version_sha_conflicts(self):
        path = self.repo / "AGENTS.md"
        first_content = "authoritative v3"
        first = {"content": first_content, "version": 3,
                 "sha256": c.sha256_hex(first_content)}
        created = c.refresh_cloud_context_block_payload(
            first, "p1", self.repo, files=["AGENTS.md"], create=True)
        self.assertTrue(created["ok"])
        exact = path.read_bytes()
        inode = path.stat().st_ino

        lower = {"content": first_content, "version": 2,
                 "sha256": c.sha256_hex(first_content)}
        refused = c.refresh_cloud_context_block_payload(
            lower, "p1", self.repo, files=["AGENTS.md"], create=True)
        self.assertFalse(refused["ok"])
        self.assertEqual(refused["files"][0]["status"], "rollback_refused")
        self.assertEqual(path.read_bytes(), exact)

        conflict_content = "different v3"
        conflict = c.refresh_cloud_context_block_payload(
            {"content": conflict_content, "version": 3,
             "sha256": c.sha256_hex(conflict_content)},
            "p1", self.repo, files=["AGENTS.md"], create=True)
        self.assertFalse(conflict["ok"])
        self.assertEqual(conflict["files"][0]["status"], "version_conflict")
        self.assertEqual(path.read_bytes(), exact)

        current = c.refresh_cloud_context_block_payload(
            first, "p1", self.repo, files=["AGENTS.md"], create=True)
        self.assertTrue(current["ok"])
        self.assertEqual(current["files"][0]["status"], "current")
        self.assertEqual(path.stat().st_ino, inode)

        newer_content = "authoritative v4"
        newer = c.refresh_cloud_context_block_payload(
            {"content": newer_content, "version": 4,
             "sha256": c.sha256_hex(newer_content)},
            "p1", self.repo, files=["AGENTS.md"], create=True)
        self.assertTrue(newer["ok"])
        self.assertEqual(newer["files"][0]["status"], "updated")
        self.assertIn(newer_content, path.read_text())

    def test_lifecycle_creates_then_refreshes_only_changed_snapshot(self):
        self._set("startup context")
        cc1 = c.cloud_context_get(self.conn, "p1")["cloud_context"]
        status = {"project_id": "p1", "root": str(self.repo)}
        snapshot1 = {"cloud_context": {"project": "p1",
                                       "cloud_context": cc1}}
        path = self.repo / "AGENTS.md"
        path.write_text(
            path.read_text() + "\n" +
            c.managed_instruction_block("p1", None) + "\n")

        first = hook._refresh_cloud_context_from_snapshot(
            status, ROOT, snapshot1, create=True)
        self.assertIsNotNone(first)
        initial_inode = path.stat().st_ino
        initial_bytes = path.read_bytes()
        second = hook._refresh_cloud_context_from_snapshot(
            status, ROOT, snapshot1, create=True)
        self.assertIsNone(second)
        self.assertEqual(path.stat().st_ino, initial_inode)
        self.assertEqual(path.read_bytes(), initial_bytes)

        self._set("changed context")
        cc2 = c.cloud_context_get(self.conn, "p1")["cloud_context"]
        changed = hook._refresh_cloud_context_from_snapshot(
            status, ROOT, {"cloud_context": {"cloud_context": cc2}},
            create=True)
        self.assertIsNotNone(changed)
        self.assertIn("changed context", path.read_text())
        self.assertNotIn("startup context", path.read_text())
        self.assertIn("Local note.", path.read_text())

    def test_lifecycle_never_creates_a_cloud_only_instruction_file(self):
        self._set("managed ownership required")
        cc = c.cloud_context_get(self.conn, "p1")["cloud_context"]
        status = {"project_id": "p1", "root": str(self.repo)}
        snapshot = {"cloud_context": {"cloud_context": cc}}
        path = self.repo / "AGENTS.md"

        notice = hook._refresh_cloud_context_from_snapshot(
            status, ROOT, snapshot, create=True)
        self.assertIsNone(notice)
        self.assertNotIn(c.CLOUD_CONTEXT_BEGIN, path.read_text())

        path.write_text(
            path.read_text() + "\n" +
            c.managed_instruction_block("p1", None) + "\n")
        notice = hook._refresh_cloud_context_from_snapshot(
            status, ROOT, snapshot, create=True)
        self.assertIsNotNone(notice)
        text = path.read_text()
        self.assertIn("MANAGED_ATTACCA:BEGIN", text)
        self.assertIn("ATTACCA_CLOUD_CONTEXT:BEGIN", text)
        self.assertIn("managed ownership required", text)

    def test_lifecycle_cloud_creation_is_gated_per_instruction_file(self):
        self._set("per-file ownership")
        cc = c.cloud_context_get(self.conn, "p1")["cloud_context"]
        agents = self.repo / "AGENTS.md"
        claude = self.repo / "CLAUDE.md"
        agents.write_text(
            "# Agents local\n\n" + c.managed_instruction_block("p1", None) +
            "\n")
        claude.write_text("# Claude is independently user-managed\n")

        notice = hook._refresh_cloud_context_from_snapshot(
            {"project_id": "p1", "root": str(self.repo)}, ROOT,
            {"cloud_context": {"cloud_context": cc}}, create=True)

        self.assertIsNotNone(notice)
        self.assertIn("AGENTS.md", notice["context"])
        self.assertNotIn("CLAUDE.md", notice["context"])
        self.assertIn("per-file ownership", agents.read_text())
        self.assertEqual(claude.read_text(),
                         "# Claude is independently user-managed\n")

    def test_lifecycle_rejects_invalid_per_file_managed_ownership(self):
        self._set("must not cross projects")
        cc = c.cloud_context_get(self.conn, "p1")["cloud_context"]
        path = self.repo / "AGENTS.md"
        path.write_text(c.managed_instruction_block("another", None) + "\n")

        notice = hook._refresh_cloud_context_from_snapshot(
            {"project_id": "p1", "root": str(self.repo)}, ROOT,
            {"cloud_context": {"cloud_context": cc}}, create=True)

        self.assertIsNotNone(notice)
        self.assertIn("another project", notice["context"])
        self.assertNotIn(c.CLOUD_CONTEXT_BEGIN, path.read_text())

    def test_cloud_creation_requires_owned_matching_versioned_managed_block(self):
        content = "owned only"
        payload = {"content": content, "version": 1,
                   "sha256": c.sha256_hex(content)}
        valid = c.managed_instruction_block("p1", None)
        cases = {
            "wrong-project.md": valid.replace(
                " project=p1 ", " project=other ", 1),
            "unowned.md": valid.replace(
                " do_not_edit=true ", " do_not_edit=false ", 1),
            "unversioned.md": valid.replace(
                " v=%d " % c.MANAGED_BLOCK_VERSION, " v=broken ", 1),
            "zero-version.md": valid.replace(
                " v=%d " % c.MANAGED_BLOCK_VERSION, " v=0 ", 1),
        }
        for filename, text in cases.items():
            with self.subTest(filename=filename):
                path = self.repo / filename
                path.write_text(text + "\n")
                result = c.refresh_cloud_context_block_payload(
                    payload, "p1", self.repo, files=[filename], create=True,
                    require_managed_ownership=True)
                self.assertFalse(result["ok"])
                self.assertEqual(result["files"][0]["status"],
                                 "ownership_invalid")
                self.assertNotIn(c.CLOUD_CONTEXT_BEGIN, path.read_text())

    def test_changed_periodic_snapshot_injects_refetched_cloud_context(self):
        status = {"project_id": "p1"}
        previous = {
            "cloud_context": {"version": 1, "sha256": "old",
                              "content": "old context"},
            "counts": {"events": 1},
        }
        current = {
            "cloud_context": {"version": 2, "sha256": "new",
                              "content": "NEW AUTHORITATIVE CONTEXT"},
            "counts": {"events": 2},
        }
        summary = hook._change_summary(
            status, previous, current,
            {"inbox": {"messages": []}, "room": {"messages": []}}, 60)
        self.assertIn("Cloud Context changed to v2", summary)
        self.assertIn("NEW AUTHORITATIVE CONTEXT", summary)
        self.assertIn("END ATTACCA CLOUD CONTEXT", summary)

    def test_remote_setup_uses_hosted_context_not_unrelated_local_db(self):
        self._set("# Hosted authority\nRemote only.")
        server = c.AttaccaServer(("127.0.0.1", 0), self.db)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        checkout = Path(self.tmp.name) / "remote-checkout"
        checkout.mkdir()
        (checkout / "AGENTS.md").write_text("# Local\n\nPreserve me.\n")
        unrelated_db = Path(self.tmp.name) / "unrelated.db"
        c.connect(unrelated_db).close()
        home = Path(self.tmp.name) / "home"
        home.mkdir()
        try:
            result = c.one_shot_remote_setup(
                "human", "human", unrelated_db,
                url="http://127.0.0.1:%d" % server.server_address[1],
                path=str(checkout), here=True, manage_server=False,
                manage_tools=False, write_instructions=True,
                attach_project="p1", home=str(home))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        self.assertEqual(result["project_id"], "p1")
        self.assertTrue(any(row["changed"]
                            for row in result["cloud_context_files"]))
        text = (checkout / "AGENTS.md").read_text()
        self.assertIn("Hosted authority", text)
        self.assertIn("Remote only.", text)
        self.assertIn("Preserve me.", text)
        self.assertEqual(text.count("MANAGED_ATTACCA:BEGIN"), 1)
        self.assertEqual(text.count("ATTACCA_CLOUD_CONTEXT:BEGIN"), 1)

    def test_setup_surfaces_cloud_instruction_sync_failures(self):
        checkout = Path(self.tmp.name) / "sync-failure"
        checkout.mkdir()
        home = Path(self.tmp.name) / "sync-home"
        home.mkdir()
        payload = {"content": "hosted", "version": 1,
                   "sha256": c.sha256_hex("hosted")}
        failed = {
            "ok": False, "changed": False,
            "files": [{"file": str(checkout / "AGENTS.md"),
                       "changed": False, "status": "version_conflict",
                       "error": "same version has different sha256"}],
        }
        with mock.patch.object(
                c, "refresh_cloud_context_block_payload",
                return_value=failed):
            with self.assertRaisesRegex(
                    c.AttaccaError,
                    r"AGENTS\.md \[version_conflict\].*different sha256"):
                c._configure_checkout(
                    "p1", checkout, self.db, c.DEFAULT_URL, True, True,
                    False, [], str(home), cloud_context_payload=payload)

    def test_setup_reports_only_real_instruction_and_cloud_changes(self):
        checkout = Path(self.tmp.name) / "sync-status"
        checkout.mkdir()
        home = Path(self.tmp.name) / "sync-status-home"
        home.mkdir()
        payload = {"content": "hosted status", "version": 1,
                   "sha256": c.sha256_hex("hosted status")}

        first = c._configure_checkout(
            "p1", checkout, self.db, c.DEFAULT_URL, True, True,
            False, [], str(home), cloud_context_payload=payload)
        self.assertTrue(first["instruction_sync_ok"])
        self.assertEqual(
            set(first["instruction_files"]),
            {row["file"] for row in first["instruction_file_statuses"]
             if row.get("changed") is True})
        self.assertTrue(any(
            row.get("changed") is True
            for row in first["cloud_context_files"]))

        second = c._configure_checkout(
            "p1", checkout, self.db, c.DEFAULT_URL, True, True,
            False, [], str(home), cloud_context_payload=payload)
        self.assertTrue(second["instruction_sync_ok"])
        self.assertEqual(second["instruction_files"], [])
        self.assertFalse(any(
            row.get("changed") is True
            for row in second["instruction_file_statuses"] +
            second["cloud_context_files"]))
        self.assertTrue(all(
            row.get("status") in {"current", "linked"}
            for row in second["instruction_file_statuses"] +
            second["cloud_context_files"]))

    def test_atomic_absent_cas_refuses_a_concurrently_created_file(self):
        path = self.repo / "NEW.md"
        path.write_text("human created this\n")
        with self.assertRaisesRegex(c.AttaccaError, "created concurrently"):
            c._atomic_write_instruction(
                path, "attacca content\n",
                expected_text=c._INSTRUCTION_FILE_ABSENT)
        self.assertEqual(path.read_text(), "human created this\n")

    def test_concurrent_standard_claude_link_creation_is_no_replace(self):
        target = self.repo / "CLAUDE.md"
        barrier = threading.Barrier(2)
        outcomes = []

        def create_link():
            barrier.wait(timeout=5)
            outcomes.append(c._create_standard_claude_link(
                target, self.repo))

        threads = [threading.Thread(target=create_link) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        self.assertEqual(sorted(outcomes), [False, True])
        self.assertTrue(target.is_symlink())
        self.assertEqual(os.readlink(str(target)), "AGENTS.md")
        self.assertEqual(target.read_text(),
                         (self.repo / "AGENTS.md").read_text())

    def test_managed_and_cloud_concurrent_writers_never_clobber_regions(self):
        path = self.repo / "AGENTS.md"
        initial_cloud = {"content": "cloud v1", "version": 1,
                         "sha256": c.sha256_hex("cloud v1")}
        installed = c.install_instructions(
            "p1", self.repo, self.db, files=["AGENTS.md"],
            cloud_context_payload=initial_cloud)
        self.assertTrue(installed["ok"], installed)
        desired_law = c.managed_instruction_block("p1", None).replace(
            "The project owns the knowledge",
            "The project durably owns the knowledge", 1)
        desired_law_sha = c.sha256_hex(desired_law)
        cloud_v2 = {"content": "cloud v2 concurrent", "version": 2,
                    "sha256": c.sha256_hex("cloud v2 concurrent")}
        barrier = threading.Barrier(2)
        original_atomic = c._atomic_write_instruction
        outcomes = {}

        def synchronized_atomic(*args, **kwargs):
            barrier.wait(timeout=5)
            return original_atomic(*args, **kwargs)

        def managed_writer():
            outcomes["managed"] = c.refresh_managed_instruction_block(
                "p1", self.repo, desired_law,
                expected_sha256=desired_law_sha, files=["AGENTS.md"])

        def cloud_writer():
            outcomes["cloud"] = c.refresh_cloud_context_block_payload(
                cloud_v2, "p1", self.repo, files=["AGENTS.md"], create=False)

        with mock.patch.object(
                c, "_atomic_write_instruction",
                side_effect=synchronized_atomic):
            threads = [threading.Thread(target=managed_writer),
                       threading.Thread(target=cloud_writer)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)
                self.assertFalse(thread.is_alive())

        statuses = {outcomes[name]["files"][0]["status"]
                    for name in ("managed", "cloud")}
        self.assertIn("write_error", statuses)
        self.assertTrue(statuses & {"updated"})
        raced_text = path.read_text()
        self.assertEqual(raced_text.count("MANAGED_ATTACCA:BEGIN"), 1)
        self.assertEqual(raced_text.count("ATTACCA_CLOUD_CONTEXT:BEGIN"), 1)
        self.assertIn("# Mine", raced_text)

        # The surfaced loser retries against the new exact bytes and merges
        # its own region without reverting the winner.
        managed_retry = c.refresh_managed_instruction_block(
            "p1", self.repo, desired_law,
            expected_sha256=desired_law_sha, files=["AGENTS.md"])
        cloud_retry = c.refresh_cloud_context_block_payload(
            cloud_v2, "p1", self.repo, files=["AGENTS.md"], create=False)
        self.assertTrue(managed_retry["ok"], managed_retry)
        self.assertTrue(cloud_retry["ok"], cloud_retry)
        converged = path.read_text()
        self.assertIn("durably owns the knowledge", converged)
        self.assertIn("cloud v2 concurrent", converged)
        self.assertIn("# Mine", converged)

    def test_watcher_treats_cloud_context_update_as_relevant(self):
        self.assertTrue(hook._watcher_relevant_event({
            "event_type": "cloud_context.updated"}))
        self.assertFalse(hook._watcher_relevant_event({
            "event_type": "agent.seen"}))

    def test_watcher_verified_projection_refresh_survives_mirror_render_error(self):
        self._set("watcher-refetched context")
        cc = c.cloud_context_get(self.conn, "p1")["cloud_context"]
        instruction = self.repo / "AGENTS.md"
        instruction.write_text(
            instruction.read_text() + "\n" +
            c.managed_instruction_block("p1", None) + "\n")

        class Adapter:
            @staticmethod
            def local_projection():
                return {"cloud_context": cc}

        class Runtime:
            @staticmethod
            def write_state_markdown(*args, **kwargs):
                raise OSError("mirror view unavailable")

            inspect_managed_instruction_file = staticmethod(
                c.inspect_managed_instruction_file)
            refresh_cloud_context_block_payload = staticmethod(
                c.refresh_cloud_context_block_payload)

        with mock.patch.object(
                hook, "_load_attacca_runtime", return_value=Runtime):
            hook._watcher_write_markdown_mirror({
                "root": str(self.repo), "project_id": "p1",
                "plugin_root": str(ROOT)}, Adapter())
        self.assertIn(
            "watcher-refetched context",
            instruction.read_text())

    def test_managed_law_describes_identity_handoffs_and_auto_sync(self):
        block = c.managed_instruction_block("p1", None)
        self.assertEqual(c.MANAGED_BLOCK_VERSION, 16)
        self.assertIn("workspace.role.runtime.persona", block)
        self.assertIn("legacy three-part", block)
        self.assertIn("exact identity handoff", block)
        self.assertIn("every exact registered identity", block)
        self.assertIn("ONE", block)
        self.assertIn("shared project handoff", block)
        self.assertIn("update_identity_handoff", block)
        self.assertIn("only a registered AI Director writes", block)
        self.assertIn("ATTACCA_CLOUD_CONTEXT", block)
        self.assertIn("loaded in full", block)
        self.assertIn("at session start", block)
        self.assertIn("version/hash changes", block)
        self.assertNotIn("injected into every brief", " ".join(block.split()))
        self.assertIn("stale_context_warning", block)


if __name__ == "__main__":
    unittest.main()
