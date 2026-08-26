"""Client-side regression coverage for server-authoritative managed law."""

import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError


os.environ["ATTACCA_OWNER"] = ""
ROOT = Path(__file__).resolve().parent.parent

CORE_SPEC = importlib.util.spec_from_file_location(
    "attacca_managed_law_client_core_test", ROOT / "attacca.py")
core = importlib.util.module_from_spec(CORE_SPEC)
CORE_SPEC.loader.exec_module(core)

HOOK_SPEC = importlib.util.spec_from_file_location(
    "attacca_managed_law_client_hook_test",
    ROOT / "hooks" / "session_start.py")
hook = importlib.util.module_from_spec(HOOK_SPEC)
HOOK_SPEC.loader.exec_module(hook)


class _Response:
    def __init__(self, payload):
        self.raw = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def read(self, size=-1):
        return self.raw if size < 0 else self.raw[:size]


def _with_version(block, version):
    return block.replace(
        "MANAGED_ATTACCA:BEGIN v=%d" % core.MANAGED_BLOCK_VERSION,
        "MANAGED_ATTACCA:BEGIN v=%d" % version, 1)


def _payload_for_block(block, version, project_id):
    template = block.replace(
        "project=%s" % project_id, "project=attacca-project", 1)
    return {
        "version": version,
        "sha256": hashlib.sha256(block.encode("utf-8")).hexdigest(),
        "law_sha256": hashlib.sha256(
            template.encode("utf-8")).hexdigest(),
        "server_software_version": core.VERSION,
        "block": block,
    }


class ManagedLawClientTestCase(unittest.TestCase):
    def _validated(self, payload, project_id="shared"):
        return hook._server_managed_law(
            {"url": "https://attacca.test/"}, project_id,
            opener=lambda request, timeout: _Response(payload))

    def test_fetch_uses_exact_authenticated_subscription_identity(self):
        project_id = "shared+ops"
        payload = core.managed_law_payload(project_id, None)
        captured = {}

        def opener(request, timeout):
            captured["url"] = request.full_url
            captured["headers"] = {
                key.lower(): value for key, value in request.header_items()}
            captured["timeout"] = timeout
            return _Response(payload)

        entry = {
            "server_url": "https://attacca.test",
            "project_id": project_id,
            "runtime": "codex",
            "canonical_actor_id": "shared+ops.director.codex",
            "owner": "jack",
            "device_id": "laptop-one",
        }
        with mock.patch.object(
                hook, "_watcher_api_token",
                return_value="terminal-secret") as token, \
             mock.patch.object(
                 hook, "_client_instance_id", return_value="codex-one"):
            result = hook._server_managed_law(
                {"url": "https://attacca.test/"}, project_id,
                opener=opener, entry=entry)

        token.assert_called_once_with(entry)
        self.assertEqual(result, payload)
        self.assertIn("project=shared%2Bops", captured["url"])
        self.assertEqual(captured["headers"]["authorization"],
                         "Bearer terminal-secret")
        self.assertEqual(captured["headers"]["x-attacca-actor"],
                         "shared+ops.director.codex")
        self.assertEqual(captured["headers"]["x-attacca-actor-type"],
                         "agent")
        self.assertEqual(captured["headers"]["x-attacca-project"],
                         project_id)
        self.assertEqual(captured["headers"]["x-attacca-device-id"],
                         "laptop-one")
        self.assertEqual(captured["headers"]["x-attacca-client-instance"],
                         "codex-one")
        self.assertEqual(captured["headers"]["x-attacca-owner"], "jack")
        self.assertEqual(
            captured["timeout"], hook.AUXILIARY_HTTP_TIMEOUT_SECONDS)

    def test_newer_law_applies_without_binary_offer_and_preserves_outside_bytes(self):
        self.assertGreater(core.MANAGED_BLOCK_VERSION, 1)
        project_id = "shared"
        desired = core.managed_instruction_block(project_id, None)
        previous = _with_version(desired, core.MANAGED_BLOCK_VERSION - 1)
        prefix = "# Local rules\r\n\r\nCaf\u00e9 stays byte-exact.  \r\n\r\n".encode(
            "utf-8")
        suffix = b"\r\n\r\n## Local tail\r\nKeep tabs\tand spaces.  \r\n"

        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp) / "repo"
            checkout.mkdir()
            agents = checkout / "AGENTS.md"
            agents.write_bytes(prefix + previous.encode("utf-8") + suffix)
            status = {
                "project_id": project_id,
                "root": str(checkout),
                "state_path": str(Path(tmp) / "hook-state.json"),
            }
            payload = core.managed_law_payload(project_id, None)
            self.assertEqual(payload["server_software_version"], core.VERSION)
            validated = self._validated(payload, project_id)

            release = {
                "version": core.VERSION,
                "managed_instructions": {
                    "version": payload["version"],
                    "sha256": payload["law_sha256"],
                },
            }
            with mock.patch.object(
                    hook, "_local_version", return_value=core.VERSION), \
                 mock.patch.object(
                    hook, "_cached_server_release", return_value=release), \
                 mock.patch.object(hook, "_claim_update_offer") as claim:
                offer = hook._update_offer(status, ROOT, {"url": "https://attacca.test"})
            self.assertIsNone(offer)
            claim.assert_not_called()
            self.assertFalse(Path(status["state_path"]).exists())

            with mock.patch.object(
                    hook, "_load_attacca_runtime", return_value=core) as runtime:
                notice = hook._refresh_managed_laws(
                    status, ROOT, config={"url": "https://attacca.test"},
                    fetcher=lambda config, project: validated)

            runtime.assert_called_once_with(ROOT)
            self.assertIsNotNone(notice)
            self.assertEqual(
                agents.read_bytes(),
                prefix + desired.encode("utf-8") + suffix)
            self.assertFalse((checkout / "CLAUDE.md").exists())
            self.assertIn("AGENTS.md", notice["context"])
            combined_notice = " ".join(notice.values()).lower()
            self.assertNotIn("install now", combined_notice)
            self.assertNotIn("restart", combined_notice)
            self.assertNotIn("update choice", combined_notice)

    def test_older_server_law_cannot_downgrade_a_newer_local_block(self):
        self.assertGreater(core.MANAGED_BLOCK_VERSION, 1)
        project_id = "shared"
        current = core.managed_instruction_block(project_id, None)
        older_version = core.MANAGED_BLOCK_VERSION - 1
        older = _with_version(current, older_version)
        payload = self._validated(
            _payload_for_block(older, older_version, project_id), project_id)

        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp)
            agents = checkout / "AGENTS.md"
            original = ("# Before\n\n" + current + "\n\n# After\n").encode(
                "utf-8")
            agents.write_bytes(original)

            with mock.patch.object(
                    hook, "_load_attacca_runtime", return_value=core):
                result = hook._server_managed_law_adapter(
                    ROOT, project_id, str(checkout), payload)

            agents_result = next(
                item for item in result["files"]
                if Path(item["file"]).name == "AGENTS.md")
            self.assertEqual(agents_result["status"], "future")
            self.assertFalse(agents_result["changed"])
            self.assertFalse(result["ok"])
            self.assertEqual(agents.read_bytes(), original)

    def test_malformed_server_payloads_fail_before_the_core_adapter(self):
        project_id = "shared"
        valid = core.managed_law_payload(project_id, None)
        wrong_project = core.managed_law_payload("another-project", None)
        duplicate_end_block = valid["block"] + "\n" + core.MANAGED_END
        malformed = {
            "sha256": dict(valid, sha256="0" * 64),
            "law_sha256": dict(valid, law_sha256="0" * 64),
            "project": wrong_project,
            "version": dict(valid, version=valid["version"] + 1),
            "markers": _payload_for_block(
                duplicate_end_block, valid["version"], project_id),
        }

        for label, payload in malformed.items():
            with self.subTest(label=label), \
                 mock.patch.object(
                    hook, "_server_managed_law_adapter") as adapter:
                def fetch(config, requested_project, invalid=payload):
                    return hook._server_managed_law(
                        config, requested_project,
                        opener=lambda request, timeout: _Response(invalid))

                notice = hook._refresh_managed_laws(
                    {"project_id": project_id, "root": "/unused"}, ROOT,
                    config={"url": "https://attacca.test"}, fetcher=fetch)

                adapter.assert_not_called()
                self.assertIsNotNone(notice)
                self.assertIn("could not run", notice["system_message"])

    def test_missing_unmanaged_and_unsafe_targets_are_left_untouched(self):
        project_id = "shared"
        payload = core.managed_law_payload(project_id, None)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = core.refresh_managed_instruction_block(
                project_id, root, payload["block"],
                expected_sha256=payload["sha256"], files=["AGENTS.md"])
            self.assertEqual(result["files"][0]["status"], "missing")
            self.assertFalse((root / "AGENTS.md").exists())

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            agents = root / "AGENTS.md"
            original = b"# Human-owned instructions only\r\nDo not append here.\r\n"
            agents.write_bytes(original)
            result = core.refresh_managed_instruction_block(
                project_id, root, payload["block"],
                expected_sha256=payload["sha256"], files=["AGENTS.md"])
            self.assertEqual(result["files"][0]["status"], "missing")
            self.assertEqual(agents.read_bytes(), original)

        with tempfile.TemporaryDirectory() as tmp, \
             tempfile.TemporaryDirectory() as outside_tmp:
            root = Path(tmp)
            outside = Path(outside_tmp) / "outside.md"
            original = b"outside checkout\n"
            outside.write_bytes(original)
            (root / "AGENTS.md").symlink_to(outside)
            result = core.refresh_managed_instruction_block(
                project_id, root, payload["block"],
                expected_sha256=payload["sha256"], files=["AGENTS.md"])
            self.assertEqual(
                result["files"][0]["status"], "unsafe_symlink")
            self.assertEqual(outside.read_bytes(), original)
            self.assertTrue((root / "AGENTS.md").is_symlink())

    def test_server_404_is_quiet_and_never_reaches_the_adapter(self):
        def missing(config, project_id):
            raise HTTPError(
                config["url"] + "/v1/managed-law", 404, "not found", {}, None)

        with mock.patch.object(
                hook, "_server_managed_law_adapter") as adapter:
            notice = hook._refresh_managed_laws(
                {"project_id": "shared", "root": "/unused"}, ROOT,
                config={"url": "https://attacca.test"}, fetcher=missing)

        self.assertIsNone(notice)
        adapter.assert_not_called()


if __name__ == "__main__":
    unittest.main()
