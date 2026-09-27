"""The public checkout and plugin do not require personal workspace files."""

import importlib.util
import io
import json
import re
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock
from urllib.parse import unquote, urlparse


ROOT = Path(__file__).resolve().parent.parent
PRIVATE_PATHS = frozenset((
    "AGENTS.md", "CLAUDE.md", ".attacca/project.json", ".mcp.json",
    ".devcontainer/devcontainer.json", ".devcontainer/devcontainer-lock.json",
    ".devcontainer/start-attacca.sh", "docs/LOG.md", "docs/LOG.archive.md",
    "docs/blueprint.txt", "docs/multi_agent_developer_saas_blueprint.docx",
))


class PublicRepositoryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "attacca_public_repository", ROOT / "attacca.py")
        cls.runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.runtime)

    def test_public_document_links_resolve_without_private_files(self):
        for name in ("README.md", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md"):
            document = ROOT / name
            for target in re.findall(r"\]\(([^\s)]+)(?:\s+[^)]*)?\)",
                                     document.read_text(encoding="utf-8")):
                parsed = urlparse(target.strip("<>"))
                if parsed.scheme or parsed.netloc or not parsed.path:
                    continue
                relative = unquote(parsed.path)
                with self.subTest(document=name, target=target):
                    self.assertNotIn(relative, PRIVATE_PATHS)
                    self.assertTrue((document.parent / relative).is_file(), target)

    def test_contribution_guide_does_not_require_private_workspace_access(self):
        guide = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        self.assertIn("You do not need an Attacca account", guide)
        self.assertIn("python3 -m unittest", guide)
        self.assertIn("isolated development server", guide)
        for path in PRIVATE_PATHS:
            self.assertNotIn(path, guide)

    def test_private_files_are_ignored_not_distribution_inputs(self):
        ignores = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        for entry in ("AGENTS.md", "CLAUDE.md", ".attacca/*", ".mcp.json",
                      ".devcontainer/", "*.log", "*.jsonl", "logs/",
                      "docs/blueprint.txt", "docs/LOG.md", "docs/LOG.archive.md",
                      "docs/multi_agent_developer_saas_blueprint.docx"):
            self.assertIn(entry, ignores)
        self.assertNotIn("!.attacca/project.json", ignores)
        for collection in (self.runtime.PLUGIN_FILES, self.runtime.AUTH_ARTIFACT_FILES):
            self.assertFalse(PRIVATE_PATHS.intersection(collection))

    def test_codex_manifest_uses_portable_inline_descriptor(self):
        manifest = json.loads((ROOT / ".codex-plugin/plugin.json").read_text())
        self.assertIsInstance(manifest["mcpServers"], dict)
        server = manifest["mcpServers"]["attacca"]
        self.assertEqual(server["args"], ["./attacca.py", "connect"])
        self.assertEqual(server["cwd"], ".")
        self.assertEqual(server["env"]["ATTACCA_ACTOR"], "codex")
        self.assertNotIn("ATTACCA_PROJECT", server["env"])
        self.assertNotIn("ATTACCA_OWNER", server["env"])
        self.assertNotIn("ATTACCA_TOKEN", server["env"])

    def test_distribution_builds_without_any_private_source_file(self):
        runtime = self.runtime
        with tempfile.TemporaryDirectory(prefix="attacca-public-package-") as scratch:
            public_root = Path(scratch)
            for relative in runtime.PLUGIN_FILES:
                target = public_root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(str(ROOT / relative), str(target))
            for relative in PRIVATE_PATHS:
                self.assertFalse((public_root / relative).exists())
            with mock.patch.object(runtime, "script_path",
                                   return_value=str(public_root / "attacca.py")):
                snapshot = runtime._capture_distribution_snapshot()
                archive = runtime.build_plugin_zip(
                    "http://127.0.0.1:8799",
                    source_snapshot=snapshot["plugin_sources"],
                    plugin_files=snapshot["plugin_files"])
            with zipfile.ZipFile(io.BytesIO(archive)) as packaged:
                self.assertEqual(set(packaged.namelist()), set(runtime.PLUGIN_FILES))
                self.assertFalse(PRIVATE_PATHS.intersection(packaged.namelist()))
                self.assertIn("local_access.py", packaged.namelist())
                manifest = json.loads(packaged.read(".codex-plugin/plugin.json"))
                self.assertEqual(
                    manifest["mcpServers"]["attacca"]["env"]["ATTACCA_URL"],
                    "http://127.0.0.1:8799")


if __name__ == "__main__":
    unittest.main()
