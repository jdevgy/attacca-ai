"""Packaged setup/auth onboarding documentation acceptance tests."""

import importlib.util
import io
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SETUP_SKILL = ROOT / "skills" / "setup" / "SKILL.md"
KIMI_SETUP = ROOT / "kimi-commands" / "setup.md"
README = ROOT / "README.md"
SPEC = importlib.util.spec_from_file_location(
    "attacca_auth_onboarding_core", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


class AuthOnboardingTestCase(unittest.TestCase):
    def test_native_skills_authenticate_before_unscoped_mcp(self):
        for path in (SETUP_SKILL, KIMI_SETUP):
            source = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                preflight = source.index("--json setup --discover")
                first_mcp = source.index("MCP `list_projects`")
                self.assertLess(preflight, first_mcp)
                self.assertIn("public", source[:first_mcp].lower())
                self.assertIn("terminal_flow.py", source)
                self.assertIn("browser/device", source)
                self.assertIn("zero-binding", source)
                self.assertIn("provisional", source.lower())
                self.assertIn("/v1/auth/terminals/{token_id}/bindings", source)
                self.assertIn("not a browser cookie", source.lower())
                self.assertIn("exact", source.lower())
                self.assertIn("actor", source.lower())
                self.assertIn("revok", source.lower())
                self.assertIn("controlling", source.lower())
                self.assertIn("tty", source.lower())
                self.assertNotIn("setup --interactive", source)
                self.assertNotIn("--paste-token", source)
                self.assertIn("never", source.lower())
                self.assertIn("401/403", source)
                self.assertIn("cached offline", source.lower())
                self.assertIn("hot-reload", source.lower())
                self.assertIn("verified hosted", source.lower())

    def test_skill_does_not_claim_cross_process_login_reuse(self):
        skill = SETUP_SKILL.read_text(encoding="utf-8")
        kimi = KIMI_SETUP.read_text(encoding="utf-8")
        self.assertIn("processes remain separate", skill)
        normalized_skill = " ".join(skill.split())
        normalized_kimi = " ".join(kimi.split())
        self.assertIn("never claim a temporary login session carries",
                      normalized_skill)
        self.assertIn("Discovery and apply remain separate processes", kimi)
        self.assertIn("never claim a temporary login session carries",
                      normalized_kimi)
        self.assertNotIn("Before running a shell command, call Attacca's unscoped",
                         skill)
        self.assertNotIn("Before running Bash, call Attacca's unscoped", kimi)
        self.assertNotIn("uses a short-lived human browser/account session",
                         skill)
        self.assertNotIn("uses a short-lived human browser/account session",
                         kimi)

    def test_readme_documents_activation_tokens_and_honest_limits(self):
        source = README.read_text(encoding="utf-8")
        for phrase in (
                "Hosted authentication (prototype)",
                "serve --auth",
                "first admin account",
                "HttpOnly",
                "CSRF",
                "Plaintext is shown exactly once",
                "~/.attacca/credentials.json",
                "mode `0600`",
                "browser/device enrollment",
                "high-entropy device code",
                "provisional human setup principal",
                "terminal-binding endpoint",
                "controlling TTY",
                "Sign out",
                "Revoke a token",
                "remain public",
                "does not terminate TLS"):
            self.assertIn(phrase, source)
        self.assertRegex(source, r"full\s+server base\s+URL\s+\(including "
                         r"any path\) and the machine device")
        self.assertNotIn("attacca setup --interactive", source)
        self.assertNotIn("--paste-token", source)
        self.assertNotIn("Authentication, permissions, and hostile-client",
                         source)
        self.assertNotIn("**unauthenticated** server", source)
        normalized = " ".join(source.split())
        self.assertIn("does **not** activate enforcement", normalized)
        self.assertIn("two recorded QA passes", normalized)
        self.assertIn("creating new registered-AI actor tokens is disabled",
                      normalized)
        self.assertIn(
            "compatibility may treat an invalid legacy bearer as absent",
            normalized)
        for obsolete in (
                "Creating that account immediately protects",
                "`serve --auth` requires authentication immediately",
                "Settings can create human API tokens or tokens for a\n"
                "registered AI actor",
                "uses a short-lived human browser session"):
            self.assertNotIn(obsolete, source)

    def test_packaged_plugin_contains_current_secure_onboarding(self):
        archive = zipfile.ZipFile(io.BytesIO(
            c.build_plugin_zip("http://127.0.0.1:9999")))
        names = set(archive.namelist())
        self.assertIn("skills/setup/SKILL.md", names)
        self.assertIn("kimi-commands/setup.md", names)
        self.assertIn("README.md", names)
        self.assertIn("terminal_flow.py", names)
        skill = archive.read("skills/setup/SKILL.md").decode()
        self.assertIn("authenticate before MCP", skill)
        self.assertIn("terminal_flow.py", skill)
        self.assertNotIn("setup --interactive", skill)
        self.assertFalse(any(name.endswith("credentials.json") for name in names))


if __name__ == "__main__":
    unittest.main()
