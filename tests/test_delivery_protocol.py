"""Distributed delivery instructions and derived mirror freshness semantics."""

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("delivery_protocol_core", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


class DeliveryProtocolTests(unittest.TestCase):
    def test_managed_protocol_requires_distinct_delivery_proofs_and_safe_repair(self):
        block = c.managed_instruction_block("example", "/unused/database")
        self.assertIn("v=16 project=example", block)
        for requirement in (
                "recent successful watcher poll", "current session's receiver",
                "actual delivery at a supported boundary", "supported host",
                "accepted queue", "never proves", "bounded repair",
                "Never disable server authentication", "restart the shared server",
                "Unchanged local checks must not create model turns"):
            with self.subTest(requirement=requirement):
                self.assertIn(requirement, block)

    def test_room_view_is_explicit_snapshot_even_when_empty(self):
        views = c.render_state_markdown({"project": {"project_id": "example"}})
        self.assertIn("SYNC SNAPSHOT", views["ROOM.md"])
        self.assertIn("not a live message feed", views["ROOM.md"])
        self.assertIn("unchanged file does not mean no new mail", views["ROOM.md"])
        self.assertIn("may lag", views["README.md"])

    def test_mirror_label_preserves_messages_and_writes_no_private_feed(self):
        projection = {"project": {"project_id": "example"}, "room_messages": [
            {"actor": "example.worker.codex.test", "msg_type": "chat",
             "body": "Current snapshot content", "seq": 7}]}
        with tempfile.TemporaryDirectory() as directory:
            written = c.write_state_markdown(directory, projection)
            room = (Path(directory) / "ROOM.md").read_text()
            self.assertIn("SYNC SNAPSHOT", room)
            self.assertIn("Current snapshot content", room)
            self.assertIn(str(Path(directory) / "ROOM.md"), written)
            self.assertFalse((Path(directory) / "watcher-state.json").exists())


if __name__ == "__main__":
    unittest.main()
