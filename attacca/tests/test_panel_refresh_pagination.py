"""Regression coverage for stable, paginated control-room feeds.

These tests deliberately exercise the panel's pure feed reducer with Node and
inspect the shipped HTML contract.  They do not start or contact an Attacca
server, so the live development service is never involved.
"""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path


PANEL = Path(__file__).resolve().parents[1] / "web" / "admin.html"


class PanelRefreshPaginationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = PANEL.read_text(encoding="utf-8")
        match = re.search(
            r"// TESTABLE_FEED_HELPERS:BEGIN\n(?P<body>.*?)"
            r"\n\s*// TESTABLE_FEED_HELPERS:END",
            cls.source,
            flags=re.DOTALL,
        )
        if not match:
            raise AssertionError("testable feed-helper block is missing")
        cls.helpers = match.group("body")

    def run_node(self, assertions: str) -> None:
        program = "\n".join(
            [
                '"use strict";',
                'const assert = require("node:assert/strict");',
                self.helpers,
                assertions,
            ]
        )
        completed = subprocess.run(
            ["node", "-e", program],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=f"Node feed-model check failed:\n{completed.stderr}\n{completed.stdout}",
        )

    def test_pagination_handles_empty_large_and_append_only_histories(self) -> None:
        self.run_node(
            """
            const empty = paginateFeed([], 75, 99, false);
            assert.deepEqual(
              {page: empty.page, pages: empty.pageCount, start: empty.rangeStart,
               end: empty.rangeEnd, total: empty.total, rows: empty.rows},
              {page: 0, pages: 1, start: 0, end: 0, total: 0, rows: []});

            const original = Array.from({length: 180}, (_, index) => index + 1);
            const newest = paginateFeed(original, 75, 0, true);
            assert.equal(newest.page, 2);
            assert.equal(isNewestFeedPage(newest.page, newest.pageCount), true);
            assert.equal(isNewestFeedPage(1, newest.pageCount), false);
            assert.equal(newest.rangeStart, 151);
            assert.equal(newest.rangeEnd, 180);
            assert.deepEqual(newest.rows, original.slice(150));

            const middle = paginateFeed(original, 75, 1, false);
            const afterAppend = paginateFeed([...original, 181], 75, 1, false);
            assert.equal(afterAppend.page, middle.page);
            assert.deepEqual(afterAppend.rows, middle.rows);
            """
        )

    def test_refresh_follows_only_at_newest_edge_and_counts_unseen_rows(self) -> None:
        self.run_node(
            """
            const reading = {
              page: 1, followNewest: false, newCount: 2, newestSeq: 40
            };
            const whileReading = reduceFeedRefresh(reading, 43, 3, false);
            assert.equal(whileReading.followNewest, false);
            assert.equal(whileReading.newCount, 5);
            assert.equal(whileReading.newestSeq, 43);
            assert.equal(whileReading.page, 1);

            const atNewestEdge = reduceFeedRefresh(reading, 43, 3, true);
            assert.equal(atNewestEdge.followNewest, true);
            assert.equal(atNewestEdge.newCount, 0);
            """
        )

    def test_rapid_unchanged_refreshes_do_not_replace_the_dom(self) -> None:
        self.run_node(
            """
            for (let index = 0; index < 1000; index += 1) {
              assert.equal(shouldReplaceRender("p:room", "same", "p:room", "same"), false);
            }
            assert.equal(shouldReplaceRender("p:room", "old", "p:room", "new"), true);
            assert.equal(shouldReplaceRender("p:room", "same", "q:room", "same"), true);
            assert.equal(shouldReplaceRender("p:room", "same", "p:room", "same", true), true);
            """
        )
        self.assertIn("const loadSerial = ++state.loadSerial", self.source)
        self.assertIn("if (!requestIsCurrent()) return", self.source)

    def test_rendering_uses_stable_keys_and_restores_a_visible_anchor(self) -> None:
        self.assertNotIn("content.innerHTML = renderer();", self.source)
        self.assertIn("shouldReplaceRender(state.renderedKey", self.source)
        self.assertIn("captureFeedViewport()", self.source)
        self.assertIn("snapshot.anchorKey", self.source)
        self.assertIn("anchor.getBoundingClientRect().top - feed.getBoundingClientRect().top", self.source)
        self.assertIn("feed.scrollTop += offsetDelta", self.source)
        self.assertGreaterEqual(self.source.count('data-feed-key="${h('), 2)
        self.assertIn("snapshot.nearNewest", self.source)
        self.assertIn('kind === "room" ? feed.scrollHeight : 0', self.source)

    def test_room_and_activity_have_explicit_pagination_and_larger_windows(self) -> None:
        self.assertIn("const ROOM_HISTORY_LIMIT = 500", self.source)
        self.assertIn("const ACTIVITY_HISTORY_LIMIT = 1000", self.source)
        self.assertIn("const ROOM_PAGE_SIZE = 75", self.source)
        self.assertIn("const ACTIVITY_PAGE_SIZE = 100", self.source)
        self.assertIn('data-action="${kind}-older"', self.source)
        self.assertIn('data-action="${kind}-newer"', self.source)
        self.assertIn("Latest ${allMessages.length} retained room messages loaded", self.source)
        self.assertIn("Up to ${h(ACTIVITY_HISTORY_LIMIT)} events", self.source)
        self.assertRegex(
            self.source,
            r"\.room-feed, \.history-feed \{[^}]*min-height: clamp\(520px, 64vh, 760px\);"
            r"[^}]*max-height: min\(78vh, 940px\);",
        )
        self.assertIn("min-height: 56vh; max-height: 72vh", self.source)

    def test_conversation_and_filter_changes_intentionally_reset_the_page(self) -> None:
        conversation_handler = re.search(
            r'if \(event\.target\.id === "room-conversation"\) \{(?P<body>.*?)\n\s*\}',
            self.source,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(conversation_handler)
        self.assertIn('resetFeed("room")', conversation_handler.group("body"))
        self.assertIn("await loadProjectData({ quiet: true })", conversation_handler.group("body"))

        filter_handler = re.search(
            r'if \(event\.target\.id === "activity-search"\) \{(?P<body>.*?)\n\s*\}',
            self.source,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(filter_handler)
        self.assertIn('resetFeed("activity")', filter_handler.group("body"))
        self.assertIn('feedTransition: "activity"', filter_handler.group("body"))
        self.assertIn('const roomScope = `${state.projectId}:${state.roomConversation}`', self.source)
        self.assertIn('const activityScope = `${state.projectId}:${query}`', self.source)

    def test_feeds_and_controls_are_keyboard_and_screen_reader_accessible(self) -> None:
        self.assertGreaterEqual(self.source.count('role="log"'), 2)
        self.assertGreaterEqual(self.source.count('aria-live="off" tabindex="0"'), 2)
        self.assertIn('role="navigation" aria-label="${h(identityPart(title))} history pages"', self.source)
        self.assertIn('class="button quiet small new-items"', self.source)
        self.assertIn('aria-live="polite"', self.source)
        self.assertIn('empty("No matching events"', self.source)
        self.assertIn("state.errors.events ? errorNotice", self.source)
        self.assertIn("conversationDenied ? empty", self.source)


if __name__ == "__main__":
    unittest.main()
