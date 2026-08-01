"""Tests for memory dedup module."""

from nodechain.memory.dedup import content_fingerprint, check_text_similarity, find_duplicate


class TestContentFingerprint:
    def test_deterministic(self):
        fp1 = content_fingerprint("Hello world")
        fp2 = content_fingerprint("Hello world")
        assert fp1 == fp2

    def test_normalizes_case(self):
        fp1 = content_fingerprint("Hello World")
        fp2 = content_fingerprint("hello world")
        assert fp1 == fp2

    def test_normalizes_whitespace(self):
        fp1 = content_fingerprint("Hello world")
        fp2 = content_fingerprint("  Hello world  ")
        assert fp1 == fp2

    def test_different_content(self):
        fp1 = content_fingerprint("Content A")
        fp2 = content_fingerprint("Content B")
        assert fp1 != fp2


class TestTextSimilarity:
    def test_identical_texts(self):
        score = check_text_similarity("the cat sat", "the cat sat")
        assert score == 1.0

    def test_no_overlap(self):
        score = check_text_similarity("alpha beta", "gamma delta")
        assert score == 0.0

    def test_partial_overlap(self):
        score = check_text_similarity("the cat sat on the mat", "the cat jumped over")
        assert 0.0 < score < 1.0

    def test_empty_both(self):
        score = check_text_similarity("", "")
        assert score == 1.0

    def test_empty_one(self):
        score = check_text_similarity("text", "")
        assert score == 0.0


class TestFindDuplicate:
    def test_finds_exact_duplicate(self):
        entries = [
            {"content": "AI improves diagnostics by 20%", "fingerprint": content_fingerprint("AI improves diagnostics by 20%")},
        ]
        result = find_duplicate("AI improves diagnostics by 20%", entries)
        assert result is not None

    def test_no_duplicate(self):
        entries = [
            {"content": "Completely different content", "fingerprint": content_fingerprint("Completely different content")},
        ]
        result = find_duplicate("AI improves diagnostics by 20%", entries)
        assert result is None

    def test_empty_entries(self):
        result = find_duplicate("Any content", [])
        assert result is None
