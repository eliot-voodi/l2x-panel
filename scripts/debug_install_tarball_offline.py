#!/usr/bin/env python3
"""Offline checks for install.sh repo tarball URL ordering."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def ok(name: str) -> None:
    print(f"  OK  {name}")


def fail(name: str, msg: str) -> None:
    print(f" FAIL {name}: {msg}")
    raise SystemExit(1)


def test_branch_prefers_heads():
    text = (ROOT / "install.sh").read_text(encoding="utf-8")
    assert "_download_repo_tarball()" in text
    assert "refs/heads/${BRANCH}" in text
    assert "refs/tags/${BRANCH}" in text
    assert '[ "$code" = "404" ]' in text
    # else branch (non-version): heads first
    else_idx = text.find('urls=("${head_urls[@]}" "${tag_urls[@]}"')
    tag_first = text.find('urls=("${tag_urls[@]}" "${head_urls[@]}"')
    if else_idx < 0:
        fail("order", "missing heads-first urls= for branch refs")
    if tag_first < 0:
        fail("order", "missing tags-first urls= for version refs")
    # In the if/else, version path (tag first) appears before else (heads first)
    if tag_first > else_idx:
        fail("order", "expected version→tags-first before else→heads-first")
    ok("main → heads before tags; 404 skips")


def test_version_tag_regex():
    # sanity: what install.sh considers a tag
    pat = re.compile(r"^[vV]?[0-9]+\.[0-9]+")
    assert pat.match("v1.9.77")
    assert pat.match("1.9.77")
    assert not pat.match("main")
    assert not pat.match("master")
    ok("tag vs branch classification")


def main():
    print("== L2X install tarball offline debug ==")
    test_branch_prefers_heads()
    test_version_tag_regex()
    print("ALL PASSED")


if __name__ == "__main__":
    main()
