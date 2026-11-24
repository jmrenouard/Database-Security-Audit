"""Executable verification tests for Database-Security-Audit docs, STE rules, Mermaid, SQL, and bash snippets."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from urllib.parse import unquote

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR = REPO_ROOT / "docs"

LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)\n]+)\)")
FENCE_RE = re.compile(r"^(?P<indent>[ \t]*)(?P<ticks>`{3,}|~{3,})(?P<info>.*)$")
BOX_CHAR_RE = re.compile(r"[\u2500-\u257f▼▲◄►]")
SMART_QUOTES_RE = re.compile(r"[\u2018\u2019\u201c\u201d]")
FRENCH_DOC_MARKERS = re.compile(
    r"\b(?:procédure|tutoriel|démarrage|prérequis|vérification|"
    r"retour\s+arrière|utilisation|générateur|dico\.txt)\b",
    re.IGNORECASE,
)
STE_BANNED = re.compile(
    r"(?:;|should\b|would\b|may\b|might\b|shall\b|"
    r"\b(?:don't|doesn't|isn't|aren't|won't|can't|let's)\b)",
    re.IGNORECASE,
)


def _iter_markdown() -> list[Path]:
    """Return all repository Markdown files outside .git."""
    return sorted(p for p in REPO_ROOT.rglob("*.md") if ".git/" not in p.as_posix())


def _extract_fenced_blocks(text: str) -> list[dict[str, object]]:
    """Extract fenced code blocks with indentation and language tag metadata."""
    blocks: list[dict[str, object]] = []
    open_fence: dict[str, object] | None = None
    for idx, line in enumerate(text.splitlines(), start=1):
        match = FENCE_RE.match(line)
        if open_fence is None:
            if match:
                ticks = match.group("ticks")
                open_fence = {
                    "char": ticks[0],
                    "len": len(ticks),
                    "indent": match.group("indent"),
                    "info": match.group("info").strip().lower(),
                    "start_line": idx,
                    "lines": [],
                }
        else:
            if match and match.group("ticks")[0] == open_fence["char"] and len(match.group("ticks")) >= int(open_fence["len"]):
                if not match.group("info").strip():
                    open_fence["code"] = "\n".join(open_fence["lines"])  # type: ignore[arg-type]
                    blocks.append(open_fence)
                    open_fence = None
                    continue
            open_fence["lines"].append(line)  # type: ignore[union-attr]
    if open_fence is not None:
        raise AssertionError(f"Unclosed fenced code block at line {open_fence['start_line']}")
    return blocks


def _strip_code(text: str) -> str:
    """Return Markdown text outside fenced and inline code spans."""
    lines: list[str] = []
    in_fence = False
    fence_char = ""
    fence_len = 0
    for line in text.splitlines():
        match = FENCE_RE.match(line)
        if not in_fence:
            if match:
                in_fence = True
                fence_char = match.group("ticks")[0]
                fence_len = len(match.group("ticks"))
            else:
                lines.append(re.sub(r"`[^`]+`", "", line))
        else:
            if match and match.group("ticks")[0] == fence_char and len(match.group("ticks")) >= fence_len and not match.group("info").strip():
                in_fence = False
    return "\n".join(lines)


def _heading_slugs(text: str) -> set[str]:
    """Build GitHub-style heading anchors from Markdown outside code blocks."""
    slugs: set[str] = set()
    counts: dict[str, int] = {}
    for line in _strip_code(text).splitlines():
        match = re.match(r"^\s{0,3}#{1,6}\s+(.+?)\s*$", line)
        if not match:
            continue
        raw = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", match.group(1).strip())
        slug = re.sub(r"[^a-z0-9\- ]+", "", raw.lower()).strip().replace(" ", "-")
        slug = re.sub(r"-{2,}", "-", slug)
        if not slug:
            continue
        seen = counts.get(slug, 0)
        counts[slug] = seen + 1
        slugs.add(slug if seen == 0 else f"{slug}-{seen}")
    return slugs


class TestDatabaseSecurityAuditDocs(unittest.TestCase):
    """Validate Diátaxis structure, STE compliance, safety notices, Mermaid, SQL, and bash snippets."""

    def test_diataxis_links_safety_warnings_and_ste(self) -> None:
        required_docs = [
            REPO_ROOT / "README.md",
            REPO_ROOT / "MySQL database penetration testing.md",
            REPO_ROOT / "PostgreSQL database penetration testing.md",
            DOCS_DIR / "index.md",
            DOCS_DIR / "01-tutorials" / "index.md",
            DOCS_DIR / "01-tutorials" / "01-isolated-mysql-postgres-audit-lab.md",
            DOCS_DIR / "02-how-to-guides" / "index.md",
            DOCS_DIR / "02-how-to-guides" / "audit-mysql-security.md",
            DOCS_DIR / "02-how-to-guides" / "audit-postgresql-security.md",
            DOCS_DIR / "03-reference" / "index.md",
            DOCS_DIR / "03-reference" / "security-audit-checks-and-ports.md",
            DOCS_DIR / "04-explanation" / "index.md",
            DOCS_DIR / "04-explanation" / "threat-model-and-defense-in-depth.md",
        ]
        for path in required_docs:
            self.assertTrue(path.is_file(), f"Missing doc: {path}")

        for guided_doc in [
            REPO_ROOT / "README.md",
            REPO_ROOT / "MySQL database penetration testing.md",
            REPO_ROOT / "PostgreSQL database penetration testing.md",
            DOCS_DIR / "index.md",
            DOCS_DIR / "01-tutorials" / "01-isolated-mysql-postgres-audit-lab.md",
            DOCS_DIR / "02-how-to-guides" / "audit-mysql-security.md",
            DOCS_DIR / "02-how-to-guides" / "audit-postgresql-security.md",
        ]:
            text_lower = guided_doc.read_text(encoding="utf-8").lower()
            self.assertTrue(
                "authorized" in text_lower or "isolated" in text_lower,
                f"Missing authorization or isolated-lab notice in {guided_doc}",
            )

        for md_file in _iter_markdown():
            content = md_file.read_text(encoding="utf-8")
            plain = _strip_code(content)
            self.assertIsNone(FRENCH_DOC_MARKERS.search(content), f"French/stale token in {md_file}")

            for link in LINK_RE.findall(plain):
                if link.startswith(("http://", "https://", "mailto:")):
                    continue
                target_str, _, anchor = link.partition("#")
                decoded = unquote(target_str)
                target_path = md_file if not decoded else (md_file.parent / decoded).resolve()
                self.assertTrue(target_path.exists(), f"Broken link '{link}' in {md_file}")
                if anchor and target_path.is_file() and target_path.suffix == ".md":
                    slugs = _heading_slugs(target_path.read_text(encoding="utf-8"))
                    self.assertIn(anchor, slugs, f"Broken anchor '#{anchor}' in {md_file}")

        for howto in sorted((DOCS_DIR / "02-how-to-guides").glob("*.md")):
            plain = _strip_code(howto.read_text(encoding="utf-8"))
            self.assertIsNone(STE_BANNED.search(plain), f"ASD-STE100 banned pattern in {howto}")

    def test_mermaid_and_zero_ascii_diagrams(self) -> None:
        mermaid_total = 0
        for md_file in _iter_markdown():
            content = md_file.read_text(encoding="utf-8")
            for block in _extract_fenced_blocks(content):
                code = str(block["code"])
                info = str(block["info"])
                if info == "mermaid":
                    mermaid_total += 1
                    self.assertEqual(block["indent"], "", f"Indented mermaid block in {md_file}")
                    first_line = next((ln.strip() for ln in code.splitlines() if ln.strip()), "")
                    self.assertTrue(
                        first_line.startswith(("flowchart ", "graph ", "sequenceDiagram")),
                        f"Unsupported mermaid diagram header '{first_line}' in {md_file}",
                    )
                elif info in {"", "text", "plaintext", "ascii"}:
                    self.assertNotIn("-->", code, f"ASCII arrow found in {md_file}")
                    self.assertNotIn("graph ", code, f"Untagged mermaid diagram in {md_file}")
                    self.assertIsNone(BOX_CHAR_RE.search(code), f"Box-drawing art in {md_file}")

        self.assertGreaterEqual(mermaid_total, 3)

    def test_legacy_guide_syntax_fixes_and_sql_bash_snippets(self) -> None:
        mysql_guide = (REPO_ROOT / "MySQL database penetration testing.md").read_text(encoding="utf-8")
        pg_guide = (REPO_ROOT / "PostgreSQL database penetration testing.md").read_text(encoding="utf-8")

        self.assertNotIn("> map -p 3306", mysql_guide)
        self.assertNotIn("LOAD_FILE('/root/.my.cnf);", mysql_guide)
        self.assertNotIn("SELECT * @@proxy_user;", mysql_guide)
        self.assertNotIn("--script-args -query=", mysql_guide)
        self.assertNotIn("To ADD", mysql_guide)
        self.assertNotIn("postgresSQL", pg_guide)
        self.assertNotIn("__passsword__", pg_guide)
        self.assertNotIn("2a01:e35:2fef", pg_guide)
        self.assertNotIn("To research...", pg_guide)
        self.assertIsNone(SMART_QUOTES_RE.search(mysql_guide), "Curly smart quotes remain in MySQL guide")
        self.assertIsNone(SMART_QUOTES_RE.search(pg_guide), "Curly smart quotes remain in PostgreSQL guide")

        bash_checked = 0
        sql_checked = 0
        for md_file in sorted(DOCS_DIR.rglob("*.md")):
            for block in _extract_fenced_blocks(md_file.read_text(encoding="utf-8")):
                info = str(block["info"])
                code = str(block["code"])
                if info == "sql":
                    sql_checked += 1
                    self.assertIsNone(SMART_QUOTES_RE.search(code), f"Curly quotes inside SQL in {md_file}")
                    self.assertEqual(code.count("'") % 2, 0, f"Unbalanced single quote in SQL block of {md_file}")
                    self.assertEqual(code.count("("), code.count(")"), f"Unbalanced parentheses in SQL block of {md_file}")
                    self.assertNotIn("//", code, f"Invalid // SQL comment in {md_file}")
                elif info in {"bash", "sh"} and os.name != "nt" and shutil.which("bash"):
                    # Strip <<'SQL'...SQL heredocs cleanly for bash syntax check; bash -n validates full script including heredoc directly.
                    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False, encoding="utf-8") as tmp:
                        tmp.write(code + "\n")
                        tmp_path = tmp.name
                    try:
                        res = subprocess.run(["bash", "-n", tmp_path], capture_output=True, text=True, timeout=15)
                        self.assertEqual(res.returncode, 0, f"bash -n failed in {md_file}: {res.stderr}\n{code}")
                        bash_checked += 1
                    finally:
                        Path(tmp_path).unlink(missing_ok=True)

        self.assertGreaterEqual(sql_checked, 5)
        if os.name != "nt" and shutil.which("bash"):
            self.assertGreaterEqual(bash_checked, 5)


if __name__ == "__main__":
    unittest.main()
