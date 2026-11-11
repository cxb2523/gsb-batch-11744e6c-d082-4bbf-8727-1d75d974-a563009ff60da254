"""The manual CI workflow, pinned from its text: trigger, permissions, runners, pinned actions and the one command."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/manual-proof.yml"
CHECKOUT = ("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", "v7.0.1")
SETUP_PYTHON = ("actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0", "v7.1.0")
COMMAND = 'python -B tools/host_proof.py --receipt "${{ runner.temp }}/receipt.json"'


def scalar(text):
    """A plain or double-quoted scalar; "value # comment" gives (value, comment). Anything else is refused."""
    value, _, comment = text.partition(" # ")
    value = value.strip()
    if not value or value[0] in "&*{[|>!'%@`":
        raise ValueError("not a plain block-style scalar: " + text)
    if value[0] == '"':
        if len(value) < 2 or not value.endswith('"') or '"' in value[1:-1]:
            raise ValueError("unbalanced quotes: " + text)
        value = value[1:-1]
    return (value, comment.strip()) if comment else value


def parse(text):
    """The block-style subset this workflow uses: mappings, sequences, plain or double-quoted scalars, comments."""
    rows = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if "\t" in raw:
            raise ValueError("tab in indentation")
        rows.append([len(raw) - len(raw.lstrip(" ")), raw.strip()])
    value, end = node(rows, 0, rows[0][0])
    if end != len(rows):
        raise ValueError("unparsed lines from " + rows[end][1])
    return value


def node(rows, i, indent):
    if rows[i][1].startswith("- "):
        items = []
        while i < len(rows) and rows[i][0] == indent and rows[i][1].startswith("- "):
            body = rows[i][1][2:]
            if re.match(r"[A-Za-z_-]+:( |$)", body):
                rows[i] = [indent + 2, body]  # a mapping item continues at the column after "- "
                item, i = node(rows, i, indent + 2)
            else:
                item, i = scalar(body), i + 1
            items.append(item)
        return items, i
    mapping = {}
    while i < len(rows) and rows[i][0] == indent:
        key, colon, rest = rows[i][1].partition(":")
        if not colon or not re.fullmatch(r"[A-Za-z_-]+", key) or key in mapping or (rest and rest[0] != " "):
            raise ValueError("not a block mapping line: " + rows[i][1])
        if rest.strip():
            mapping[key], i = scalar(rest), i + 1
        elif i + 1 < len(rows) and rows[i + 1][0] > indent:
            mapping[key], i = node(rows, i + 1, rows[i + 1][0])
        else:
            raise ValueError("empty value for " + key)
    return mapping, i


def job(target, runner):
    return {"if": f"inputs.target == '{target}' || inputs.target == 'both'", "runs-on": runner,
            "timeout-minutes": "30", "steps": [
                {"uses": CHECKOUT, "with": {"persist-credentials": "false"}},
                {"uses": SETUP_PYTHON, "with": {"python-version": "3.12"}},
                {"name": "Host proof", "run": COMMAND}]}


class ManualWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text(encoding="utf-8")
        self.code = [line for line in self.text.splitlines() if line.strip() and not line.lstrip().startswith("#")]

    def test_the_whole_workflow_is_exactly_the_contracted_structure(self):
        self.assertEqual(parse(self.text), {
            "name": "manual-proof",
            "on": {"workflow_dispatch": {"inputs": {"target": {
                "description": "Hosts to prove", "required": "true", "default": "linux", "type": "choice",
                "options": ["linux", "windows", "both"]}}}},
            "permissions": {"contents": "read"},
            "jobs": {"linux": job("linux", "ubuntu-24.04"), "windows": job("windows", "windows-2025")}})

    def test_no_other_trigger_secret_cache_upload_or_write_permission_appears(self):
        code = "\n".join(self.code)
        for word in ("push", "pull_request", "schedule", "workflow_run", "workflow_call", "repository_dispatch",
                     "secrets", "cache", "artifact", "deploy", "environment", "write", "token", "GITHUB_TOKEN"):
            with self.subTest(word=word):
                self.assertNotIn(word, code)
        self.assertTrue(self.text.isascii())

    def test_actions_are_pinned_by_full_commit_with_the_version_as_a_comment(self):
        uses = [line.strip() for line in self.code if line.strip().startswith("- uses:")]
        self.assertEqual(uses, [f"- uses: {pin} # {version}" for pin, version in (CHECKOUT, SETUP_PYTHON)] * 2)
        for pin, _ in (CHECKOUT, SETUP_PYTHON):
            self.assertRegex(pin, r"@[0-9a-f]{40}\Z")
        self.assertEqual(self.text.count('python-version: "3.12"'), 2)  # quoted: an unquoted 3.12 is a YAML float
        self.assertEqual([line.strip() for line in self.code if line.strip().startswith("run:")], ["run: " + COMMAND] * 2)

    def test_the_reader_refuses_anchors_flow_collections_and_block_scalars(self):
        for text in ("a: &x 1\n", "a: *x\n", "a: {b: 1}\n", "a: [1, 2]\n", "a: |\n  text\n", "a: 'x'\n",
                     "a:\n  - &x b\n", "a:b\n", "a: 1\na: 2\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse(text)


if __name__ == "__main__":
    unittest.main()
