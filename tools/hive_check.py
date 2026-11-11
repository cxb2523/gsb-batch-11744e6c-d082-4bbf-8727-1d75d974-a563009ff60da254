"""Deterministic citation check for an AI analyst team's claims.

Agents in the hive (see docs/HIVE.md) cite the findings that ReverseAI returned
to them over MCP. This checker trusts none of the agents' transcripts: it runs
every cited question again through ReverseAI itself, with the same mapping the
MCP server uses, and keeps a claim only when each of its citations names a
finding that the fresh report contains with a `supported` or `derived` verdict.
Finding IDs are content-bound, so a citation can only resolve if the same file,
tool, operation and result produce it again.

It checks citations, not prose: whether the claim's sentence follows from the
cited findings is the council's judgement. It never executes the input.

    python tools/hive_check.py --inputs DIR --claims claims.json --out NEW_DIR [--with-ghidra] [--jobs 2]

claims.json:

    {"file": "program",
     "claims": [{"id": "main-usage",
                 "text": "Without arguments the program prints its usage line and exits 1.",
                 "citations": [{"tool": "search_strings", "args": {"query": "usage"},
                                "id": "fi-0123456789abcdef"}]}]}

`file` is the relative name inside DIR (a citation may override it with its own
`file`); `args` are the MCP tool arguments. The output directory receives
verdicts.json and one folder per distinct question. Exit status: 0 when every
claim is confirmed, 1 when any claim is rejected, 2 on a usage error.
"""

import argparse
import concurrent.futures
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from reverseai import mcp_tools  # noqa: E402

TOOLS = ("lief", "yarax", "ghidra", "jadx", "jsparser")
ID = re.compile(r"(fi|ev)-[0-9a-f]{16}\Z")
CLAIM_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
KEPT = ("supported", "derived")
MAX_CLAIMS = 5000
MAX_CITATIONS = 32
MAX_QUESTIONS = 1000
QUESTION_TIMEOUT = 1500


class UsageError(ValueError):
    pass


def _require(condition, message):
    if not condition:
        raise UsageError(message)


def load_claims(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise UsageError(f"cannot read claims: {error}") from None
    _require(isinstance(data, dict), "claims file must be a JSON object")
    default_file = data.get("file")
    _require(default_file is None or isinstance(default_file, str), "'file' must be a string")
    claims = data.get("claims")
    _require(isinstance(claims, list) and 0 < len(claims) <= MAX_CLAIMS,
             f"'claims' must be a list of 1..{MAX_CLAIMS} claims")
    seen = set()
    for claim in claims:
        _require(isinstance(claim, dict), "each claim must be an object")
        _require(isinstance(claim.get("id"), str) and CLAIM_ID.match(claim["id"]),
                 "each claim needs an 'id' of letters, digits and ._:- (at most 128)")
        _require(claim["id"] not in seen, f"duplicate claim id {claim['id']}")
        seen.add(claim["id"])
        _require(isinstance(claim.get("text"), str), f"claim {claim['id']}: 'text' must be a string")
        citations = claim.get("citations")
        _require(isinstance(citations, list) and len(citations) <= MAX_CITATIONS,
                 f"claim {claim['id']}: 'citations' must be a list of at most {MAX_CITATIONS}")
        for citation in citations:
            _require(isinstance(citation, dict), f"claim {claim['id']}: each citation must be an object")
            _require(isinstance(citation.get("tool"), str), f"claim {claim['id']}: citation needs 'tool'")
            _require(isinstance(citation.get("args", {}), dict), f"claim {claim['id']}: 'args' must be an object")
            _require(isinstance(citation.get("id"), str) and ID.match(citation["id"]),
                     f"claim {claim['id']}: citation 'id' must be a fi-/ev- ID")
            file = citation.get("file", citation.get("args", {}).get("file", default_file))
            _require(isinstance(file, str), f"claim {claim['id']}: no input file for a citation")
    return default_file, claims


def question_key(citation, default_file):
    args = dict(citation.get("args", {}))
    args["file"] = citation.get("file", args.get("file", default_file))
    return json.dumps({"tool": citation["tool"], "args": args}, sort_keys=True, separators=(",", ":"))


def run_question(key, number, *, inputs, out, enabled, runner, timeout):
    question = json.loads(key)
    folder = out / "questions" / f"{number:04d}"
    try:
        argv = mcp_tools.command(question["tool"], question["args"], root=str(inputs),
                                 out=str(folder), enabled=enabled)
    except Exception as error:  # the MCP layer's own refusals: unknown tool, bad arguments, refused path
        return {"status": "refused", "detail": type(error).__name__ + (f": {error}" if str(error) else "")}
    folder.parent.mkdir(parents=True, exist_ok=True)
    try:
        completed = runner(argv, timeout)
    except subprocess.TimeoutExpired:
        return {"status": "failed", "detail": f"no answer within {timeout} s"}
    report = folder / "report.json"
    if completed.returncode != 0 or not report.is_file():
        tail = (completed.stderr or "").strip().splitlines()[-1:] or [""]
        return {"status": "failed", "detail": f"exit {completed.returncode}: {tail[0][:300]}"}
    data = json.loads(report.read_text(encoding="utf-8"))
    findings, evidence = {}, {}
    for result in data.get("results", []):
        for finding in result.get("findings", []):
            findings[finding["id"]] = finding["verdict"]
            for evidence_id in finding.get("evidence_ids", []):
                if finding["verdict"] in KEPT or evidence_id not in evidence:
                    evidence[evidence_id] = finding["verdict"]
        for item in result.get("evidence", []):
            evidence.setdefault(item["id"], "unreviewed")
    return {"status": "ok", "input_sha256": data["input"]["sha256"], "folder": str(folder.relative_to(out)),
            "findings": findings, "evidence": evidence}


def default_runner(argv, timeout):
    command = [sys.executable, "-B", "-m", "reverseai", *argv]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=env, check=False)


def judge(claims, default_file, answers):
    verdicts = []
    for claim in claims:
        reasons, kinds = [], []
        if not claim["citations"]:
            reasons.append("no citation")
        for citation in claim["citations"]:
            answer = answers[question_key(citation, default_file)]
            label = f"{citation['tool']} {citation['id']}"
            if answer["status"] != "ok":
                reasons.append(f"{label}: question {answer['status']} ({answer['detail']})")
                continue
            table = answer["findings"] if citation["id"].startswith("fi-") else answer["evidence"]
            verdict = table.get(citation["id"])
            if verdict is None:
                reasons.append(f"{label}: not in the fresh report")
            elif verdict not in KEPT:
                reasons.append(f"{label}: {verdict}")
            else:
                kinds.append(verdict)
        verdicts.append({
            "id": claim["id"],
            "verdict": "rejected" if reasons else "confirmed",
            "basis": None if reasons else ("supported" if all(k == "supported" for k in kinds) else "derived"),
            "reasons": reasons,
        })
    return verdicts


def check(inputs, claims_path, out, *, enabled=frozenset(), jobs=2, runner=default_runner, timeout=QUESTION_TIMEOUT):
    inputs, out = Path(inputs), Path(out)
    _require(inputs.is_dir(), "--inputs must be an existing directory")
    _require(not out.exists() or (out.is_dir() and not any(out.iterdir())), "--out must be new or empty")
    default_file, claims = load_claims(claims_path)
    keys = sorted({question_key(c, default_file) for claim in claims for c in claim["citations"]})
    _require(len(keys) <= MAX_QUESTIONS, f"at most {MAX_QUESTIONS} distinct questions per check")
    out.mkdir(parents=True, exist_ok=True)
    answers = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        futures = {pool.submit(run_question, key, number, inputs=inputs, out=out, enabled=enabled,
                               runner=runner, timeout=timeout): key for number, key in enumerate(keys, 1)}
        for future in concurrent.futures.as_completed(futures):
            answers[futures[future]] = future.result()
    hashes = {a["input_sha256"] for a in answers.values() if a["status"] == "ok"}
    verdicts = judge(claims, default_file, answers)
    summary = {"claims": len(verdicts), "confirmed": sum(v["verdict"] == "confirmed" for v in verdicts),
               "rejected": sum(v["verdict"] == "rejected" for v in verdicts), "questions": len(keys),
               "input_sha256": sorted(hashes)}
    questions = [{"question": json.loads(key), **{k: v for k, v in answers[key].items()
                                                   if k not in ("findings", "evidence")}} for key in keys]
    (out / "verdicts.json").write_text(json.dumps({"summary": summary, "claims": verdicts, "questions": questions},
                                                  indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return summary, verdicts


def main(argv=None):
    parser = argparse.ArgumentParser(description="Re-run every cited ReverseAI question and keep only claims "
                                                 "whose citations resolve in the fresh reports.")
    parser.add_argument("--inputs", required=True, help="Directory of approved inputs (as given to reverseai mcp)")
    parser.add_argument("--claims", required=True, help="Claims JSON written by the team")
    parser.add_argument("--out", required=True, help="New or empty directory for verdicts.json and the reports")
    parser.add_argument("--jobs", type=int, default=2, help="Questions run at the same time (default 2)")
    for tool in TOOLS:
        parser.add_argument("--with-" + tool, action="store_true", help=f"Enable the contained {tool} tool")
    args = parser.parse_args(argv)
    enabled = frozenset(tool for tool in TOOLS if getattr(args, "with_" + tool))
    try:
        summary, verdicts = check(args.inputs, args.claims, args.out, enabled=enabled, jobs=args.jobs)
    except UsageError as error:
        print(f"hive_check: {error}", file=sys.stderr)
        return 2
    for verdict in verdicts:
        if verdict["verdict"] == "rejected":
            print(f"REJECTED {verdict['id']}: " + "; ".join(verdict["reasons"]))
    print(f"{summary['confirmed']}/{summary['claims']} claims confirmed from {summary['questions']} fresh questions")
    if len(summary["input_sha256"]) > 1:
        print("warning: citations resolved against more than one input", file=sys.stderr)
    return 0 if summary["rejected"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
