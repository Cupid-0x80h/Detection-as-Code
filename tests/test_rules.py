import glob
import json
import re
import shutil
import subprocess
import uuid
from datetime import date
from pathlib import Path

import yaml

REPO = Path(__file__).parent.parent
RULES = sorted(glob.glob(str(REPO / "rules" / "**" / "*.yml"), recursive=True))
SIGMA = shutil.which("sigma") or str(REPO.parent / ".venv" / "bin" / "sigma")

REQUIRED_FIELDS = ("title", "id", "status", "description", "references", "author",
                   "date", "tags", "logsource", "detection", "falsepositives", "level")

LEVELS = ("informational", "low", "medium", "high", "critical")
TAG_RE = re.compile(r"^attack\.[a-z0-9.-]+$")
TECHNIQUE_RE = re.compile(r"^attack\.t\d")


def load(rule_path):
    return yaml.safe_load(Path(rule_path).read_text())


def test_rules_exist():
    assert RULES, "no sigma rules found under rules/"


def test_required_fields():
    for rule_path in RULES:
        missing = [f for f in REQUIRED_FIELDS if f not in load(rule_path)]
        assert not missing, f"{rule_path}: missing {missing}"


def test_valid_uuid():
    for rule_path in RULES:
        uuid.UUID(load(rule_path)["id"])


def test_unique_id_and_title():
    ids = [load(p)["id"] for p in RULES]
    titles = [load(p)["title"] for p in RULES]
    assert len(set(ids)) == len(ids), "duplicate rule id"
    assert len(set(titles)) == len(titles), "duplicate rule title"


def test_detection_shape():
    for rule_path in RULES:
        detection = load(rule_path)["detection"]
        assert "condition" in detection, f"{rule_path}: detection missing condition"
        selections = [k for k in detection if k == "selection" or k.startswith("selection_")]
        assert selections, f"{rule_path}: no selection block in detection"


def test_level_and_status():
    for rule_path in RULES:
        rule = load(rule_path)
        assert rule["level"] in LEVELS, f"{rule_path}: bad level {rule['level']}"
        assert rule["status"] in ("experimental", "test", "stable"), \
            f"{rule_path}: bad status {rule['status']}"


def test_attack_tags():
    for rule_path in RULES:
        tags = load(rule_path)["tags"]
        assert all(TAG_RE.match(t) for t in tags), f"{rule_path}: malformed tags {tags}"
        assert any(TECHNIQUE_RE.match(t) for t in tags), f"{rule_path}: no ATT&CK technique"


def test_iso_date():
    for rule_path in RULES:
        date.fromisoformat(str(load(rule_path)["date"]))


def test_mitre_coverage_floor():
    techniques = {t for p in RULES for t in load(p)["tags"] if TECHNIQUE_RE.match(t)}
    assert len(techniques) >= 20, f"only {len(techniques)} distinct techniques mapped"


def test_conversion_succeeds():
    out = subprocess.run(
        [SIGMA, "convert", "-t", "lucene", "-p", "ecs_windows", "-p", "ecs_kubernetes", "-p", "ecs_zeek_beats",
         "-f", "siem_rule_ndjson", str(REPO / "rules")],
        capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    lines = [l for l in out.stdout.splitlines() if l.strip()]
    assert len(lines) >= len(RULES), f"expected >= {len(RULES)} compiled rules, got {len(lines)}"

    rules = [json.loads(l) for l in lines]
    assert all(r.get("rule_id") and r.get("query") for r in rules), "compiled output is not detection rules"
