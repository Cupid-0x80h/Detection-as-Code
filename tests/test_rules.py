import glob
import shutil
import subprocess
import uuid
from pathlib import Path

import yaml

REPO = Path(__file__).parent.parent
RULES = sorted(glob.glob(str(REPO / "rules" / "**" / "*.yml"), recursive=True))
SIGMA = shutil.which("sigma") or str(REPO.parent / ".venv" / "bin" / "sigma")

REQUIRED_FIELDS = ("title", "id", "status", "description", "references", "author",
                   "date", "tags", "logsource", "detection", "falsepositives", "level")


def test_rules_exist():
    assert RULES, "no sigma rules found under rules/"


def test_required_fields():
    for rule_path in RULES:
        rule = yaml.safe_load(Path(rule_path).read_text())
        missing = [f for f in REQUIRED_FIELDS if f not in rule]
        assert not missing, f"{rule_path}: missing {missing}"


def test_valid_uuid():
    for rule_path in RULES:
        rule = yaml.safe_load(Path(rule_path).read_text())
        uuid.UUID(rule["id"])


def test_detection_shape():
    for rule_path in RULES:
        rule = yaml.safe_load(Path(rule_path).read_text())
        detection = rule["detection"]
        assert "condition" in detection, f"{rule_path}: detection missing condition"
        selections = [k for k in detection if k == "selection" or k.startswith("selection_")]
        assert selections, f"{rule_path}: no selection block in detection"


def test_conversion_succeeds():
    out = subprocess.run(
        [SIGMA, "convert", "-t", "lucene", "-p", "ecs_windows", "-p", "ecs_kubernetes", "-p", "ecs_zeek_beats",
         "-f", "kibana_ndjson", str(REPO / "rules")],
        capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    lines = [l for l in out.stdout.splitlines() if l.strip()]
    assert len(lines) >= len(RULES), f"expected >= {len(RULES)} compiled rules, got {len(lines)}"
