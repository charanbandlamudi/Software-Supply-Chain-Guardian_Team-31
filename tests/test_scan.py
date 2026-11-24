from pathlib import Path

import pytest

import pipeline.scan as scan


@pytest.mark.parametrize("target", ["", "   ", "\n\t"])
def test_parse_target_rejects_blank_input(target):
    with pytest.raises(ValueError, match="Enter an https://"):
        scan.parse_target(target)


def test_parse_target_accepts_local_directory(tmp_path):
    kind, owner, name = scan.parse_target(str(tmp_path))
    assert (kind, owner) == ("local", "local")
    assert name == tmp_path.name


def test_load_scan_rebases_old_absolute_paths(monkeypatch, tmp_path):
    scans = tmp_path / "data" / "scans"
    scan_id = "owner__repo__20261124-120000"
    scan_dir = scans / scan_id
    scan_dir.mkdir(parents=True)
    old_dir = "/Users/example/project/data/scans"
    metadata = {
        "scan_id": scan_id,
        "scan_dir": f"{old_dir}/{scan_id}",
        "status": "complete",
        "artifacts": {
            "graph_json": f"{old_dir}/{scan_id}/graphs/graph.json",
            "sbom": f"{old_dir}/{scan_id}/sbom/bom.json",
        },
    }
    (scan_dir / "scan.json").write_text(__import__("json").dumps(metadata), encoding="utf-8")
    monkeypatch.setattr(scan, "SCANS_DIR", scans)

    loaded = scan.load_scan(scan_id)

    assert loaded["scan_dir"] == str(scan_dir)
    assert loaded["artifacts"]["graph_json"] == str(scan_dir / "graphs" / "graph.json")
    assert loaded["artifacts"]["sbom"] == str(scan_dir / "sbom" / "bom.json")


def test_load_scan_persists_interrupted_status(monkeypatch, tmp_path):
    scans = tmp_path / "data" / "scans"
    scan_id = "owner__repo__20261124-120000"
    scan_dir = scans / scan_id
    scan_dir.mkdir(parents=True)
    scan_file = scan_dir / "scan.json"
    scan_file.write_text(__import__("json").dumps({
        "scan_id": scan_id,
        "status": "running",
        "artifacts": {},
    }), encoding="utf-8")
    monkeypatch.setattr(scan, "SCANS_DIR", scans)

    loaded = scan.load_scan(scan_id)

    assert loaded["status"] == "interrupted"
    assert __import__("json").loads(scan_file.read_text(encoding="utf-8"))["status"] == "interrupted"
