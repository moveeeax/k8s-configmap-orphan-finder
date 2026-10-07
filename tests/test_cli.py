from __future__ import annotations

import json

import pytest

from k8s_configmap_orphan_finder.cli import main


def test_exit_1_and_table_output(basic_dir, capsys):
    assert main(["--manifests", basic_dir]) == 1
    out = capsys.readouterr().out
    assert "SEVERITY" in out
    assert "stale-api-key" in out
    assert "orphan-configmap" in out
    assert "finding(s)" in out


def test_exit_0_on_clean_tree(clean_dir, capsys):
    assert main(["--manifests", clean_dir]) == 0
    out = capsys.readouterr().out
    assert "No orphans and no dangling references." in out


def test_exit_2_on_load_error(fixtures_dir, capsys):
    import os

    assert main(["--manifests", os.path.join(fixtures_dir, "broken")]) == 2
    assert "error:" in capsys.readouterr().err


def test_json_shape(basic_dir, capsys):
    assert main(["--manifests", basic_dir, "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["namespaces"] == ["shop"]
    assert payload["summary"]["findings"] == len(payload["findings"])
    assert payload["summary"]["by_severity"]["high"] >= 1
    secrets = [f for f in payload["findings"] if f["kind"] == "Secret"]
    assert secrets
    for finding in payload["findings"]:
        assert set(finding) == {
            "severity",
            "kind",
            "namespace",
            "name",
            "finding",
            "detail",
            "referrers",
        }


def test_comma_separated_ignore(basic_dir, capsys):
    assert main(["--manifests", basic_dir, "--ignore", "stale-*,old-app-config", "--json"]) == 1
    names = {f["name"] for f in json.loads(capsys.readouterr().out)["findings"]}
    assert "stale-api-key" not in names


def test_min_severity_gate(basic_dir, capsys):
    # A high-severity gate is the useful CI setting: orphaned ConfigMaps are
    # untidy, a dangling reference or a stray credential is a real problem.
    assert main(["--manifests", basic_dir, "--min-severity", "high", "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert {f["severity"] for f in payload["findings"]} == {"high"}
    assert payload["summary"]["by_severity"] == {"high": 2, "medium": 0, "low": 0}


def test_clean_tree_with_json_exits_0(clean_dir, capsys):
    assert main(["--manifests", clean_dir, "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"] == []
    assert payload["summary"]["configmaps"] == 3


def test_requires_a_source(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main([])
    assert excinfo.value.code == 2
    assert "choose a source" in capsys.readouterr().err


def test_sources_are_mutually_exclusive(basic_dir, capsys):
    with pytest.raises(SystemExit):
        main(["--manifests", basic_dir, "--namespace", "prod"])


def test_version(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert "0.1.0" in capsys.readouterr().out


def test_live_mode_without_client_is_a_load_error(monkeypatch, capsys):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("kubernetes"):
            raise ImportError("no kubernetes client")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert main(["--namespace", "prod"]) == 2
    assert "kubernetes client" in capsys.readouterr().err


def test_examples_tree_is_auditable():
    import os

    from k8s_configmap_orphan_finder.audit import audit
    from k8s_configmap_orphan_finder.loader import load_manifests

    root = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples", "k8s"
    )
    result = audit(load_manifests(root))
    assert result.findings, "the examples tree should demonstrate real findings"
