from __future__ import annotations

import pytest

from k8s_configmap_orphan_finder.audit import Options, audit, collect_references
from k8s_configmap_orphan_finder.loader import load_manifests
from k8s_configmap_orphan_finder.model import LoadError


def run(path: str, **kwargs):
    return audit(load_manifests(path), Options(**kwargs))


def ids(result):
    return {(f.finding, f.kind, f.name) for f in result.findings}


def test_finds_orphans_and_dangling_reference(basic_dir):
    result = run(basic_dir)
    assert ("orphan-configmap", "ConfigMap", "old-app-config") in ids(result)
    assert ("orphan-secret", "Secret", "stale-api-key") in ids(result)
    assert ("dangling-configmap-ref", "ConfigMap", "ca-bundle") in ids(result)


def test_referenced_objects_are_never_reported(basic_dir):
    reported = {f.name for f in run(basic_dir).findings}
    for name in (
        "api-config",
        "nginx-snippets",
        "report-templates",
        "db-credentials",
        "api-tls",
        "ghcr-pull",
        "smtp-credentials",
    ):
        assert name not in reported


def test_ingress_tls_and_service_account_secrets_are_in_use(basic_dir):
    reported = {f.name for f in run(basic_dir).findings}
    assert "shop-example-com-tls" not in reported
    assert "basic-auth" not in reported
    assert "api-sa-token" not in reported


def test_cluster_and_controller_owned_objects_are_skipped(basic_dir):
    reported = {f.name for f in run(basic_dir).findings}
    assert "kube-root-ca.crt" not in reported
    assert "sh.helm.release.v1.shop.v7" not in reported


def test_service_account_token_is_its_own_finding(basic_dir):
    finding = next(
        f for f in run(basic_dir).findings if f.finding == "orphan-serviceaccount-token"
    )
    assert finding.name == "orphan-sa-token"
    assert finding.severity == "medium"
    assert "deleted-sa" in finding.detail


def test_optional_dangling_reference_is_low_severity(basic_dir):
    finding = next(f for f in run(basic_dir).findings if f.name == "legacy-token")
    assert finding.finding == "dangling-secret-ref"
    assert finding.severity == "low"
    assert "optional" in finding.detail
    assert finding.referrers


def test_severities_assigned_as_documented(basic_dir):
    by_name = {f.name: f.severity for f in run(basic_dir).findings}
    assert by_name["stale-api-key"] == "high"
    assert by_name["ca-bundle"] == "high"
    assert by_name["old-app-config"] == "medium"


def test_findings_are_sorted_by_severity(basic_dir):
    order = [f.severity for f in run(basic_dir).findings]
    rank = {"high": 0, "medium": 1, "low": 2}
    assert order == sorted(order, key=lambda s: rank[s])


def test_clean_namespace_has_no_findings(clean_dir):
    result = run(clean_dir)
    assert result.findings == []
    assert result.configmaps == 3
    assert result.secrets == 3
    assert result.namespaces == ["platform"]


def test_ignore_glob_suppresses_by_name(basic_dir):
    reported = {f.name for f in run(basic_dir, ignore=["stale-*", "old-app-config"]).findings}
    assert "stale-api-key" not in reported
    assert "old-app-config" not in reported
    assert "ca-bundle" in reported


def test_skip_kinds_drops_a_target_kind(basic_dir):
    kinds = {f.kind for f in run(basic_dir, skip_kinds=["Secret"]).findings}
    assert kinds == {"ConfigMap"}


def test_skip_kinds_drops_a_referencing_kind(basic_dir):
    # Skipping the CronJob removes the only reference to report-templates,
    # which then shows up as an orphan.
    reported = {f.name for f in run(basic_dir, skip_kinds=["CronJob"]).findings}
    assert "report-templates" in reported


def test_min_severity_filters(basic_dir):
    severities = {f.severity for f in run(basic_dir, min_severity="high").findings}
    assert severities == {"high"}


def test_namespaces_are_isolated(tmp_path):
    (tmp_path / "a.yaml").write_text(
        """
apiVersion: v1
kind: ConfigMap
metadata:
  name: shared
  namespace: one
---
apiVersion: v1
kind: Pod
metadata:
  name: user
  namespace: two
spec:
  containers:
    - name: c
      envFrom:
        - configMapRef:
            name: shared
"""
    )
    result = audit(load_manifests(str(tmp_path)))
    assert ("orphan-configmap", "ConfigMap", "shared") in ids(result)
    assert ("dangling-configmap-ref", "ConfigMap", "shared") in ids(result)


def test_default_namespace_is_applied(tmp_path):
    (tmp_path / "a.yaml").write_text(
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: loose\n"
    )
    inventory = load_manifests(str(tmp_path), default_namespace="staging")
    assert inventory.namespaces() == ["staging"]


def test_pod_inherits_service_account_image_pull_secret(tmp_path):
    (tmp_path / "a.yaml").write_text(
        """
apiVersion: v1
kind: ServiceAccount
metadata:
  name: runner
  namespace: ci
imagePullSecrets:
  - name: registry
---
apiVersion: v1
kind: Secret
metadata:
  name: registry
  namespace: ci
type: kubernetes.io/dockerconfigjson
---
apiVersion: v1
kind: Pod
metadata:
  name: build
  namespace: ci
spec:
  serviceAccountName: runner
  containers:
    - name: c
"""
    )
    result = audit(load_manifests(str(tmp_path)))
    assert result.findings == []
    refs = collect_references(load_manifests(str(tmp_path)))
    referrers = {r.referrer for refs_list in refs.values() for r in refs_list}
    assert any("via ServiceAccount/runner" in r for r in referrers)


def test_list_wrapper_is_unwrapped(clean_dir):
    inventory = load_manifests(clean_dir)
    assert len(inventory.resources) == 9


def test_invalid_yaml_raises_load_error(fixtures_dir):
    import os

    with pytest.raises(LoadError):
        load_manifests(os.path.join(fixtures_dir, "broken"))


def test_missing_directory_raises_load_error():
    with pytest.raises(LoadError):
        load_manifests("/nonexistent/path/for/tests")


def test_directory_without_manifests_raises(tmp_path):
    (tmp_path / "notes.txt").write_text("hello")
    with pytest.raises(LoadError):
        load_manifests(str(tmp_path))
