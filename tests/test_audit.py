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


KEYS_NS = """
apiVersion: v1
kind: ConfigMap
metadata:
  name: app
  namespace: keys
data:
  DB_PORT: "5432"
binaryData:
  logo.png: aGVsbG8=
---
apiVersion: v1
kind: Secret
metadata:
  name: creds
  namespace: keys
type: Opaque
data:
  username: YWRtaW4=
stringData:
  password: hunter2
---
apiVersion: v1
kind: Secret
metadata:
  name: sa-token
  namespace: keys
  annotations:
    kubernetes.io/service-account.name: default
type: kubernetes.io/service-account-token
---
apiVersion: v1
kind: Pod
metadata:
  name: web
  namespace: keys
spec:
  containers:
    - name: c
      env:
        - name: DB_HOST
          valueFrom:
            configMapKeyRef:
              name: app
              key: DB_HOST
        - name: DB_PORT
          valueFrom:
            configMapKeyRef:
              name: app
              key: DB_PORT
        - name: USER
          valueFrom:
            secretKeyRef:
              name: creds
              key: username
        - name: PASSWORD
          valueFrom:
            secretKeyRef:
              name: creds
              key: password
        - name: API_KEY
          valueFrom:
            secretKeyRef:
              name: creds
              key: api_key
              optional: true
        - name: TOKEN
          valueFrom:
            secretKeyRef:
              name: sa-token
              key: token
        - name: GONE
          valueFrom:
            configMapKeyRef:
              name: deleted
              key: anything
  volumes:
    - name: static
      configMap:
        name: app
        items:
          - key: logo.png
            path: logo.png
          - key: favicon.ico
            path: favicon.ico
"""


def key_findings(tmp_path, **kwargs):
    (tmp_path / "a.yaml").write_text(KEYS_NS)
    result = audit(load_manifests(str(tmp_path)), Options(**kwargs))
    return [f for f in result.findings if f.finding.endswith("-key")]


def test_missing_configmap_key_is_high(tmp_path):
    by_detail = {f.detail: f for f in key_findings(tmp_path) if f.kind == "ConfigMap"}
    assert set(by_detail) == {"key 'DB_HOST' not found", "key 'favicon.ico' not found"}
    for finding in by_detail.values():
        assert finding.finding == "dangling-configmap-key"
        assert finding.severity == "high"
        assert finding.name == "app"
    assert by_detail["key 'DB_HOST' not found"].referrers == [
        "Pod/web (containers.env.configMapKeyRef)"
    ]
    assert by_detail["key 'favicon.ico' not found"].referrers == [
        "Pod/web (volumes.configMap)"
    ]


def test_optional_missing_secret_key_is_low(tmp_path):
    secrets = [f for f in key_findings(tmp_path) if f.kind == "Secret"]
    assert len(secrets) == 1
    finding = secrets[0]
    assert finding.finding == "dangling-secret-key"
    assert finding.name == "creds"
    assert finding.severity == "low"
    assert finding.detail == "key 'api_key' not found (optional: true)"


def test_keys_from_every_data_field_count(tmp_path):
    details = {f.detail for f in key_findings(tmp_path)}
    # binaryData, data and stringData keys all satisfy a reference, and the
    # token controller's keys satisfy a service-account token Secret.
    for key in ("DB_PORT", "logo.png", "username", "password", "token"):
        assert not any(repr(key) in d for d in details), key


def test_missing_object_is_not_also_a_missing_key(tmp_path):
    (tmp_path / "a.yaml").write_text(KEYS_NS)
    result = audit(load_manifests(str(tmp_path)))
    deleted = [f.finding for f in result.findings if f.name == "deleted"]
    assert deleted == ["dangling-configmap-ref"]


def test_key_findings_honour_ignore_and_skip_kinds(tmp_path):
    assert key_findings(tmp_path, ignore=["app", "creds"]) == []
    assert {f.kind for f in key_findings(tmp_path, skip_kinds=["ConfigMap"])} == {"Secret"}


def test_secret_values_are_never_reported(tmp_path):
    (tmp_path / "a.yaml").write_text(KEYS_NS)
    from k8s_configmap_orphan_finder.report import render_json, render_table

    result = audit(load_manifests(str(tmp_path)))
    for rendered in (render_json(result), render_table(result)):
        assert "hunter2" not in rendered
        assert "YWRtaW4=" not in rendered
        assert "api_key" in rendered
