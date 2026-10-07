from __future__ import annotations

import yaml

from k8s_configmap_orphan_finder.model import Resource
from k8s_configmap_orphan_finder.refs import (
    POD_SPEC_PATHS,
    pod_spec_of,
    references_of,
    service_account_of,
)


def res(text: str, namespace: str = "shop") -> Resource:
    body = yaml.safe_load(text)
    meta = body.get("metadata") or {}
    return Resource(
        kind=body["kind"],
        name=meta.get("name", "unnamed"),
        namespace=meta.get("namespace") or namespace,
        body=body,
    )


def targets(resource: Resource):
    return {(r.target.kind, r.target.name) for r in references_of(resource)}


DEPLOY = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      serviceAccountName: api
      imagePullSecrets:
        - name: pull-creds
      initContainers:
        - name: init
          envFrom:
            - configMapRef:
                name: init-config
      containers:
        - name: app
          env:
            - name: A
              valueFrom:
                configMapKeyRef:
                  name: env-config
                  key: a
            - name: B
              valueFrom:
                secretKeyRef:
                  name: env-secret
                  key: b
          envFrom:
            - secretRef:
                name: bulk-secret
      volumes:
        - name: v1
          configMap:
            name: vol-config
        - name: v2
          secret:
            secretName: vol-secret
        - name: v3
          projected:
            sources:
              - configMap:
                  name: proj-config
              - secret:
                  name: proj-secret
        - name: v4
          csi:
            driver: secrets-store.csi.k8s.io
            nodePublishSecretRef:
              name: csi-creds
        - name: v5
          cephfs:
            monitors: ["1.2.3.4"]
            secretRef:
              name: ceph-creds
        - name: v6
          azureFile:
            shareName: share
            secretName: azure-creds
"""


def test_collects_every_pod_spec_reference_site():
    found = targets(res(DEPLOY))
    assert ("ConfigMap", "init-config") in found
    assert ("ConfigMap", "env-config") in found
    assert ("ConfigMap", "vol-config") in found
    assert ("ConfigMap", "proj-config") in found
    assert ("Secret", "env-secret") in found
    assert ("Secret", "bulk-secret") in found
    assert ("Secret", "vol-secret") in found
    assert ("Secret", "proj-secret") in found
    assert ("Secret", "pull-creds") in found


def test_collects_in_tree_volume_plugin_credentials():
    found = targets(res(DEPLOY))
    assert ("Secret", "csi-creds") in found
    assert ("Secret", "ceph-creds") in found
    assert ("Secret", "azure-creds") in found


def test_service_account_name_is_reported():
    assert service_account_of(res(DEPLOY)) == "api"


def test_optional_flag_survives_collection():
    resource = res(
        """
apiVersion: v1
kind: Pod
metadata:
  name: p
spec:
  containers:
    - name: c
      env:
        - name: T
          valueFrom:
            secretKeyRef:
              name: maybe
              key: t
              optional: true
"""
    )
    refs = references_of(resource)
    assert [(r.target.name, r.optional) for r in refs] == [("maybe", True)]


def test_cronjob_template_is_reached():
    resource = res(
        """
apiVersion: batch/v1
kind: CronJob
metadata:
  name: job
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: c
              envFrom:
                - configMapRef:
                    name: job-config
"""
    )
    assert pod_spec_of(resource) is not None
    assert targets(resource) == {("ConfigMap", "job-config")}


def test_every_workload_kind_has_a_resolvable_spec_path():
    for kind, path in POD_SPEC_PATHS.items():
        assert path and all(isinstance(part, str) for part in path), kind


def test_ingress_tls_and_auth_annotation():
    resource = res(
        """
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  annotations:
    nginx.ingress.kubernetes.io/auth-tls-secret: other-ns/client-ca
spec:
  tls:
    - secretName: web-tls
"""
    )
    refs = references_of(resource)
    by_name = {r.target.name: r.target.namespace for r in refs}
    assert by_name["web-tls"] == "shop"
    # nginx accepts namespace/name in its annotations; the reference belongs to
    # the namespace named there, not to the Ingress's own namespace.
    assert by_name["client-ca"] == "other-ns"


def test_reloader_annotation_on_pod_template():
    resource = res(
        """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    metadata:
      annotations:
        configmap.reloader.stakater.com/reload: a-config, b-config
        secret.reloader.stakater.com/reload: a-secret
    spec:
      containers:
        - name: c
"""
    )
    assert targets(resource) == {
        ("ConfigMap", "a-config"),
        ("ConfigMap", "b-config"),
        ("Secret", "a-secret"),
    }


def test_unknown_kind_yields_nothing():
    assert references_of(res("apiVersion: v1\nkind: Service\nmetadata:\n  name: svc\n")) == []


def test_malformed_spec_does_not_explode():
    resource = Resource(kind="Deployment", name="x", namespace="shop", body={"spec": None})
    assert references_of(resource) == []
