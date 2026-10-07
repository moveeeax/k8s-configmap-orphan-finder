"""Collect every ConfigMap/Secret reference a Kubernetes object can carry.

The whole value of this tool lives in this module: a pod spec can name a
ConfigMap or a Secret from at least six unrelated fields, and missing one of
them turns a cleanup tool into a way to break production.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from .model import ObjectRef, Reference, Resource

#: Kinds that carry a pod template, mapped to the path of that template's spec.
POD_SPEC_PATHS: Dict[str, tuple] = {
    "Pod": ("spec",),
    "Deployment": ("spec", "template", "spec"),
    "StatefulSet": ("spec", "template", "spec"),
    "DaemonSet": ("spec", "template", "spec"),
    "ReplicaSet": ("spec", "template", "spec"),
    "ReplicationController": ("spec", "template", "spec"),
    "Job": ("spec", "template", "spec"),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
}

WORKLOAD_KINDS = tuple(POD_SPEC_PATHS)

#: Other kinds that legitimately pin a Secret or a ConfigMap.
EXTRA_REF_KINDS = ("ServiceAccount", "Ingress")

REF_KINDS = WORKLOAD_KINDS + EXTRA_REF_KINDS

#: Annotations used by common controllers to point at config objects. Without
#: these, nginx auth secrets and Reloader-tracked ConfigMaps look orphaned.
ANNOTATION_REFS: Dict[str, str] = {
    "nginx.ingress.kubernetes.io/auth-secret": "Secret",
    "nginx.ingress.kubernetes.io/auth-tls-secret": "Secret",
    "nginx.ingress.kubernetes.io/proxy-ssl-secret": "Secret",
    "configmap.reloader.stakater.com/reload": "ConfigMap",
    "secret.reloader.stakater.com/reload": "Secret",
    "reloader.stakater.com/search": "",
}


def _dig(body: Dict[str, Any], path: Iterable[str]) -> Optional[Dict[str, Any]]:
    node: Any = body
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node if isinstance(node, dict) else None


def pod_spec_of(resource: Resource) -> Optional[Dict[str, Any]]:
    """Return the pod spec of a workload, or ``None`` if it has no template."""
    path = POD_SPEC_PATHS.get(resource.kind)
    if path is None:
        return None
    return _dig(resource.body, path)


class _Collector:
    def __init__(self, namespace: str, referrer: str) -> None:
        self.namespace = namespace
        self.referrer = referrer
        self.out: List[Reference] = []

    def add(self, kind: str, name: Any, field: str, optional: Any = False) -> None:
        if not isinstance(name, str) or not name:
            return
        namespace = self.namespace
        # nginx accepts "namespace/name" in its auth-secret annotations.
        if "/" in name and field.startswith("metadata.annotations"):
            head, _, tail = name.partition("/")
            if head and tail:
                namespace, name = head, tail
        self.out.append(
            Reference(
                target=ObjectRef(namespace, kind, name),
                referrer=self.referrer,
                field=field,
                optional=bool(optional),
            )
        )


def _collect_container(container: Dict[str, Any], prefix: str, c: _Collector) -> None:
    if not isinstance(container, dict):
        return
    for entry in container.get("env") or []:
        if not isinstance(entry, dict):
            continue
        value_from = entry.get("valueFrom")
        if not isinstance(value_from, dict):
            continue
        cm = value_from.get("configMapKeyRef")
        if isinstance(cm, dict):
            c.add("ConfigMap", cm.get("name"), f"{prefix}.env.configMapKeyRef", cm.get("optional"))
        secret = value_from.get("secretKeyRef")
        if isinstance(secret, dict):
            c.add("Secret", secret.get("name"), f"{prefix}.env.secretKeyRef", secret.get("optional"))
    for entry in container.get("envFrom") or []:
        if not isinstance(entry, dict):
            continue
        cm = entry.get("configMapRef")
        if isinstance(cm, dict):
            c.add("ConfigMap", cm.get("name"), f"{prefix}.envFrom.configMapRef", cm.get("optional"))
        secret = entry.get("secretRef")
        if isinstance(secret, dict):
            c.add("Secret", secret.get("name"), f"{prefix}.envFrom.secretRef", secret.get("optional"))


def _collect_volume(volume: Dict[str, Any], c: _Collector) -> None:
    if not isinstance(volume, dict):
        return
    cm = volume.get("configMap")
    if isinstance(cm, dict):
        c.add("ConfigMap", cm.get("name"), "volumes.configMap", cm.get("optional"))
    secret = volume.get("secret")
    if isinstance(secret, dict):
        c.add("Secret", secret.get("secretName"), "volumes.secret", secret.get("optional"))
    projected = volume.get("projected")
    if isinstance(projected, dict):
        for source in projected.get("sources") or []:
            if not isinstance(source, dict):
                continue
            pcm = source.get("configMap")
            if isinstance(pcm, dict):
                c.add(
                    "ConfigMap",
                    pcm.get("name"),
                    "volumes.projected.configMap",
                    pcm.get("optional"),
                )
            psecret = source.get("secret")
            if isinstance(psecret, dict):
                c.add(
                    "Secret",
                    psecret.get("name"),
                    "volumes.projected.secret",
                    psecret.get("optional"),
                )
    csi = volume.get("csi")
    if isinstance(csi, dict):
        node_publish = csi.get("nodePublishSecretRef")
        if isinstance(node_publish, dict):
            c.add("Secret", node_publish.get("name"), "volumes.csi.nodePublishSecretRef")
    # In-tree volume plugins (rbd, cephfs, iscsi, azureFile, storageos, flexVolume)
    # all spell their credential as secretRef.name or secretName. Sweeping the
    # volume sources generically means a new plugin does not become a false
    # positive the day somebody uses it.
    for key, source in volume.items():
        if key in ("configMap", "secret", "projected", "csi") or not isinstance(source, dict):
            continue
        ref = source.get("secretRef")
        if isinstance(ref, dict):
            c.add("Secret", ref.get("name"), f"volumes.{key}.secretRef")
        c.add("Secret", source.get("secretName"), f"volumes.{key}.secretName")


def _collect_annotations(metadata: Dict[str, Any], c: _Collector) -> None:
    annotations = metadata.get("annotations") if isinstance(metadata, dict) else None
    if not isinstance(annotations, dict):
        return
    for key, kind in ANNOTATION_REFS.items():
        raw = annotations.get(key)
        if not isinstance(raw, str) or not kind:
            continue
        for name in raw.split(","):
            c.add(kind, name.strip(), f"metadata.annotations[{key}]")


def collect_pod_spec_refs(spec: Dict[str, Any], c: _Collector) -> None:
    if not isinstance(spec, dict):
        return
    for group in ("initContainers", "containers", "ephemeralContainers"):
        for container in spec.get(group) or []:
            _collect_container(container, group, c)
    for volume in spec.get("volumes") or []:
        _collect_volume(volume, c)
    for entry in spec.get("imagePullSecrets") or []:
        if isinstance(entry, dict):
            c.add("Secret", entry.get("name"), "imagePullSecrets")


def service_account_of(resource: Resource) -> Optional[str]:
    """Name of the ServiceAccount a workload runs as, if it pins one."""
    spec = pod_spec_of(resource)
    if not isinstance(spec, dict):
        return None
    name = spec.get("serviceAccountName") or spec.get("serviceAccount")
    return name if isinstance(name, str) and name else None


def references_of(resource: Resource) -> List[Reference]:
    """Every ConfigMap/Secret reference carried by a single object."""
    c = _Collector(resource.namespace, resource.describe())
    body = resource.body
    metadata = body.get("metadata") if isinstance(body, dict) else None

    spec = pod_spec_of(resource)
    if spec is not None:
        collect_pod_spec_refs(spec, c)
        # Pod-template annotations matter too: Reloader is usually annotated on
        # the Deployment's template, not on the Deployment itself.
        template = _dig(body, POD_SPEC_PATHS[resource.kind][:-1]) or {}
        _collect_annotations(template.get("metadata") or {}, c)

    if resource.kind == "ServiceAccount":
        for entry in body.get("secrets") or []:
            if isinstance(entry, dict):
                c.add("Secret", entry.get("name"), "serviceAccount.secrets")
        for entry in body.get("imagePullSecrets") or []:
            if isinstance(entry, dict):
                c.add("Secret", entry.get("name"), "serviceAccount.imagePullSecrets")

    if resource.kind == "Ingress":
        tls = (body.get("spec") or {}).get("tls") if isinstance(body.get("spec"), dict) else None
        for entry in tls or []:
            if isinstance(entry, dict):
                c.add("Secret", entry.get("secretName"), "ingress.tls.secretName")

    _collect_annotations(metadata or {}, c)
    return c.out
