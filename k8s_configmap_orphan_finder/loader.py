"""Build an :class:`Inventory` from a directory of manifests or a live cluster."""

from __future__ import annotations

import os
from typing import Any, Dict, Iterable, List, Optional

import yaml

from .model import Inventory, LoadError, Resource
from .refs import REF_KINDS

YAML_SUFFIXES = (".yaml", ".yml")

#: Only these kinds are worth loading; anything else is noise for this audit.
INTERESTING_KINDS = frozenset(("ConfigMap", "Secret") + REF_KINDS)


def _resource_from_doc(doc: Dict[str, Any], source: str, default_namespace: str) -> Optional[Resource]:
    if not isinstance(doc, dict):
        return None
    kind = doc.get("kind")
    metadata = doc.get("metadata")
    if not isinstance(kind, str) or not isinstance(metadata, dict):
        return None
    name = metadata.get("name")
    if not isinstance(name, str) or not name:
        return None
    namespace = metadata.get("namespace")
    if not isinstance(namespace, str) or not namespace:
        namespace = default_namespace
    return Resource(kind=kind, name=name, namespace=namespace, body=doc, source=source)


def _flatten(doc: Any) -> Iterable[Dict[str, Any]]:
    """Yield objects from a document, unwrapping ``kind: List`` wrappers."""
    if not isinstance(doc, dict):
        return
    if doc.get("kind") in ("List", "ConfigMapList", "SecretList"):
        for item in doc.get("items") or []:
            for nested in _flatten(item):
                yield nested
        return
    yield doc


def manifest_files(root: str) -> List[str]:
    if os.path.isfile(root):
        return [root]
    if not os.path.isdir(root):
        raise LoadError(f"{root}: no such file or directory")
    found: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
        for filename in sorted(filenames):
            if filename.endswith(YAML_SUFFIXES):
                found.append(os.path.join(dirpath, filename))
    return found


def load_manifests(root: str, default_namespace: str = "default") -> Inventory:
    """Load every ConfigMap, Secret and reference-carrying object under ``root``."""
    inventory = Inventory()
    files = manifest_files(root)
    if not files:
        raise LoadError(f"{root}: no .yaml or .yml manifests found")
    for path in files:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                docs = list(yaml.safe_load_all(handle))
        except yaml.YAMLError as exc:
            raise LoadError(f"{path}: invalid YAML: {exc}") from exc
        except OSError as exc:
            raise LoadError(f"{path}: {exc.strerror or exc}") from exc
        for doc in docs:
            for obj in _flatten(doc):
                resource = _resource_from_doc(obj, path, default_namespace)
                if resource is not None and resource.kind in INTERESTING_KINDS:
                    inventory.add(resource)
    return inventory


# --- live cluster -----------------------------------------------------------
# Imported lazily so the package (and its test suite) works with no kubernetes
# client installed and no kubeconfig on disk.

_LIVE_READERS = (
    ("ConfigMap", "CoreV1Api", "config_map"),
    ("Secret", "CoreV1Api", "secret"),
    ("ServiceAccount", "CoreV1Api", "service_account"),
    ("Pod", "CoreV1Api", "pod"),
    ("ReplicationController", "CoreV1Api", "replication_controller"),
    ("Deployment", "AppsV1Api", "deployment"),
    ("StatefulSet", "AppsV1Api", "stateful_set"),
    ("DaemonSet", "AppsV1Api", "daemon_set"),
    ("ReplicaSet", "AppsV1Api", "replica_set"),
    ("Job", "BatchV1Api", "job"),
    ("CronJob", "BatchV1Api", "cron_job"),
    ("Ingress", "NetworkingV1Api", "ingress"),
)


def load_cluster(namespace: Optional[str], all_namespaces: bool = False) -> Inventory:
    """Read the inventory from the cluster the current kubeconfig points at."""
    try:
        from kubernetes import client, config  # type: ignore
        from kubernetes.client.rest import ApiException  # type: ignore
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise LoadError(
            "live mode needs the kubernetes client: pip install 'k8s-configmap-orphan-finder[live]'"
        ) from exc

    try:
        config.load_kube_config()
    except Exception:  # pragma: no cover - in-cluster fallback
        try:
            config.load_incluster_config()
        except Exception as exc:
            raise LoadError(f"no usable Kubernetes credentials: {exc}") from exc

    if not all_namespaces and not namespace:
        raise LoadError("live mode needs --namespace or --all-namespaces")

    api_cache: Dict[str, Any] = {}
    inventory = Inventory()
    for kind, api_name, singular in _LIVE_READERS:
        api = api_cache.get(api_name)
        if api is None:
            api = api_cache[api_name] = getattr(client, api_name)()
        if all_namespaces:
            method = getattr(api, f"list_{singular}_for_all_namespaces", None)
            args: tuple = ()
        else:
            method = getattr(api, f"list_namespaced_{singular}", None)
            args = (namespace,)
        if method is None:  # pragma: no cover - client version drift
            continue
        try:
            listing = method(*args, _preload_content=False)
        except ApiException as exc:  # pragma: no cover - needs a cluster
            if exc.status in (403, 404):
                continue
            raise LoadError(f"listing {kind}: {exc.status} {exc.reason}") from exc
        import json as _json

        payload = _json.loads(listing.data)
        for item in payload.get("items") or []:
            item.setdefault("kind", kind)
            resource = _resource_from_doc(item, "<cluster>", namespace or "default")
            if resource is not None:
                inventory.add(resource)
    return inventory
