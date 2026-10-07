"""Turn an inventory into findings."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Sequence, Set

from .model import Finding, Inventory, ObjectRef, Reference, Resource
from .refs import REF_KINDS, references_of, service_account_of

SA_TOKEN_TYPE = "kubernetes.io/service-account-token"

#: Objects the control plane creates and owns. Reporting them is always wrong.
CLUSTER_OWNED_NAMES = frozenset(
    (
        "kube-root-ca.crt",
        "openshift-service-ca.crt",
        "istio-ca-root-cert",
    )
)

#: Secret types owned by a controller that keeps its own state in them.
CONTROLLER_OWNED_TYPES = frozenset(
    (
        "helm.sh/release.v1",
        "bootstrap.kubernetes.io/token",
    )
)


@dataclass
class Options:
    ignore: Sequence[str] = ()
    skip_kinds: Sequence[str] = ()
    min_severity: str = "low"


@dataclass
class AuditResult:
    findings: List[Finding] = field(default_factory=list)
    configmaps: int = 0
    secrets: int = 0
    referrers: int = 0
    namespaces: List[str] = field(default_factory=list)


def _ignored(name: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(name, pattern) for pattern in patterns)


def _secret_type(resource: Resource) -> str:
    value = resource.body.get("type")
    return value if isinstance(value, str) else ""


def _sa_owner(resource: Resource) -> str:
    annotations = (resource.body.get("metadata") or {}).get("annotations")
    if isinstance(annotations, dict):
        owner = annotations.get("kubernetes.io/service-account.name")
        if isinstance(owner, str):
            return owner
    return ""


def collect_references(inventory: Inventory, skip_kinds: Iterable[str] = ()) -> Dict[ObjectRef, List[Reference]]:
    """Map every referenced ConfigMap/Secret to the places that name it."""
    skipped = {k.lower() for k in skip_kinds}
    service_accounts = {
        (r.namespace, r.name): r for r in inventory.by_kind("ServiceAccount")
    }
    index: Dict[ObjectRef, List[Reference]] = {}
    seen: Set[tuple] = set()

    def record(reference: Reference) -> None:
        key = (reference.target, reference.referrer, reference.field)
        if key in seen:
            return
        seen.add(key)
        index.setdefault(reference.target, []).append(reference)

    for resource in inventory.by_kind(*REF_KINDS):
        if resource.kind.lower() in skipped:
            continue
        for reference in references_of(resource):
            record(reference)
        # A pod that runs as a ServiceAccount inherits that account's secrets,
        # so those secrets are in use even if the SA object itself is not.
        sa_name = service_account_of(resource)
        if sa_name:
            sa = service_accounts.get((resource.namespace, sa_name))
            if sa is not None:
                for reference in references_of(sa):
                    record(
                        Reference(
                            target=reference.target,
                            referrer=f"{resource.describe()} via ServiceAccount/{sa_name}",
                            field=reference.field,
                            optional=reference.optional,
                        )
                    )
    return index


def audit(inventory: Inventory, options: Options = Options()) -> AuditResult:
    """Compare declared ConfigMaps/Secrets against everything that names one."""
    skipped = {k.lower() for k in options.skip_kinds}
    references = collect_references(inventory, options.skip_kinds)

    targets: Dict[ObjectRef, Resource] = {}
    for resource in inventory.by_kind("ConfigMap", "Secret"):
        targets[resource.ref] = resource

    result = AuditResult(
        configmaps=sum(1 for r in targets.values() if r.kind == "ConfigMap"),
        secrets=sum(1 for r in targets.values() if r.kind == "Secret"),
        referrers=len(inventory.by_kind(*REF_KINDS)),
        namespaces=inventory.namespaces(),
    )
    findings: List[Finding] = []

    service_account_names = {
        (r.namespace, r.name) for r in inventory.by_kind("ServiceAccount")
    }

    # 1. Objects nobody references.
    for ref, resource in targets.items():
        if resource.kind.lower() in skipped:
            continue
        if ref in references:
            continue
        if resource.name in CLUSTER_OWNED_NAMES:
            continue
        if _ignored(resource.name, options.ignore):
            continue
        if resource.kind == "Secret":
            secret_type = _secret_type(resource)
            if secret_type in CONTROLLER_OWNED_TYPES:
                continue
            if secret_type == SA_TOKEN_TYPE:
                owner = _sa_owner(resource)
                owner_exists = bool(owner) and (resource.namespace, owner) in service_account_names
                findings.append(
                    Finding(
                        severity="medium" if owner and not owner_exists else "low",
                        kind="Secret",
                        namespace=resource.namespace,
                        name=resource.name,
                        finding="orphan-serviceaccount-token",
                        detail=(
                            f"service-account token for missing ServiceAccount/{owner}"
                            if owner and not owner_exists
                            else "legacy service-account token, not mounted by any pod"
                        ),
                    )
                )
                continue
        if resource.kind == "Secret":
            findings.append(
                Finding(
                    severity="high",
                    kind="Secret",
                    namespace=resource.namespace,
                    name=resource.name,
                    finding="orphan-secret",
                    detail=f"type {_secret_type(resource) or 'Opaque'}, referenced by nothing in scope",
                )
            )
        else:
            findings.append(
                Finding(
                    severity="medium",
                    kind="ConfigMap",
                    namespace=resource.namespace,
                    name=resource.name,
                    finding="orphan-configmap",
                    detail="referenced by nothing in scope",
                )
            )

    # 2. References pointing at objects that do not exist. This is the opposite
    #    failure and it is the one that actually breaks pods.
    for ref, referring in sorted(references.items(), key=lambda kv: str(kv[0])):
        if ref in targets or ref.kind.lower() in skipped:
            continue
        if _ignored(ref.name, options.ignore):
            continue
        if ref.name in CLUSTER_OWNED_NAMES:
            continue
        required = [r for r in referring if not r.optional]
        findings.append(
            Finding(
                severity="high" if required else "low",
                kind=ref.kind,
                namespace=ref.namespace,
                name=ref.name,
                finding="dangling-configmap-ref" if ref.kind == "ConfigMap" else "dangling-secret-ref",
                detail=(
                    "referenced but not found in scope"
                    if required
                    else "referenced but not found in scope (optional: true)"
                ),
                referrers=[r.describe() for r in referring],
            )
        )

    floor = {"high": 0, "medium": 1, "low": 2}.get(options.min_severity, 2)
    findings = [f for f in findings if {"high": 0, "medium": 1, "low": 2}[f.severity] <= floor]
    findings.sort(key=Finding.sort_key)
    result.findings = findings
    return result
