"""Core data types shared by the loader, the reference walker and the audit."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

#: Secret/ConfigMap kinds this tool audits.
TARGET_KINDS = ("ConfigMap", "Secret")

#: Severity names, most to least urgent. Used for sorting and for --min-severity.
SEVERITIES = ("high", "medium", "low")

SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}


class LoadError(Exception):
    """Raised when inventory cannot be read (bad YAML, unreachable cluster, ...)."""


@dataclass(frozen=True)
class ObjectRef:
    """A namespaced reference to a ConfigMap or a Secret."""

    namespace: str
    kind: str
    name: str

    def __str__(self) -> str:  # pragma: no cover - debugging aid
        return f"{self.namespace}/{self.kind}/{self.name}"


@dataclass(frozen=True)
class Reference:
    """One place that names a ConfigMap or a Secret."""

    target: ObjectRef
    #: Human-readable owner, e.g. ``Deployment/api``.
    referrer: str
    #: Pod-spec path the name was read from, e.g. ``volumes[].projected.secret``.
    field: str
    #: ``optional: true`` references do not block a pod from starting.
    optional: bool = False

    def describe(self) -> str:
        return f"{self.referrer} ({self.field})"


@dataclass
class Resource:
    """A single Kubernetes object as loaded from YAML or from the API."""

    kind: str
    name: str
    namespace: str
    body: Dict[str, Any]
    #: Where it came from, used in load-error messages.
    source: str = "<api>"

    @property
    def ref(self) -> ObjectRef:
        return ObjectRef(self.namespace, self.kind, self.name)

    def describe(self) -> str:
        return f"{self.kind}/{self.name}"


@dataclass
class Inventory:
    """Everything the audit needs: the objects and where they came from."""

    resources: List[Resource] = field(default_factory=list)

    def add(self, resource: Resource) -> None:
        self.resources.append(resource)

    def by_kind(self, *kinds: str) -> List[Resource]:
        wanted = set(kinds)
        return [r for r in self.resources if r.kind in wanted]

    def namespaces(self) -> List[str]:
        return sorted({r.namespace for r in self.resources})


@dataclass
class Finding:
    """One problem worth a human's attention."""

    severity: str
    kind: str
    namespace: str
    name: str
    #: Stable machine-readable id, e.g. ``orphan-secret``.
    finding: str
    detail: str
    referrers: List[str] = field(default_factory=list)

    def sort_key(self) -> Tuple[int, str, str, str, str]:
        return (
            SEVERITY_RANK.get(self.severity, len(SEVERITIES)),
            self.namespace,
            self.kind,
            self.name,
            self.finding,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity,
            "kind": self.kind,
            "namespace": self.namespace,
            "name": self.name,
            "finding": self.finding,
            "detail": self.detail,
            "referrers": list(self.referrers),
        }
