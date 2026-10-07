# k8s-configmap-orphan-finder

[![ci](https://github.com/moveeeax/k8s-configmap-orphan-finder/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/k8s-configmap-orphan-finder/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.9%2B-3776ab)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Deleting a workload rarely deletes its config. This walks every pod template in a namespace, builds the set of ConfigMaps and Secrets that are *actually* referenced, and tells you which objects are dead weight — plus the opposite failure, references that point at objects which no longer exist.

```
$ k8s-configmap-orphan-finder --manifests examples/k8s
Scanned 3 ConfigMaps, 5 Secrets and 4 referencing objects in payments.

SEVERITY  KIND       NAMESPACE  NAME                   FINDING                 DETAIL
high      ConfigMap  payments   acme-ca-bundle         dangling-configmap-ref  referenced but not found in scope
high      Secret     payments   stripe-old             orphan-secret           type Opaque, referenced by nothing in scope
medium    ConfigMap  payments   legacy-checkout-nginx  orphan-configmap        referenced by nothing in scope

3 finding(s): high=2 medium=1
```

## Install

```sh
pip install git+https://github.com/moveeeax/k8s-configmap-orphan-finder
# live cluster mode also needs the Kubernetes client:
pip install 'k8s-configmap-orphan-finder[live] @ git+https://github.com/moveeeax/k8s-configmap-orphan-finder'
```

Manifest mode needs only `PyYAML`, so it runs in CI without cluster credentials.

## How it works

A pod spec can name a ConfigMap or a Secret from at least six unrelated fields. Miss one and a cleanup tool becomes a way to break production, so the reference walker reads all of them:

| Where | ConfigMap | Secret |
| --- | --- | --- |
| `volumes` | `configMap.name` | `secret.secretName` |
| `volumes[].projected.sources` | `configMap.name` | `secret.name` |
| `volumes[].csi` | — | `nodePublishSecretRef.name` |
| in-tree volume plugins (`cephfs`, `rbd`, `iscsi`, `azureFile`, …) | — | `secretRef.name`, `secretName` |
| `env[].valueFrom` | `configMapKeyRef` | `secretKeyRef` |
| `envFrom[]` | `configMapRef` | `secretRef` |
| pod spec | — | `imagePullSecrets[].name` |

Containers, `initContainers` and `ephemeralContainers` are all walked, and the template is found for `Pod`, `Deployment`, `StatefulSet`, `DaemonSet`, `ReplicaSet`, `ReplicationController`, `Job` and `CronJob`.

Three more reference sources exist outside pod specs, and they are the ones that cause false positives when a tool ignores them:

- **`ServiceAccount`** — its `secrets` and `imagePullSecrets`. A pod that sets `serviceAccountName` inherits them, and the report says so (`Deployment/api via ServiceAccount/api`).
- **`Ingress`** — `spec.tls[].secretName`, plus the nginx annotations `auth-secret`, `auth-tls-secret` and `proxy-ssl-secret`. Those accept a `namespace/name` form and it is honoured.
- **Reloader annotations** — `configmap.reloader.stakater.com/reload` and `secret.reloader.stakater.com/reload`, read from the workload *and* from its pod template.

Objects the cluster or a controller owns are never reported: `kube-root-ca.crt`, `openshift-service-ca.crt`, `istio-ca-root-cert`, and Secrets typed `helm.sh/release.v1` or `bootstrap.kubernetes.io/token`.

### Findings

| `finding` | Severity | Meaning |
| --- | --- | --- |
| `orphan-secret` | high | A Secret nothing references. A live credential nobody remembers creating. |
| `dangling-secret-ref` / `dangling-configmap-ref` | high | Something names an object that is not there. Pods will not start. `optional: true` drops it to low. |
| `orphan-configmap` | medium | A ConfigMap nothing references. Review noise. |
| `orphan-serviceaccount-token` | medium / low | A legacy `kubernetes.io/service-account-token` Secret no pod mounts. Medium when its ServiceAccount is also gone. |

## Usage

```
k8s-configmap-orphan-finder (-n NS | -A | -m DIR) [options]

  -n, --namespace NS        audit this namespace in the live cluster
  -A, --all-namespaces      audit every namespace in the live cluster
  -m, --manifests DIR       audit a directory of YAML manifests instead
      --default-namespace   namespace assumed for manifests without one (default: default)
      --ignore GLOB         skip objects by name glob; repeatable or comma-separated
      --skip-kinds KIND     exclude a kind from the audit, e.g. Secret or CronJob
      --min-severity LEVEL  high | medium | low (default: low)
      --json                emit JSON instead of a table
```

Audit a live namespace:

```sh
k8s-configmap-orphan-finder --namespace prod
```

Filter the JSON with `jq`:

```sh
k8s-configmap-orphan-finder --manifests ./k8s --json | jq '.findings[] | select(.kind=="Secret")'
```

Gate a pipeline on the problems that actually break things, and let untidy ConfigMaps pass:

```sh
k8s-configmap-orphan-finder --manifests ./k8s --min-severity high --ignore 'debug-*'
```

Exit codes: `0` nothing to clean up, `1` at least one finding, `2` the inventory could not be read.

## One thing to know about manifest mode

Scope is honest, not clairvoyant. In `--manifests` mode the tool only knows about the files you point it at, so a ConfigMap that lives in another repo shows up as `dangling-configmap-ref`, and a ConfigMap referenced only from a Helm chart you did not render looks orphaned. Point it at a rendered tree (`helm template`, `kustomize build`) or at the live namespace when you want the full picture, and use `--ignore` for the objects that genuinely come from elsewhere.

Namespaces are kept separate throughout: a reference in `two` never satisfies an object in `one`.

## Development

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest
```

Tests run against the fixture manifests in `tests/fixtures/`, offline, with no cluster.

## License

MIT — see [LICENSE](LICENSE).
