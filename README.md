# @tailsec/scan-k8s

Security scanner for Kubernetes manifests. Detects insecure configurations including privileged containers, hostPath volumes, wildcards in RBAC, and more.

## Usage

```bash
npx @tailsec/scan-k8s ./manifests
npx @tailsec/scan-k8s ./manifests --format json
```

## Checks

- Privileged containers
- Host network/PID/IPC sharing
- hostPath volumes
- RBAC wildcards
- Container resource limits
- Image tag :latest
- And more...