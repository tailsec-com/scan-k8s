# @tailsec/scan-k8s

Security scanner for Kubernetes manifests. Detects privileged containers, hostPath volumes, RBAC wildcards, insecure capabilities, and other misconfigurations in Kubernetes YAML.

[![npm](https://img.shields.io/npm/v/@tailsec/scan-k8s)](https://www.npmjs.com/package/@tailsec/scan-k8s)
[![CI](https://github.com/tailsec-com/scan-k8s/actions/workflows/ci.yml/badge.svg)](https://github.com/tailsec-com/scan-k8s)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

## Features

- Scans Kubernetes manifests (YAML) for security misconfigurations
- Supports Pod, Deployment, StatefulSet, DaemonSet, Job, CronJob, Role, ClusterRole, NetworkPolicy, Service
- Detects container-level and pod-level security issues
- JSON output for CI/CD integration
- No external dependencies — parses manifests statically

## Installation

```bash
npm install -g @tailsec/scan-k8s
```

## Usage

```bash
# Scan a directory of manifests
npx @tailsec/scan-k8s ./manifests

# Output as JSON (for CI/CD pipelines)
npx @tailsec/scan-k8s ./manifests --format json

# Scan specific files
npx @tailsec/scan-k8s deployment.yaml service.yaml
```

### Programmatic

```typescript
import { scanK8sManifest, formatK8sOutput } from '@tailsec/scan-k8s';

const findings = scanK8sManifest(yamlContent);
console.log(formatK8sOutput(findings, 'text'));
console.log(formatK8sOutput(findings, 'json'));
```

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `--format` | `text` | Output format: `text` or `json` |

## Supported Resources

| Kind | Scanned |
|------|---------|
| Pod | Yes |
| Deployment | Yes |
| StatefulSet | Yes |
| DaemonSet | Yes |
| Job | Yes |
| CronJob | Yes |
| Role | Yes |
| ClusterRole | Yes |
| NetworkPolicy | Yes |
| Service | Yes |

## Detection Rules

| Rule ID | Severity | Title |
|---------|----------|-------|
| k8s-privileged-container | Critical | Privileged container — can access host resources |
| k8s-allow-privilege-escalation | Critical | Allow privilege escalation enabled |
| k8s-default-allow-priv-esc | Critical | PodSecurityContext defaultAllowPrivilegeEscalation is true |
| k8s-host-path | Critical | hostPath volume mounts sensitive paths |
| k8s-host-devices | Critical | Pod has direct access to host devices |
| k8s-dangerous-capability | High | Dangerous capability added (SYS_ADMIN, NET_ADMIN, etc.) |
| k8s-host-network | High | Pod uses host network — can sniff cluster traffic |
| k8s-host-pid | High | Pod shares host PID namespace |
| k8s-host-ipc | High | Pod shares host IPC namespace |
| k8s-capabilities-drop-missing | High | Container does not drop ALL capabilities |
| k8s-run-as-non-root | High | Container may run as root |
| k8s-clusterrole-wildcard | High | ClusterRole grants wildcard verbs on all resources |
| k8s-no-resource-limits | Medium | No resource limits set on container |
| k8s-image-latest | Medium | Image uses :latest tag — non-reproducible |
| k8s-dns-host-network | Medium | Pod uses host network with ClusterFirst DNS |
| k8s-automount-sa-token | Medium | ServiceAccount token explicitly automounted |
| k8s-default-sa | Medium | Pod uses default service account |
| k8s-high-priority-class | Medium | Pod uses high priority class |
| k8s-service-loadbalancer | Medium | Service type LoadBalancer exposes cluster |
| k8s-netpol-empty-selector | Medium | NetworkPolicy with empty podSelector |
| k8s-read-only-fs | Low | Root filesystem is not read-only |
| k8s-image-unqualified | Low | Unqualified image reference |
| k8s-image-pull-always | Low | Image pull policy is Always |
| k8s-long-grace-period | Low | Termination grace period too long |
| k8s-service-nodeport | Low | Service type NodePort exposes on all nodes |
| k8s-role-pod-delete | Medium | Role can create and delete pods |

## Exit Codes

- `0` — Scan completed, no issues found
- `1` — Scan completed, issues found
- `2` — Scan failed (file errors, parse errors)

## Contributing

Rules are defined in `src/k8s.ts` as detection functions. To add a new rule:

1. Create a detection function in `src/k8s.ts`
2. Push a finding object with `ruleId`, `severity`, `title`, `resource`, `advice`
3. Rule IDs should follow the pattern: `k8s-<descriptive-name>` (e.g., `k8s-my-new-rule`)
4. Severity must be one of: `critical`, `high`, `medium`, `low`

Example rule structure:

```typescript
if (someCondition) {
  results.push({
    ruleId: 'k8s-my-new-rule',
    type: 'kubernetes',
    severity: 'high',
    title: 'Descriptive title of the issue',
    resource: `${doc.kind}: ${doc.metadata?.name || 'unknown'}`,
    namespace: doc.metadata?.namespace,
    advice: ['First remediation step', 'Second remediation step'],
  });
}
```

## License

MIT