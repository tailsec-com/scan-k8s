import { readFileSync } from 'fs';

function parseYaml(content: string): unknown[] {
  const docs: unknown[] = [];
  const rawDocs = content.split(/^---$/m);

  for (const raw of rawDocs) {
    const stripped = raw
      .split('\n')
      .filter(l => !l.trim().startsWith('#'))
      .join('\n')
      .trim();

    if (!stripped) continue;

    try {
      const obj = eval(`(${stripped.replace(/'/g, '"')})`);
      docs.push(obj);
    } catch {
      docs.push(parseYamlLines(stripped.split('\n')));
    }
  }

  return docs;
}

function parseYamlLines(lines: string[]): Record<string, unknown> {
  const root: Record<string, unknown> = {};
  const stack: Array<{ indent: number; obj: Record<string, unknown> }> = [{ indent: -1, obj: root }];

  for (const rawLine of lines) {
    const line = rawLine;
    if (!line.trim()) continue;

    const match = line.match(/^(\s*)(-?\s*)([^:]+):\s*(.*)$/);
    if (!match) continue;

    const [, indentStr, dash, key, value] = match;
    const indent = indentStr.length;
    const isListItem = dash.trim() === '-';

    while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
      stack.pop();
    }

    const parent = stack[stack.length - 1].obj;

    if (isListItem) {
      if (!parent[key.trim()]) parent[key.trim()] = [];
      const arr = parent[key.trim()] as unknown[];
      const item: Record<string, unknown> = {};
      arr.push(item);
      stack.push({ indent, obj: item });

      if (value.trim()) {
        const num = Number(value.trim());
        item[key.trim()] = value.trim() === 'true' ? true : value.trim() === 'false' ? false : isNaN(num) ? value.trim().replace(/^["']|["']$/g, '') : num;
      }
    } else {
      if (value.trim() === '' || value.trim() === '|' || value.trim() === '>-') {
        parent[key.trim()] = {};
        stack.push({ indent, obj: parent[key.trim()] as Record<string, unknown> });
      } else if (value.trim().startsWith('[') && value.trim().endsWith(']')) {
        parent[key.trim()] = value.trim().slice(1, -1).split(',').map(v => v.trim().replace(/^["']|["']$/g, ''));
      } else if (value.trim().startsWith('{') && value.trim().endsWith('}')) {
        try {
          parent[key.trim()] = JSON.parse(value.trim());
        } catch {
          parent[key.trim()] = value.trim().replace(/^["']|["']$/g, '');
        }
      } else {
        const num = Number(value.trim());
        parent[key.trim()] = value.trim() === 'true' ? true : value.trim() === 'false' ? false : isNaN(num) ? value.trim().replace(/^["']|["']$/g, '') : num;
      }
    }
  }

  return root;
}

function normalizeValue(val: unknown): Array<Record<string, unknown>> {
  if (Array.isArray(val)) return val as Array<Record<string, unknown>>;
  if (typeof val === 'object' && val !== null && !Array.isArray(val)) {
    const keys = Object.keys(val as Record<string, unknown>);
    const firstVal = (val as Record<string, unknown>)[keys[0]];
    if (Array.isArray(firstVal)) return firstVal as Array<Record<string, unknown>>;
    return [val as Record<string, unknown>];
  }
  return [];
}

export interface K8sFinding {
  ruleId: string;
  type: string;
  severity: string;
  title: string;
  resource: string;
  namespace?: string;
  line?: number;
  advice: string[];
}

interface K8sDoc {
  apiVersion?: string;
  kind?: string;
  metadata?: { name?: string; namespace?: string; labels?: Record<string, string> };
  spec?: Record<string, unknown>;
  [key: string]: unknown;
}

function checkContainer(container: Record<string, unknown>, doc: K8sDoc, results: K8sFinding[], yamlLine?: number) {
  const securityContext = container.securityContext as Record<string, unknown> || {};
  const podSec = doc.spec?.securityContext as Record<string, unknown> || {};

  if (securityContext.privileged === true) {
    results.push({
      ruleId: 'k8s-privileged-container',
      type: 'kubernetes',
      severity: 'critical',
      title: 'Privileged container — can access host resources',
      resource: `${doc.kind}: ${doc.metadata?.name || 'unknown'}`,
      namespace: doc.metadata?.namespace,
      advice: ['Remove privileged: true', 'Use securityContext.capabilities to add only required capabilities'],
    });
  }

  if (securityContext.allowPrivilegeEscalation === true || securityContext.allowPrivilegeEscalation === undefined && podSec.allowPrivilegeEscalation !== false) {
    results.push({
      ruleId: 'k8s-allow-privilege-escalation',
      type: 'kubernetes',
      severity: 'critical',
      title: 'Allow privilege escalation enabled',
      resource: `${doc.kind}: ${doc.metadata?.name || 'unknown'}`,
      namespace: doc.metadata?.namespace,
      advice: ['Set allowPrivilegeEscalation: false', 'This is default in PSP but not in all contexts'],
    });
  }

  if (!securityContext.runAsNonRoot && !podSec.runAsNonRoot) {
    results.push({
      ruleId: 'k8s-run-as-non-root',
      type: 'kubernetes',
      severity: 'high',
      title: 'Container may run as root — no runAsNonRoot set',
      resource: `${doc.kind}: ${doc.metadata?.name || 'unknown'}`,
      namespace: doc.metadata?.namespace,
      advice: ['Set securityContext.runAsNonRoot: true', 'Ensure base image has a non-root user'],
    });
  }

  if (!securityContext.readOnlyRootFilesystem && !container.readOnlyRootFilesystem) {
    results.push({
      ruleId: 'k8s-read-only-fs',
      type: 'kubernetes',
      severity: 'low',
      title: 'Root filesystem is not read-only',
      resource: `${doc.kind}: ${doc.metadata?.name || 'unknown'}`,
      namespace: doc.metadata?.namespace,
      advice: ['Set readOnlyRootFilesystem: true if application allows', 'Prevents writing to filesystem'],
    });
  }

  const caps = securityContext.capabilities as Record<string, unknown>;
  if (caps?.add) {
    const dangerous = ['SYS_ADMIN', 'NET_ADMIN', 'SYS_MODULE', 'DAC_READ_SEARCH', 'DAC_OVERRIDE', 'FOWNER', 'FSETID', 'KILL', 'SETGID', 'SETUID', 'SETFCAP', 'LINUX_IMMUTABLE', 'NET_BROADCAST', 'IPC_LOCK', 'IPC_OWNER', 'SYS_MODULE', 'SYS_RAWIO', 'SYS_PTRACE', 'SYS_TIME', 'SYS_CHROOT', 'AUDIT_WRITE', 'CHOWN', 'NET_RAW', 'NET_BIND_SERVICE', 'SYS_BOOT'];
    const added = caps.add as string[];
    for (const cap of added) {
      if (dangerous.includes(cap.toUpperCase())) {
        results.push({
          ruleId: 'k8s-dangerous-capability',
          type: 'kubernetes',
          severity: 'high',
          title: `Dangerous capability added: ${cap}`,
          resource: `${doc.kind}: ${doc.metadata?.name || 'unknown'}`,
          namespace: doc.metadata?.namespace,
          advice: [`Remove capability ${cap}`, 'Use least-privilege principle for capabilities'],
        });
      }
    }
  }

  const resources = container.resources as Record<string, unknown>;
  if (resources && !resources.limits) {
    results.push({
      ruleId: 'k8s-no-resource-limits',
      type: 'kubernetes',
      severity: 'medium',
      title: 'No resource limits set on container',
      resource: `${doc.kind}: ${doc.metadata?.name || 'unknown'}`,
      namespace: doc.metadata?.namespace,
      advice: ['Set resources.limits.cpu and resources.limits.memory', 'Prevents resource exhaustion attacks'],
    });
  }

  const image = container.image as string;
  if (image && (image.includes(':latest') || image.includes(':latest'))) {
    results.push({
      ruleId: 'k8s-image-latest',
      type: 'kubernetes',
      severity: 'medium',
      title: 'Image uses :latest tag — non-reproducible',
      resource: `${doc.kind}: ${doc.metadata?.name || 'unknown'}`,
      namespace: doc.metadata?.namespace,
      advice: ['Pin to specific version or SHA', 'Use :latest makes updates unpredictable'],
    });
  }

  if (image && !image.includes('/') && !image.includes(':')) {
    results.push({
      ruleId: 'k8s-image-unqualified',
      type: 'low',
      severity: 'low',
      title: 'Unqualified image reference — may resolve to unexpected registry',
      resource: `${doc.kind}: ${doc.metadata?.name || 'unknown'}`,
      namespace: doc.metadata?.namespace,
      advice: ['Use fully-qualified image name: registry.example.com/image:tag'],
    });
  }

  const imagePullPolicy = container.imagePullPolicy as string;
  if (!imagePullPolicy || imagePullPolicy === 'Always') {
    results.push({
      ruleId: 'k8s-image-pull-always',
      type: 'kubernetes',
      severity: 'low',
      title: 'Image pull policy is Always — increases latency and egress',
      resource: `${doc.kind}: ${doc.metadata?.name || 'unknown'}`,
      namespace: doc.metadata?.namespace,
      advice: ['Use IfNotPresent or Never to reduce unnecessary pulls'],
    });
  }
}

function checkPodSpec(doc: K8sDoc, results: K8sFinding[]) {
  const spec = doc.spec as Record<string, unknown> || {};
  const secCtx = spec.securityContext as Record<string, unknown> || {};

  if (spec.hostNetwork === true) {
    results.push({
      ruleId: 'k8s-host-network',
      type: 'kubernetes',
      severity: 'high',
      title: 'Pod uses host network — can sniff cluster traffic',
      resource: `Pod: ${doc.metadata?.name || 'unknown'}`,
      namespace: doc.metadata?.namespace,
      advice: ['Avoid hostNetwork unless absolutely necessary', 'Use Kubernetes network policies instead'],
    });
  }

  if (spec.hostPID === true) {
    results.push({
      ruleId: 'k8s-host-pid',
      type: 'kubernetes',
      severity: 'high',
      title: 'Pod shares host PID namespace — can see other processes',
      resource: `Pod: ${doc.metadata?.name || 'unknown'}`,
      namespace: doc.metadata?.namespace,
      advice: ['Avoid hostPID unless process monitoring is required'],
    });
  }

  if (spec.hostIPC === true) {
    results.push({
      ruleId: 'k8s-host-ipc',
      type: 'kubernetes',
      severity: 'high',
      title: 'Pod shares host IPC namespace — can access shared memory',
      resource: `Pod: ${doc.metadata?.name || 'unknown'}`,
      namespace: doc.metadata?.namespace,
      advice: ['Avoid hostIPC unless necessary'],
    });
  }

  const volumes = normalizeValue(spec.volumes);
  for (const vol of volumes) {
    if (vol.hostPath) {
      const path = (vol.hostPath as Record<string, unknown>).path as string;
      if (!path || path === '/' || path === '/var/log' || path === '/var/run/docker.sock') {
        results.push({
          ruleId: 'k8s-host-path',
          type: 'kubernetes',
          severity: 'critical',
          title: `hostPath volume mounts: ${path || 'unspecified'}`,
          resource: `Pod: ${doc.metadata?.name || 'unknown'}`,
          namespace: doc.metadata?.namespace,
          advice: ['Use persistent volume claims instead of hostPath', 'If hostPath is required, restrict to specific path and use readOnly'],
        });
      }
    }
  }
}

export function scanK8sManifest(content: string): K8sFinding[] {
  const results: K8sFinding[] = [];

  let docs: unknown[];
  try {
    docs = parseYaml(content);
  } catch {
    return results;
  }

  for (const doc of docs as K8sDoc[]) {
    if (!doc || !doc.kind) continue;

    if (doc.kind === 'Pod') {
      checkPodSpec(doc, results);
      const containers = normalizeValue(doc.spec?.containers);
      for (const c of containers) checkContainer(c, doc, results);
    }

    if (doc.kind === 'Deployment' || doc.kind === 'StatefulSet' || doc.kind === 'DaemonSet' || doc.kind === 'Job' || doc.kind === 'CronJob') {
      const template = (doc.spec as Record<string, unknown>)?.template as Record<string, unknown>;
      const templateSpec = template.spec as Record<string, unknown> | undefined;
      if (templateSpec) {
        checkPodSpec(doc as K8sDoc, results);
        const containers = normalizeValue(templateSpec.containers);
        for (const c of containers) checkContainer(c, doc, results);
        const initContainers = normalizeValue(templateSpec.initContainers);
        for (const c of initContainers) checkContainer(c, doc, results);
      }
    }

    if (doc.kind === 'Role' || doc.kind === 'ClusterRole') {
      const rules = (Array.isArray(doc.rules) ? doc.rules : []) as Array<Record<string, unknown>>;
      for (const rule of rules) {
        if (!rule) continue;
        const verbs = (Array.isArray(rule.verbs) ? rule.verbs : []) as string[];
        const resources = (Array.isArray(rule.resources) ? rule.resources : []) as string[];
        const apiGroups = (Array.isArray(rule.apiGroups) ? rule.apiGroups : []) as string[];

        if (apiGroups.includes('') && resources.includes('*') && verbs.includes('*')) {
          results.push({
            ruleId: 'k8s-clusterrole-wildcard',
            type: 'kubernetes',
            severity: 'high',
            title: 'ClusterRole grants wildcard verbs on all resources — bypasses RBAC',
            resource: `${doc.kind}: ${doc.metadata?.name || 'unknown'}`,
            namespace: doc.metadata?.namespace,
            advice: ['Use least-privilege: specify exact verbs and resources', 'Audit ClusterRoleBinding if attached to system:masters'],
          });
        }

        if (verbs.includes('create') && verbs.includes('delete') && resources.includes('pods')) {
          results.push({
            ruleId: 'k8s-role-pod-delete',
            type: 'kubernetes',
            severity: 'medium',
            title: 'Role can create and delete pods — potential for malicious pod placement',
            resource: `${doc.kind}: ${doc.metadata?.name || 'unknown'}`,
            namespace: doc.metadata?.namespace,
            advice: ['Review if pod create/delete is necessary', 'Consider restricting to specific pod labels'],
          });
        }
      }
    }

    if (doc.kind === 'NetworkPolicy') {
      const podSelector = doc.spec?.podSelector;
      if (!podSelector || Object.keys(podSelector).length === 0) {
        results.push({
          ruleId: 'k8s-netpol-empty-selector',
          type: 'kubernetes',
          severity: 'medium',
          title: 'NetworkPolicy with empty podSelector — applies to all pods in namespace',
          resource: `NetworkPolicy: ${doc.metadata?.name || 'unknown'}`,
          namespace: doc.metadata?.namespace,
          advice: ['Verify this is intentional — empty selector matches all pods', 'Consider scoping to specific pods'],
        });
      }
    }

    if (doc.kind === 'Service') {
      const serviceType = doc.spec?.type as string;
      if (serviceType === 'LoadBalancer') {
        results.push({
          ruleId: 'k8s-service-loadbalancer',
          type: 'kubernetes',
          severity: 'medium',
          title: 'Service type LoadBalancer — exposes cluster to external traffic',
          resource: `Service: ${doc.metadata?.name || 'unknown'}`,
          namespace: doc.metadata?.namespace,
          advice: ['Ensure cloud provider security groups restrict traffic', 'Prefer ClusterIP with ingress for internal services'],
        });
      }
      if (serviceType === 'NodePort') {
        results.push({
          ruleId: 'k8s-service-nodeport',
          type: 'kubernetes',
          severity: 'low',
          title: 'Service type NodePort — exposes service on all cluster nodes',
          resource: `Service: ${doc.metadata?.name || 'unknown'}`,
          namespace: doc.metadata?.namespace,
          advice: ['NodePort exposes on all nodes — consider ClusterIP + ingress'],
        });
      }
    }
  }

  return results;
}

export function formatK8sOutput(findings: K8sFinding[], format: 'text' | 'json' = 'text'): string {
  if (format === 'json') {
    return JSON.stringify({ kubernetes: findings, total: findings.length }, null, 2);
  }

  const lines: string[] = ['\n=== Kubernetes Manifest Findings ===\n'];
  lines.push(`Total: ${findings.length} issues\n`);
  lines.push('─'.repeat(60));

  for (const f of findings) {
    lines.push(`\n[${f.severity.toUpperCase()}] ${f.title}`);
    lines.push(`  Resource: ${f.resource}${f.namespace ? ` (ns: ${f.namespace})` : ''}`);
    if (f.advice.length > 0) lines.push(`  Fix: ${f.advice.join(' | ')}`);
  }

  return lines.join('\n');
}