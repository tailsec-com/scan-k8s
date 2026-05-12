import { readFileSync, statSync } from 'fs';

const YAML_CACHE = new Map<string, unknown[]>();
const RELEVANT_KINDS = new Set(['Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob', 'Role', 'ClusterRole', 'NetworkPolicy', 'Service']);

function parseYaml(content: string): unknown[] {
  const cached = YAML_CACHE.get(content);
  if (cached) return cached;

  const docs: unknown[] = [];
  const rawDocs = content.split(/^---$/m);

  for (const raw of rawDocs) {
    const lines = raw.split('\n');
    const strippedLines: string[] = [];
    for (let i = 0; i < lines.length; i++) {
      const l = lines[i];
      if (!l.trim().startsWith('#')) strippedLines.push(l);
    }
    const stripped = strippedLines.join('\n').trim();

    if (!stripped) continue;

    try {
      const obj = eval(`(${stripped.replace(/'/g, '"')})`);
      if (obj && typeof obj === 'object' && obj.kind) {
        if (!RELEVANT_KINDS.has(obj.kind as string)) continue;
      }
      docs.push(obj);
    } catch {
      const parsed = parseYamlLines(lines);
      if (parsed && typeof parsed === 'object' && Object.keys(parsed).length > 0) {
        docs.push(parsed);
      }
    }
  }

  YAML_CACHE.set(content, docs);
  return docs;
}

function parseYamlLines(lines: string[]): Record<string, unknown> {
  const root: Record<string, unknown> = {};
  const stack: Array<{ indent: number; obj: Record<string, unknown> }> = [{ indent: -1, obj: root }];
  const lineCount = lines.length;

  for (let lineIdx = 0; lineIdx < lineCount; lineIdx++) {
    const rawLine = lines[lineIdx];
    const trimmed = rawLine.trim();
    if (!trimmed) continue;

    const colonIdx = trimmed.indexOf(':');
    if (colonIdx === -1) continue;

    let indent = 0;
    let keyStart = 0;
    for (let i = 0; i < rawLine.length; i++) {
      if (rawLine[i] === ' ') indent = i;
      else if (rawLine[i] !== ' ') break;
    }

    const isListItem = trimmed[0] === '-';
    let key: string;
    let value: string;

    if (isListItem) {
      const afterDash = trimmed.slice(1).trim();
      const vc = afterDash.indexOf(':');
      if (vc !== -1) {
        key = afterDash.slice(0, vc).trim();
        value = afterDash.slice(vc + 1).trim();
      } else {
        key = afterDash;
        value = '';
      }
    } else {
      key = trimmed.slice(0, colonIdx).trim();
      value = trimmed.slice(colonIdx + 1).trim();
    }

    while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
      stack.pop();
    }

    const parent = stack[stack.length - 1].obj;

    if (isListItem) {
      if (!parent[key]) parent[key] = [];
      const arr = parent[key] as unknown[];
      const item: Record<string, unknown> = {};
      arr.push(item);
      stack.push({ indent, obj: item });

      if (value) {
        const num = Number(value);
        item[key] = value === 'true' ? true : value === 'false' ? false : isNaN(num) ? value.replace(/^["']|["']$/g, '') : num;
      }
    } else {
      if (value === '' || value === '|' || value === '>-') {
        parent[key] = {};
        stack.push({ indent, obj: parent[key] as Record<string, unknown> });
      } else if (value.startsWith('[') && value.endsWith(']')) {
        parent[key] = value.slice(1, -1).split(',').map(v => v.trim().replace(/^["']|["']$/g, ''));
      } else if (value.startsWith('{') && value.endsWith('}')) {
        try {
          parent[key] = JSON.parse(value);
        } catch {
          parent[key] = value.replace(/^["']|["']$/g, '');
        }
      } else {
        const num = Number(value);
        parent[key] = value === 'true' ? true : value === 'false' ? false : isNaN(num) ? value.replace(/^["']|["']$/g, '') : num;
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

  const caps = securityContext.capabilities as Record<string, unknown>;
  if (caps?.drop === undefined || !Array.isArray(caps.drop) || caps.drop.length === 0 || !caps.drop.includes('ALL')) {
    results.push({
      ruleId: 'k8s-capabilities-drop-missing',
      type: 'kubernetes',
      severity: 'high',
      title: 'Container does not drop ALL capabilities',
      resource: `${doc.kind}: ${doc.metadata?.name || 'unknown'}`,
      namespace: doc.metadata?.namespace,
      advice: ["Add securityContext.capabilities.drop = [\"ALL\"]", "Containers should drop all capabilities and add only what is needed"],
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

  const capsDangerous = securityContext.capabilities as Record<string, unknown>;
  if (capsDangerous?.add) {
    const dangerous = ['SYS_ADMIN', 'NET_ADMIN', 'SYS_MODULE', 'DAC_READ_SEARCH', 'DAC_OVERRIDE', 'FOWNER', 'FSETID', 'KILL', 'SETGID', 'SETUID', 'SETFCAP', 'LINUX_IMMUTABLE', 'NET_BROADCAST', 'IPC_LOCK', 'IPC_OWNER', 'SYS_MODULE', 'SYS_RAWIO', 'SYS_PTRACE', 'SYS_TIME', 'SYS_CHROOT', 'AUDIT_WRITE', 'CHOWN', 'NET_RAW', 'NET_BIND_SERVICE', 'SYS_BOOT'];
    const added = capsDangerous.add as string[];
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

  const dnsPolicy = spec.dnsPolicy as string;
  if (dnsPolicy === 'ClusterFirstWithHostNet' && spec.hostNetwork === true) {
    results.push({
      ruleId: 'k8s-dns-host-network',
      type: 'kubernetes',
      severity: 'medium',
      title: 'Pod uses host network with ClusterFirst DNS — DNS may resolve incorrectly',
      resource: `Pod: ${doc.metadata?.name || 'unknown'}`,
      namespace: doc.metadata?.namespace,
      advice: ['Set dnsPolicy: ClusterFirst to use cluster DNS from hostNetwork pod', 'Or ensure hostNetwork DNS meets your requirements'],
    });
  }

  const hostDevices = spec.hostDevices as Record<string, unknown>;
  if (hostDevices && Object.keys(hostDevices).length > 0) {
    results.push({
      ruleId: 'k8s-host-devices',
      type: 'kubernetes',
      severity: 'critical',
      title: 'Pod has direct access to host devices',
      resource: `Pod: ${doc.metadata?.name || 'unknown'}`,
      namespace: doc.metadata?.namespace,
      advice: ['Avoid hostDevices unless necessary for hardware access'],
    });
  }

  if (spec.automountServiceAccountToken === true) {
    results.push({
      ruleId: 'k8s-automount-sa-token',
      type: 'kubernetes',
      severity: 'medium',
      title: 'ServiceAccount token explicitly automounted',
      resource: `Pod: ${doc.metadata?.name || 'unknown'}`,
      namespace: doc.metadata?.namespace,
      advice: ['Set automountServiceAccountToken: false if token is not needed', 'Use workload identity instead'],
    });
  }

  const serviceAccountName = spec.serviceAccountName as string;
  if (serviceAccountName === 'default') {
    results.push({
      ruleId: 'k8s-default-sa',
      type: 'kubernetes',
      severity: 'medium',
      title: 'Pod uses default service account — lacks proper isolation',
      resource: `Pod: ${doc.metadata?.name || 'unknown'}`,
      namespace: doc.metadata?.namespace,
      advice: ['Create a dedicated service account for this workload', 'Use RBAC to grant minimum required permissions'],
    });
  }

  const priorityClassName = spec.priorityClassName as string;
  if (priorityClassName && !priorityClassName.startsWith('system-')) {
    const highPriority = ['high', 'critical', 'very-high', 'urgent', 'production-high'];
    if (highPriority.some(p => priorityClassName.toLowerCase().includes(p))) {
      results.push({
        ruleId: 'k8s-high-priority-class',
        type: 'kubernetes',
        severity: 'medium',
        title: `Pod uses high priority class: ${priorityClassName} — may evict other pods`,
        resource: `Pod: ${doc.metadata?.name || 'unknown'}`,
        namespace: doc.metadata?.namespace,
        advice: ['Review if high priority is necessary', 'High priority pods can preempt lower priority workloads'],
      });
    }
  }

  const terminationGracePeriodSeconds = spec.terminationGracePeriodSeconds as number;
  if (terminationGracePeriodSeconds && terminationGracePeriodSeconds > 300) {
    results.push({
      ruleId: 'k8s-long-grace-period',
      type: 'kubernetes',
      severity: 'low',
      title: `Termination grace period is ${terminationGracePeriodSeconds}s — longer than recommended`,
      resource: `Pod: ${doc.metadata?.name || 'unknown'}`,
      namespace: doc.metadata?.namespace,
      advice: ['Consider reducing terminationGracePeriodSeconds to 300 or less', 'Long grace periods delay pod cleanup and scaling operations'],
    });
  }

  const defaultAllowPrivilegeEscalation = secCtx.defaultAllowPrivilegeEscalation;
  if (defaultAllowPrivilegeEscalation === true) {
    results.push({
      ruleId: 'k8s-default-allow-priv-esc',
      type: 'kubernetes',
      severity: 'critical',
      title: 'PodSecurityContext defaultAllowPrivilegeEscalation is true',
      resource: `Pod: ${doc.metadata?.name || 'unknown'}`,
      namespace: doc.metadata?.namespace,
      advice: ['Set defaultAllowPrivilegeEscalation: false in PodSecurityContext', 'This is a PSP-adjacent control for environments without PSP'],
    });
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