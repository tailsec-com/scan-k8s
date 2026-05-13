import { describe, it, test, expect } from '@jest/globals';
import { scanK8sManifest, formatK8sOutput } from '../src/k8s.js';

describe('scanK8sManifest', () => {
  it('scan empty manifest → 0 findings', () => {
    const findings = scanK8sManifest('');
    expect(findings).toHaveLength(0);
  });

  it('scan privileged container → finds k8s-privileged-container', () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
    - name: nginx
      image: nginx
      securityContext:
        privileged: true
`;
    const findings = scanK8sManifest(yaml);
    expect(findings.some(f => f.ruleId === 'k8s-privileged-container')).toBe(true);
  });

  it('scan allowPrivilegeEscalation true → finds k8s-allow-privilege-escalation', () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata:
  name: escalator
spec:
  containers:
    - name: app
      image: app:latest
      securityContext:
        allowPrivilegeEscalation: true
`;
    const findings = scanK8sManifest(yaml);
    expect(findings.some(f => f.ruleId === 'k8s-allow-privilege-escalation')).toBe(true);
  });

  it('scan hostNetwork true → finds k8s-host-network', () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata:
  name: network-pod
spec:
  hostNetwork: true
  containers:
    - name: app
      image: app:latest
`;
    const findings = scanK8sManifest(yaml);
    expect(findings.some(f => f.ruleId === 'k8s-host-network')).toBe(true);
  });

  it('scan hostPath volume → finds k8s-host-path', () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata:
  name: hostpath-pod
spec:
  containers:
    - name: app
      image: app:latest
  volumes:
    - name: host-volume
      hostPath:
        path: /var/run/docker.sock
`;
    const findings = scanK8sManifest(yaml);
    expect(findings.some(f => f.ruleId === 'k8s-host-path')).toBe(true);
  });

  it('scan ClusterRole with wildcard → finds k8s-clusterrole-wildcard', () => {
    const yaml = `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"wild-role"},"rules":[{"apiGroups":[""],"resources":["*"],"verbs":["*"]}]}`;
    const findings = scanK8sManifest(yaml);
    expect(findings.some(f => f.ruleId === 'k8s-clusterrole-wildcard')).toBe(true);
  });

  it('scan Service type LoadBalancer → finds k8s-service-loadbalancer', () => {
    const yaml = `
apiVersion: v1
kind: Service
metadata:
  name: my-service
spec:
  type: LoadBalancer
  ports:
    - port: 80
`;
    const findings = scanK8sManifest(yaml);
    expect(findings.some(f => f.ruleId === 'k8s-service-loadbalancer')).toBe(true);
  });

  it('scan Deployment with :latest image → finds k8s-image-latest', () => {
    const yaml = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: latest-deployment
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:latest
`;
    const findings = scanK8sManifest(yaml);
    expect(findings.some(f => f.ruleId === 'k8s-image-latest')).toBe(true);
  });

  it('scan capabilities.drop missing ALL → finds k8s-capabilities-drop-missing', () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata:
  name: no-cap-drop
spec:
  containers:
    - name: app
      image: app:latest
      securityContext:
        capabilities:
          add: ["NET_ADMIN"]
`;
    const findings = scanK8sManifest(yaml);
    expect(findings.some(f => f.ruleId === 'k8s-capabilities-drop-missing')).toBe(true);
  });

  it('scan automountServiceAccountToken: true → finds k8s-automount-sa-token', () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata:
  name: automount-sa
spec:
  automountServiceAccountToken: true
  containers:
    - name: app
      image: app:latest
`;
    const findings = scanK8sManifest(yaml);
    expect(findings.some(f => f.ruleId === 'k8s-automount-sa-token')).toBe(true);
  });

  it('scan dnsPolicy ClusterFirstWithHostNet → finds k8s-dns-host-network', () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata:
  name: dns-hostnet
spec:
  hostNetwork: true
  dnsPolicy: ClusterFirstWithHostNet
  containers:
    - name: app
      image: app:latest
`;
    const findings = scanK8sManifest(yaml);
    expect(findings.some(f => f.ruleId === 'k8s-dns-host-network')).toBe(true);
  });

  it('scan serviceAccountName: default → finds k8s-default-sa', () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata:
  name: default-sa-pod
spec:
  serviceAccountName: default
  containers:
    - name: app
      image: app:latest
`;
    const findings = scanK8sManifest(yaml);
    expect(findings.some(f => f.ruleId === 'k8s-default-sa')).toBe(true);
  });

  it('scan high priority class name → finds k8s-high-priority-class', () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata:
  name: high-priority-pod
spec:
  priorityClassName: production-high
  containers:
    - name: app
      image: app:latest
`;
    const findings = scanK8sManifest(yaml);
    expect(findings.some(f => f.ruleId === 'k8s-high-priority-class')).toBe(true);
  });

  it('scan terminationGracePeriodSeconds > 300 → finds k8s-long-grace-period', () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata:
  name: long-grace-pod
spec:
  terminationGracePeriodSeconds: 600
  containers:
    - name: app
      image: app:latest
`;
    const findings = scanK8sManifest(yaml);
    expect(findings.some(f => f.ruleId === 'k8s-long-grace-period')).toBe(true);
  });

  it('scan defaultAllowPrivilegeEscalation: true → finds k8s-default-allow-priv-esc', () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata:
  name: default-priv-esc
spec:
  securityContext:
    defaultAllowPrivilegeEscalation: true
  containers:
    - name: app
      image: app:latest
`;
    const findings = scanK8sManifest(yaml);
    expect(findings.some(f => f.ruleId === 'k8s-default-allow-priv-esc')).toBe(true);
  });

  it('scan container missing liveness probe → finds k8s-missing-liveness-probe', () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata:
  name: no-liveness
spec:
  containers:
    - name: app
      image: app:latest
`;
    const findings = scanK8sManifest(yaml);
    expect(findings.some(f => f.ruleId === 'k8s-missing-liveness-probe')).toBe(true);
  });

  it('scan container with liveness probe → does not find k8s-missing-liveness-probe', () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata:
  name: with-liveness
spec:
  containers:
    - name: app
      image: app:latest
      livenessProbe:
        httpGet:
          path: /healthz
          port: 8080
`;
    const findings = scanK8sManifest(yaml);
    expect(findings.some(f => f.ruleId === 'k8s-missing-liveness-probe')).toBe(false);
  });

  it('scan container missing readiness probe → finds k8s-missing-readiness-probe', () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata:
  name: no-readiness
spec:
  containers:
    - name: app
      image: app:latest
`;
    const findings = scanK8sManifest(yaml);
    expect(findings.some(f => f.ruleId === 'k8s-missing-readiness-probe')).toBe(true);
  });

  it('scan container with readiness probe → does not find k8s-missing-readiness-probe', () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata:
  name: with-readiness
spec:
  containers:
    - name: app
      image: app:latest
      readinessProbe:
        httpGet:
          path: /ready
          port: 8080
`;
    const findings = scanK8sManifest(yaml);
    expect(findings.some(f => f.ruleId === 'k8s-missing-readiness-probe')).toBe(false);
  });

  it('scan container missing resources → finds k8s-missing-resources', () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata:
  name: no-resources
spec:
  containers:
    - name: app
      image: app:latest
`;
    const findings = scanK8sManifest(yaml);
    expect(findings.some(f => f.ruleId === 'k8s-missing-resources')).toBe(true);
  });

  it('scan container with resources → does not find k8s-missing-resources', () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata:
  name: with-resources
spec:
  containers:
    - name: app
      image: app:latest
      resources:
        limits:
          cpu: "100m"
          memory: "128Mi"
        requests:
          cpu: "50m"
          memory: "64Mi"
`;
    const findings = scanK8sManifest(yaml);
    expect(findings.some(f => f.ruleId === 'k8s-missing-resources')).toBe(false);
  });

  it('scan automountServiceAccountToken: false → finds k8s-automount-sa-token-false', () => {
    const yaml = `
apiVersion: v1
kind: Pod
metadata:
  name: no-sa-token
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: app:latest
`;
    const findings = scanK8sManifest(yaml);
    expect(findings.some(f => f.ruleId === 'k8s-automount-sa-token-false')).toBe(true);
  });
});

describe('formatK8sOutput', () => {
  it('format output text → contains "Kubernetes Manifest Findings"', () => {
    const findings = scanK8sManifest('');
    const output = formatK8sOutput(findings, 'text');
    expect(output).toContain('Kubernetes Manifest Findings');
  });

  it('format output json → valid JSON with kubernetes array', () => {
    const findings = scanK8sManifest('');
    const output = formatK8sOutput(findings, 'json');
    const parsed = JSON.parse(output);
    expect(parsed).toHaveProperty('kubernetes');
    expect(Array.isArray(parsed.kubernetes)).toBe(true);
    expect(parsed).toHaveProperty('total');
  });

  it('format empty output → shows "0 issues"', () => {
    const findings = scanK8sManifest('');
    const output = formatK8sOutput(findings, 'text');
    expect(output).toContain('0 issues');
  });
});
