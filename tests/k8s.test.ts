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