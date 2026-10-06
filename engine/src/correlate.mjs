// Cross-Layer Exposure Correlation: Bridging IaC Ingress & Application Entry Points.
//
// Correlates network exposure rules from Terraform, CloudFormation, Kubernetes,
// and Docker Compose with application HTTP routes and nearby dangerous sinks to
// construct end-to-end Attack Path Graphs.

import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs';
import { join, relative, resolve, sep, basename } from 'node:path';
import { parseHcl } from './parse/hcl.mjs';
import { parseStructured } from './parse/structured.mjs';
import { generateAttackSurfaceMap } from './map.mjs';

const SKIP_DIRS = new Set([
  '.git', 'node_modules', 'dist', 'build', 'out', '.next', '.nuxt', '.cache',
  'coverage', 'vendor', 'target', '.venv', 'venv', '__pycache__', '.tox',
  '.terraform', '.gradle', '.idea', '.airtight',
]);

const FRAMEWORK_DEFAULT_PORTS = {
  express: [3000, 8080],
  fastify: [3000, 8080],
  nextjs: [3000],
  nestjs: [3000],
  nuxt: [3000],
  sveltekit: [5173, 3000],
  flask: [5000],
  fastapi: [8000],
  django: [8000],
  spring: [8080],
  gin: [8080],
  cloudflare: [8787],
};

function* walk(root, dir = root) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      yield* walk(root, full);
    } else if (entry.isFile()) {
      yield full;
    }
  }
}

function parsePortNumber(val) {
  if (val === null || val === undefined) return null;
  const num = Number(val);
  return Number.isInteger(num) && num > 0 && num <= 65535 ? num : null;
}

function portInRange(port, fromPort, toPort) {
  if (port === null) return false;
  const from = fromPort ?? 0;
  const to = toPort ?? fromPort ?? 65535;
  return port >= from && port <= to;
}

function portMatchesRule(port, rule) {
  if (port === null) return false;
  if (rule.targetPort && rule.targetPort === port) return true;
  return portInRange(port, rule.fromPort, rule.toPort);
}

// ---------------------------------------------------- Ingress Rule Extraction

/**
 * Scans infrastructure manifests (Terraform, CloudFormation, Kubernetes, Compose)
 * and extracts ingress exposure rules.
 */
export function extractIngressRules(paths = ['.'], { root = process.cwd() } = {}) {
  const ingressRules = [];

  const targetDirs = (Array.isArray(paths) && paths.length > 0 ? paths : ['.']).map((p) => resolve(root, p));

  const seenFiles = new Set();
  const allFiles = [];
  for (const target of targetDirs) {
    if (!existsSync(target)) continue;
    const st = statSync(target);
    if (st.isDirectory()) {
      for (const file of walk(target)) {
        if (!seenFiles.has(file)) {
          seenFiles.add(file);
          allFiles.push(file);
        }
      }
    } else if (st.isFile()) {
      if (!seenFiles.has(target)) {
        seenFiles.add(target);
        allFiles.push(target);
      }
    }
  }

  for (const file of allFiles) {
    const relPath = relative(root, file);
    const base = basename(file).toLowerCase();

    // 1. Terraform HCL (*.tf)
    if (file.endsWith('.tf')) {
      let content;
      try { content = readFileSync(file, 'utf8'); } catch { continue; }
      const parsed = parseHcl(content);
      const doc = parsed.documents[0];
      if (!doc || !doc.allBlocks) continue;

      for (const b of doc.allBlocks) {
        const address = b.address || '';
        const attrs = b.attrs || {};

        // aws_security_group with inline ingress blocks
        if (b.type === 'ingress' && address.includes('security_group')) {
          const cidrs = Array.isArray(attrs.cidr_blocks) ? attrs.cidr_blocks : [];
          const isPublic = cidrs.includes('0.0.0.0/0') || cidrs.includes('::/0');
          const fromPort = parsePortNumber(attrs.from_port);
          const toPort = parsePortNumber(attrs.to_port) ?? fromPort;
          const protocol = String(attrs.protocol || 'tcp').toLowerCase();

          ingressRules.push({
            id: `${relPath}:${b.line || 1}`,
            source: 'terraform',
            resource: address,
            file: relPath,
            line: b.line || 1,
            protocol,
            fromPort,
            toPort,
            isPublic,
            cidr: isPublic ? '0.0.0.0/0' : cidrs.join(', ') || 'internal',
          });
        }

        // aws_vpc_security_group_ingress_rule
        if (address.includes('aws_vpc_security_group_ingress_rule')) {
          const cidr = attrs.cidr_ipv4 || attrs.cidr_ipv6 || '';
          const isPublic = cidr === '0.0.0.0/0' || cidr === '::/0';
          const fromPort = parsePortNumber(attrs.from_port);
          const toPort = parsePortNumber(attrs.to_port) ?? fromPort;
          const protocol = String(attrs.ip_protocol || attrs.protocol || 'tcp').toLowerCase();

          ingressRules.push({
            id: `${relPath}:${b.line || 1}`,
            source: 'terraform',
            resource: address,
            file: relPath,
            line: b.line || 1,
            protocol,
            fromPort,
            toPort,
            isPublic,
            cidr: cidr || 'internal',
          });
        }

        // google_compute_firewall
        if (address.includes('google_compute_firewall')) {
          const sources = Array.isArray(attrs.source_ranges) ? attrs.source_ranges : [];
          const isPublic = sources.includes('0.0.0.0/0') || sources.includes('::/0');
          let fromPort = null;
          let toPort = null;
          let protocol = 'tcp';

          if (b.blocks) {
            for (const sub of b.blocks) {
              if (sub.type === 'allow' && sub.attrs) {
                protocol = String(sub.attrs.protocol || 'tcp').toLowerCase();
                const ports = Array.isArray(sub.attrs.ports) ? sub.attrs.ports : [];
                if (ports.length > 0) {
                  const pNum = parsePortNumber(ports[0]);
                  if (pNum) { fromPort = pNum; toPort = pNum; }
                }
              }
            }
          }

          ingressRules.push({
            id: `${relPath}:${b.line || 1}`,
            source: 'terraform',
            resource: address,
            file: relPath,
            line: b.line || 1,
            protocol,
            fromPort,
            toPort,
            isPublic,
            cidr: isPublic ? '0.0.0.0/0' : sources.join(', ') || 'internal',
          });
        }

        // azurerm_network_security_rule
        if (address.includes('azurerm_network_security_rule') || address.includes('azurerm_network_security_group')) {
          const direction = String(attrs.direction || '').toLowerCase();
          const access = String(attrs.access || '').toLowerCase();
          if (direction === 'inbound' && access === 'allow') {
            const prefix = String(attrs.source_address_prefix || '');
            const isPublic = prefix === '*' || prefix === 'Internet' || prefix === '0.0.0.0/0';
            const destPort = String(attrs.destination_port_range || '');
            const pNum = parsePortNumber(destPort);

            ingressRules.push({
              id: `${relPath}:${b.line || 1}`,
              source: 'terraform',
              resource: address,
              file: relPath,
              line: b.line || 1,
              protocol: String(attrs.protocol || 'tcp').toLowerCase(),
              fromPort: pNum,
              toPort: pNum,
              isPublic,
              cidr: prefix || 'internal',
            });
          }
        }
      }
      continue;
    }

    // 2. Structured Manifests (CloudFormation, Kubernetes, Compose)
    if (file.endsWith('.yaml') || file.endsWith('.yml') || file.endsWith('.json') || file.endsWith('.template')) {
      let content;
      try { content = readFileSync(file, 'utf8'); } catch { continue; }
      const parsed = parseStructured(content);
      if (!parsed.documents || parsed.documents.length === 0) continue;

      for (const doc of parsed.documents) {
        if (!doc || typeof doc !== 'object') continue;

        // Docker Compose
        if (doc.services && typeof doc.services === 'object') {
          for (const [svcName, svc] of Object.entries(doc.services)) {
            if (!svc || typeof svc !== 'object') continue;
            const isHostNetwork = svc.network_mode === 'host';

            if (Array.isArray(svc.ports)) {
              for (const p of svc.ports) {
                const str = String(p);
                // Forms: "3000:3000", "0.0.0.0:80:80", "127.0.0.1:9000:9000"
                const parts = str.split(':');
                let hostIp = '0.0.0.0';
                let hostPort = null;
                let containerPort = null;

                if (parts.length === 3) {
                  hostIp = parts[0];
                  hostPort = parsePortNumber(parts[1]);
                  containerPort = parsePortNumber(parts[2]);
                } else if (parts.length === 2) {
                  hostPort = parsePortNumber(parts[0]);
                  containerPort = parsePortNumber(parts[1]);
                } else if (parts.length === 1) {
                  containerPort = parsePortNumber(parts[0]);
                  hostPort = containerPort;
                }

                const isPublic = hostIp === '0.0.0.0' || hostIp === '' || hostIp === '::';
                ingressRules.push({
                  id: `${relPath}:${svcName}:${hostPort || containerPort}`,
                  source: 'compose',
                  resource: `compose.services.${svcName}`,
                  file: relPath,
                  line: doc.__line || 1,
                  protocol: 'tcp',
                  fromPort: hostPort || containerPort,
                  toPort: hostPort || containerPort,
                  hostPort,
                  targetPort: containerPort,
                  isPublic,
                  cidr: isPublic ? '0.0.0.0/0' : hostIp,
                });
              }
            } else if (isHostNetwork) {
              ingressRules.push({
                id: `${relPath}:${svcName}:host`,
                source: 'compose',
                resource: `compose.services.${svcName}`,
                file: relPath,
                line: doc.__line || 1,
                protocol: 'tcp',
                fromPort: 1,
                toPort: 65535,
                isPublic: true,
                cidr: '0.0.0.0/0 (host-network)',
              });
            }
          }
        }

        // Kubernetes
        if (doc.kind === 'Service' && doc.spec && typeof doc.spec === 'object') {
          const type = doc.spec.type || 'ClusterIP';
          const isPublic = type === 'LoadBalancer' || type === 'NodePort';
          const ports = Array.isArray(doc.spec.ports) ? doc.spec.ports : [];

          for (const p of ports) {
            const svcPort = parsePortNumber(p.port);
            const targetPort = parsePortNumber(p.targetPort) ?? svcPort;
            ingressRules.push({
              id: `${relPath}:${doc.metadata?.name || 'service'}:${svcPort}`,
              source: 'k8s',
              resource: `k8s.service.${doc.metadata?.name || 'service'}`,
              file: relPath,
              line: doc.__line || 1,
              protocol: String(p.protocol || 'TCP').toLowerCase(),
              fromPort: targetPort,
              toPort: targetPort,
              svcPort,
              isPublic,
              cidr: isPublic ? '0.0.0.0/0 (LoadBalancer/NodePort)' : 'ClusterIP (internal)',
            });
          }
        }

        if (doc.kind === 'Ingress' && doc.spec && typeof doc.spec === 'object') {
          const rules = Array.isArray(doc.spec.rules) ? doc.spec.rules : [];
          for (const r of rules) {
            const host = r.host || '*';
            const paths = r.http?.paths || [];
            for (const pathObj of paths) {
              const portObj = pathObj.backend?.service?.port;
              const portNum = parsePortNumber(portObj?.number ?? portObj);
              if (portNum) {
                ingressRules.push({
                  id: `${relPath}:${doc.metadata?.name || 'ingress'}:${portNum}`,
                  source: 'k8s',
                  resource: `k8s.ingress.${doc.metadata?.name || 'ingress'}`,
                  file: relPath,
                  line: doc.__line || 1,
                  protocol: 'tcp',
                  fromPort: portNum,
                  toPort: portNum,
                  isPublic: true,
                  cidr: `0.0.0.0/0 (Ingress: ${host})`,
                });
              }
            }
          }
        }

        // CloudFormation
        if (doc.Resources && typeof doc.Resources === 'object') {
          for (const [resName, res] of Object.entries(doc.Resources)) {
            if (!res || typeof res !== 'object') continue;

            if (res.Type === 'AWS::EC2::SecurityGroup' && res.Properties) {
              const ingresses = Array.isArray(res.Properties.SecurityGroupIngress)
                ? res.Properties.SecurityGroupIngress
                : [];
              for (const ing of ingresses) {
                const cidr = ing.CidrIp || ing.CidrIpv6 || '';
                const isPublic = cidr === '0.0.0.0/0' || cidr === '::/0';
                const fromPort = parsePortNumber(ing.FromPort);
                const toPort = parsePortNumber(ing.ToPort) ?? fromPort;
                const protocol = String(ing.IpProtocol || 'tcp').toLowerCase();

                ingressRules.push({
                  id: `${relPath}:${resName}:${fromPort}`,
                  source: 'cfn',
                  resource: `cfn.resource.${resName}`,
                  file: relPath,
                  line: doc.__line || 1,
                  protocol,
                  fromPort,
                  toPort,
                  isPublic,
                  cidr: isPublic ? '0.0.0.0/0' : cidr || 'internal',
                });
              }
            }

            if (res.Type === 'AWS::EC2::SecurityGroupIngress' && res.Properties) {
              const cidr = res.Properties.CidrIp || res.Properties.CidrIpv6 || '';
              const isPublic = cidr === '0.0.0.0/0' || cidr === '::/0';
              const fromPort = parsePortNumber(res.Properties.FromPort);
              const toPort = parsePortNumber(res.Properties.ToPort) ?? fromPort;

              ingressRules.push({
                id: `${relPath}:${resName}:${fromPort}`,
                source: 'cfn',
                resource: `cfn.resource.${resName}`,
                file: relPath,
                line: doc.__line || 1,
                protocol: String(res.Properties.IpProtocol || 'tcp').toLowerCase(),
                fromPort,
                toPort,
                isPublic,
                cidr: isPublic ? '0.0.0.0/0' : cidr || 'internal',
              });
            }
          }
        }
      }
    }
  }

  return ingressRules;
}

// ---------------------------------------------------- Application Port Extraction

/**
 * Scans application source files for explicit port bindings (e.g. app.listen(3000)).
 */
export function extractServicePorts(paths = ['.'], { root = process.cwd() } = {}) {
  const servicePorts = [];
  const targetDirs = (Array.isArray(paths) && paths.length > 0 ? paths : ['.']).map((p) => resolve(root, p));

  const seenFiles = new Set();
  for (const target of targetDirs) {
    if (!existsSync(target)) continue;
    const st = statSync(target);
    if (st.isDirectory()) {
      for (const file of walk(target)) {
        if (!seenFiles.has(file)) {
          seenFiles.add(file);
        }
      }
    } else if (st.isFile()) {
      seenFiles.add(target);
    }
  }

  const explicitPortRe = /(?:\.listen\s*\(\s*(\d{2,5})\b|server\.port\s*[=:]\s*(\d{2,5})\b|PORT\s*=\s*(\d{2,5})\b|\.Run\s*\(\s*["']:(\d{2,5})["']|ListenAndServe\s*\(\s*["']:(\d{2,5})["']|port\s*=\s*(\d{2,5})\b)/;

  for (const file of seenFiles) {
    const ext = '.' + file.split('.').pop();
    if (!['.js', '.ts', '.mjs', '.cjs', '.py', '.go', '.java', '.properties', '.yaml', '.yml'].includes(ext)) {
      continue;
    }
    let content;
    try { content = readFileSync(file, 'utf8'); } catch { continue; }
    const m = explicitPortRe.exec(content);
    if (m) {
      const port = parsePortNumber(m[1] || m[2] || m[3] || m[4] || m[5] || m[6]);
      if (port) {
        servicePorts.push({
          file: relative(root, file),
          port,
        });
      }
    }
  }

  return servicePorts;
}

// ---------------------------------------------------- Attack Surface Correlation

/**
 * Correlates application HTTP routes and dangerous sinks with infrastructure
 * ingress rules, constructing an Attack Path Graph and computing risk elevation.
 */
export function correlateAttackSurface(paths = ['.'], { root = process.cwd() } = {}) {
  const mapResult = generateAttackSurfaceMap(paths, { root });
  const ingressRules = extractIngressRules(paths, { root });
  const servicePorts = extractServicePorts(paths, { root });

  const publicIngressRules = ingressRules.filter((r) => r.isPublic);

  const exposedRoutes = [];
  const internalRoutes = [];
  const attackPaths = [];

  for (const route of mapResult.routes) {
    // Determine candidate ports for this route
    const candidatePorts = new Set();

    // 1. Explicit port in the same file or project
    const fileExplicit = servicePorts.find((sp) => sp.file === route.file);
    if (fileExplicit) {
      candidatePorts.add(fileExplicit.port);
    } else if (servicePorts.length > 0) {
      // Use project-level explicit ports
      for (const sp of servicePorts) candidatePorts.add(sp.port);
    }

    // 2. Add framework default ports
    const defaults = FRAMEWORK_DEFAULT_PORTS[route.framework] || [3000, 8080];
    for (const d of defaults) candidatePorts.add(d);

    // Check if any candidate port matches a public ingress rule
    const matchingPublicIngress = [];
    const matchingInternalIngress = [];

    for (const p of candidatePorts) {
      for (const rule of ingressRules) {
        if (portMatchesRule(p, rule)) {
          if (rule.isPublic) {
            matchingPublicIngress.push({ port: p, rule });
          } else {
            matchingInternalIngress.push({ port: p, rule });
          }
        }
      }
    }

    if (matchingPublicIngress.length > 0) {
      route.exposure = 'internet-facing';
      route.ingressRules = matchingPublicIngress.map((m) => m.rule);
      route.exposedPort = matchingPublicIngress[0].port;
      exposedRoutes.push(route);

      // Build attack path for each sink on this internet-facing route
      if (Array.isArray(route.sinks)) {
        for (const sink of route.sinks) {
          const pub = matchingPublicIngress[0].rule;
          const attackPath = {
            id: `${route.file}:${route.line}:${sink.line}`,
            framework: route.framework,
            method: route.method,
            path: route.path,
            routeFile: route.file,
            routeLine: route.line,
            sinkType: sink.type,
            sinkLine: sink.line,
            sinkSnippet: sink.snippet,
            publicIngress: pub,
            exposedPort: matchingPublicIngress[0].port,
            riskLevel: 'critical',
            pathString: `Internet (0.0.0.0/0) -> ${pub.source} (${pub.cidr}:${matchingPublicIngress[0].port}) -> ${route.method} ${route.path} -> ${sink.type.toUpperCase()} Sink`,
          };
          attackPaths.push(attackPath);
        }
      }
    } else {
      route.exposure = matchingInternalIngress.length > 0 ? 'internal' : 'unmapped';
      internalRoutes.push(route);
    }
  }

  return {
    attackPaths,
    exposedRoutes,
    internalRoutes,
    ingressRules,
    servicePorts,
    summary: {
      totalIngressRules: ingressRules.length,
      totalPublicIngressRules: publicIngressRules.length,
      totalRoutes: mapResult.routes.length,
      totalExposedRoutes: exposedRoutes.length,
      totalInternalRoutes: internalRoutes.length,
      totalAttackPaths: attackPaths.length,
      frameworks: mapResult.summary.frameworks,
    },
  };
}
