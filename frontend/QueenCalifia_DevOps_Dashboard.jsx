import { useState, useEffect, useCallback, useRef } from "react";

/*
 * QueenCalifia — DevOps One-Click Operations Dashboard
 *
 * A unified control surface for K8s bootstrap, branch protection,
 * DNS sanity, and deployment operations. Designed to match the
 * SOC dashboard aesthetic of the main QueenCalifia platform.
 */

const C = {
  void: "#04070d",
  bg: "#080c18",
  panel: "#0b1120",
  panelHover: "#0f1730",
  surface: "#111b2e",
  border: "#152035",
  borderLit: "#1c3358",
  borderHot: "#3b82f6",
  glow: "rgba(59,130,246,0.08)",
  glowHot: "rgba(59,130,246,0.18)",
  text: "#d6e0f0",
  textSoft: "#8da2c0",
  textDim: "#506580",
  accent: "#3b82f6",
  accentBright: "#60a5fa",
  green: "#10b981",
  greenDim: "rgba(16,185,129,0.12)",
  amber: "#f59e0b",
  amberDim: "rgba(245,158,11,0.10)",
  red: "#ef4444",
  redDim: "rgba(239,68,68,0.10)",
  cyan: "#06b6d4",
  cyanDim: "rgba(6,182,212,0.08)",
  purple: "#a78bfa",
  purpleDim: "rgba(167,139,250,0.10)",
};

const FONT =
  "'DM Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif";
const MONO =
  "'JetBrains Mono', 'SF Mono', SFMono-Regular, Menlo, Consolas, monospace";

// ─── Workflow definitions ────────────────────────────────────────────
const WORKFLOWS = [
  {
    id: "bootstrap",
    label: "Bootstrap K8s",
    icon: "⎈",
    color: C.accent,
    dimColor: C.glow,
    description: "Provision cluster, install ingress, cert-manager, ArgoCD",
    workflow: "bootstrap-k8s.yml",
    category: "infrastructure",
    inputs: [
      { key: "cloud_provider", label: "Cloud", type: "select", options: ["aws", "gcp", "azure", "do"], default: "aws" },
      { key: "cluster_name", label: "Cluster name", type: "text", default: "qc-production" },
      { key: "ingress_provider", label: "Ingress", type: "select", options: ["nginxinc", "traefik", "haproxy"], default: "nginxinc" },
    ],
    checks: ["KUBECONFIG_B64 secret configured", "Cloud credentials set", "Domain DNS delegated"],
  },
  {
    id: "protect",
    label: "Protect Branches",
    icon: "🛡",
    color: C.green,
    dimColor: C.greenDim,
    description: "Apply branch protection rules with optional auto-discover of check contexts",
    workflow: "protect-branches.yml",
    category: "security",
    inputs: [
      { key: "branches", label: "Branches", type: "text", default: "staging,production" },
      { key: "approvals", label: "Approvals", type: "select", options: ["1", "2", "3"], default: "2" },
      { key: "enforce_admins", label: "Enforce admins", type: "toggle", default: true },
      { key: "auto_discover", label: "Auto-discover checks", type: "toggle", default: false },
      { key: "allow_list", label: "AllowList (regex, comma-sep)", type: "text", default: "" },
      { key: "deny_list", label: "DenyList (regex, comma-sep)", type: "text", default: "" },
      { key: "exclude_apps", label: "Exclude apps (slugs, comma-sep)", type: "text", default: "" },
      { key: "production_extra", label: "Production-only extras", type: "text", default: "" },
      { key: "use_checks_api", label: "Use checks[] API (collision-safe)", type: "toggle", default: true },
      { key: "dry_run", label: "Dry run", type: "toggle", default: false },
    ],
    checks: ["GH_TOKEN secret (PAT with repo admin scope)", "Branches exist in repository"],
  },
  {
    id: "protect-preview",
    label: "Protection Preview",
    icon: "🔍",
    color: C.green,
    dimColor: C.greenDim,
    description: "Dry-run branch protection and download JSON payloads for review before applying",
    workflow: "protect-branches-preview.yml",
    category: "security",
    inputs: [
      { key: "branches", label: "Branches", type: "text", default: "staging,production" },
      { key: "approvals", label: "Approvals", type: "select", options: ["1", "2", "3"], default: "2" },
      { key: "enforce_admins", label: "Enforce admins", type: "toggle", default: true },
      { key: "scan_branch", label: "Scan branch", type: "text", default: "main" },
      { key: "scan_commits", label: "Commits to scan", type: "select", options: ["5", "10", "15", "25"], default: "15" },
      { key: "exclude_apps", label: "Exclude apps (slugs)", type: "text", default: "" },
      { key: "use_checks_api", label: "Use checks[] API", type: "toggle", default: true },
    ],
    checks: ["GH_TOKEN secret (PAT with repo scope)", "CI has run on the scan branch"],
  },
  {
    id: "check-contexts",
    label: "Scan Check Contexts",
    icon: "📋",
    color: C.cyan,
    dimColor: C.cyanDim,
    description: "List check-run names with app metadata — shows which GitHub App owns each check",
    workflow: "scan-check-contexts.yml",
    script: "scripts/github/print_check_contexts.ps1",
    category: "security",
    inputs: [
      { key: "branch", label: "Branch to scan", type: "text", default: "main" },
      { key: "commits", label: "Commits to scan", type: "select", options: ["5", "10", "15", "25", "50"], default: "15" },
      { key: "exclude_apps", label: "Exclude apps (slugs)", type: "text", default: "" },
    ],
    checks: ["GH_TOKEN or GITHUB_TOKEN with checks:read", "CI has run on the scan branch"],
  },
  {
    id: "dns",
    label: "DNS Sanity",
    icon: "🌐",
    color: C.cyan,
    dimColor: C.cyanDim,
    description: "Verify DNS → ingress LB routing and ACME challenge reachability",
    workflow: "post-bootstrap-dns-sanity.yml",
    category: "infrastructure",
    inputs: [
      { key: "ingress_provider", label: "Ingress", type: "select", options: ["nginxinc", "traefik", "haproxy"], default: "nginxinc" },
      { key: "staging_host", label: "Staging host", type: "text", default: "staging.example.com" },
      { key: "prod_host", label: "Prod host", type: "text", default: "app.example.com" },
      { key: "strict_dns", label: "Strict DNS match", type: "toggle", default: false },
    ],
    checks: ["KUBECONFIG_B64 secret configured", "DNS records point to cluster", "Ingress controller healthy"],
  },
  {
    id: "deploy-vm",
    label: "Deploy VM",
    icon: "🖥",
    color: C.purple,
    dimColor: C.purpleDim,
    description: "Deploy or update QueenCalifia on a bare VM target",
    workflow: "deploy-vm.yml",
    category: "deploy",
    inputs: [
      { key: "target_host", label: "Target host", type: "text", default: "" },
      { key: "deploy_env", label: "Environment", type: "select", options: ["staging", "production"], default: "staging" },
    ],
    checks: ["SSH key configured", "Target host reachable", "Docker installed on target"],
  },
  {
    id: "promote",
    label: "Promote → Prod",
    icon: "🚀",
    color: C.amber,
    dimColor: C.amberDim,
    description: "Open a promotion PR from staging to production",
    workflow: "promote-production.yml",
    category: "deploy",
    inputs: [],
    checks: ["Staging branch healthy", "All CI checks passing", "ArgoCD staging synced"],
  },
  {
    id: "helm-release",
    label: "Release Helm",
    icon: "📦",
    color: C.accentBright,
    dimColor: C.glow,
    description: "Package and publish Helm chart to GitHub Pages / OCI registry",
    workflow: "release-helm.yml",
    category: "deploy",
    inputs: [],
    checks: ["Chart.yaml version bumped", "values.schema.json valid", "CI passing"],
  },
];

const CATEGORIES = {
  infrastructure: { label: "Infrastructure", color: C.accent },
  security: { label: "Security", color: C.green },
  deploy: { label: "Deploy", color: C.amber },
};

// ─── Micro-components ────────────────────────────────────────────────

function Pulse({ color, active }) {
  if (!active) return null;
  return (
    <span
      style={{
        display: "inline-block",
        width: 8,
        height: 8,
        borderRadius: "50%",
        background: color,
        boxShadow: `0 0 6px ${color}, 0 0 12px ${color}40`,
        animation: "qcPulse 2s ease-in-out infinite",
      }}
    />
  );
}

function Badge({ children, color, bg }) {
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 4,
        padding: "3px 10px",
        borderRadius: 99,
        fontSize: 11,
        fontFamily: MONO,
        fontWeight: 500,
        letterSpacing: "0.02em",
        color: color || C.textSoft,
        background: bg || C.surface,
        border: `1px solid ${color ? color + "30" : C.border}`,
      }}
    >
      {children}
    </span>
  );
}

function IconBtn({ children, onClick, title, active, color }) {
  const [hov, setHov] = useState(false);
  return (
    <button
      onClick={onClick}
      title={title}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        width: 34,
        height: 34,
        borderRadius: 10,
        border: `1px solid ${active ? (color || C.borderHot) : C.border}`,
        background: active ? (color || C.borderHot) + "15" : hov ? C.panelHover : "transparent",
        color: active ? (color || C.accentBright) : C.textSoft,
        cursor: "pointer",
        fontSize: 14,
        fontFamily: FONT,
        transition: "all 0.15s ease",
      }}
    >
      {children}
    </button>
  );
}

// ─── Input controls ──────────────────────────────────────────────────

function TextInput({ value, onChange, placeholder }) {
  const [focus, setFocus] = useState(false);
  return (
    <input
      type="text"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      onFocus={() => setFocus(true)}
      onBlur={() => setFocus(false)}
      placeholder={placeholder}
      style={{
        width: "100%",
        padding: "8px 12px",
        borderRadius: 8,
        border: `1px solid ${focus ? C.borderHot : C.border}`,
        background: C.void,
        color: C.text,
        fontFamily: MONO,
        fontSize: 13,
        outline: "none",
        transition: "border-color 0.15s",
        boxSizing: "border-box",
      }}
    />
  );
}

function SelectInput({ value, onChange, options }) {
  const [focus, setFocus] = useState(false);
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      onFocus={() => setFocus(true)}
      onBlur={() => setFocus(false)}
      style={{
        width: "100%",
        padding: "8px 12px",
        borderRadius: 8,
        border: `1px solid ${focus ? C.borderHot : C.border}`,
        background: C.void,
        color: C.text,
        fontFamily: MONO,
        fontSize: 13,
        outline: "none",
        cursor: "pointer",
        appearance: "none",
        backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%23506580' stroke-width='2'%3E%3Cpolyline points='6 9 12 15 18 9'%3E%3C/polyline%3E%3C/svg%3E")`,
        backgroundRepeat: "no-repeat",
        backgroundPosition: "right 10px center",
        paddingRight: 30,
        boxSizing: "border-box",
      }}
    >
      {options.map((o) => (
        <option key={o} value={o}>
          {o}
        </option>
      ))}
    </select>
  );
}

function ToggleInput({ value, onChange, label }) {
  return (
    <button
      onClick={() => onChange(!value)}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 8,
        padding: "6px 0",
        background: "none",
        border: "none",
        cursor: "pointer",
        fontFamily: FONT,
        fontSize: 13,
        color: C.textSoft,
      }}
    >
      <span
        style={{
          display: "inline-flex",
          alignItems: "center",
          justifyContent: value ? "flex-end" : "flex-start",
          width: 36,
          height: 20,
          borderRadius: 99,
          padding: 2,
          background: value ? C.accent : C.surface,
          border: `1px solid ${value ? C.accent : C.border}`,
          transition: "all 0.2s ease",
        }}
      >
        <span
          style={{
            width: 14,
            height: 14,
            borderRadius: "50%",
            background: value ? "#fff" : C.textDim,
            transition: "all 0.2s ease",
          }}
        />
      </span>
      {label}
    </button>
  );
}

// ─── Log viewer ──────────────────────────────────────────────────────

function LogViewer({ lines }) {
  const ref = useRef(null);
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [lines]);

  if (!lines.length) return null;

  return (
    <div
      ref={ref}
      style={{
        marginTop: 12,
        padding: 12,
        borderRadius: 10,
        background: C.void,
        border: `1px solid ${C.border}`,
        maxHeight: 240,
        overflowY: "auto",
        fontFamily: MONO,
        fontSize: 12,
        lineHeight: 1.7,
      }}
    >
      {lines.map((l, i) => (
        <div
          key={i}
          style={{
            color: l.includes("✅")
              ? C.green
              : l.includes("❌")
              ? C.red
              : l.includes("⚠")
              ? C.amber
              : l.startsWith("==>")
              ? C.accentBright
              : C.textSoft,
            whiteSpace: "pre-wrap",
            wordBreak: "break-all",
          }}
        >
          <span style={{ color: C.textDim, userSelect: "none" }}>
            {String(i + 1).padStart(3)}{" "}
          </span>
          {l}
        </div>
      ))}
    </div>
  );
}

// ─── Workflow Card ───────────────────────────────────────────────────

function WorkflowCard({ wf, isActive, onSelect }) {
  const [hov, setHov] = useState(false);
  const active = isActive || hov;

  return (
    <button
      onClick={onSelect}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        display: "flex",
        alignItems: "center",
        gap: 14,
        width: "100%",
        padding: "14px 16px",
        borderRadius: 14,
        border: `1px solid ${isActive ? wf.color + "50" : active ? C.borderLit : C.border}`,
        background: isActive ? wf.dimColor : active ? C.panelHover : C.panel,
        cursor: "pointer",
        textAlign: "left",
        transition: "all 0.2s ease",
        position: "relative",
        overflow: "hidden",
      }}
    >
      {isActive && (
        <div
          style={{
            position: "absolute",
            left: 0,
            top: 0,
            bottom: 0,
            width: 3,
            background: wf.color,
            borderRadius: "0 2px 2px 0",
          }}
        />
      )}
      <span
        style={{
          fontSize: 22,
          width: 40,
          height: 40,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          borderRadius: 12,
          background: wf.dimColor,
          border: `1px solid ${wf.color}20`,
          flexShrink: 0,
        }}
      >
        {wf.icon}
      </span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div
          style={{
            fontFamily: FONT,
            fontWeight: 600,
            fontSize: 14,
            color: isActive ? C.text : C.textSoft,
            letterSpacing: "-0.01em",
          }}
        >
          {wf.label}
        </div>
        <div
          style={{
            fontFamily: FONT,
            fontSize: 12,
            color: C.textDim,
            marginTop: 2,
            whiteSpace: "nowrap",
            overflow: "hidden",
            textOverflow: "ellipsis",
          }}
        >
          {wf.description}
        </div>
      </div>
    </button>
  );
}

// ─── Preflight Checklist ─────────────────────────────────────────────

function PreflightChecklist({ checks }) {
  const [states, setStates] = useState(() => checks.map(() => false));

  const toggle = (i) => {
    setStates((s) => s.map((v, j) => (j === i ? !v : v)));
  };

  const allReady = states.every(Boolean);

  return (
    <div style={{ marginBottom: 16 }}>
      <div
        style={{
          fontFamily: MONO,
          fontSize: 11,
          color: C.textDim,
          textTransform: "uppercase",
          letterSpacing: "0.08em",
          marginBottom: 8,
        }}
      >
        Preflight checks
      </div>
      {checks.map((ch, i) => (
        <button
          key={i}
          onClick={() => toggle(i)}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            width: "100%",
            padding: "7px 0",
            background: "none",
            border: "none",
            cursor: "pointer",
            fontFamily: FONT,
            fontSize: 13,
            color: states[i] ? C.green : C.textSoft,
            transition: "color 0.15s",
            textAlign: "left",
          }}
        >
          <span
            style={{
              width: 18,
              height: 18,
              borderRadius: 6,
              border: `1.5px solid ${states[i] ? C.green : C.border}`,
              background: states[i] ? C.greenDim : "transparent",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: 11,
              transition: "all 0.15s",
              flexShrink: 0,
            }}
          >
            {states[i] ? "✓" : ""}
          </span>
          {ch}
        </button>
      ))}
      {!allReady && (
        <div
          style={{
            marginTop: 6,
            fontSize: 11,
            fontFamily: FONT,
            color: C.textDim,
            fontStyle: "italic",
          }}
        >
          Check all items to enable launch
        </div>
      )}
    </div>
  );
}

// ─── Detail Panel ────────────────────────────────────────────────────

function DetailPanel({ wf }) {
  const [inputValues, setInputValues] = useState({});
  const [status, setStatus] = useState("idle"); // idle | running | success | error
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    const defaults = {};
    wf.inputs.forEach((inp) => {
      defaults[inp.key] = inp.default;
    });
    setInputValues(defaults);
    setStatus("idle");
    setLogs([]);
  }, [wf.id]);

  const setInput = useCallback((key, val) => {
    setInputValues((p) => ({ ...p, [key]: val }));
  }, []);

  const simulateRun = useCallback(() => {
    setStatus("running");
    setLogs(["==> " + (wf.workflow ? "Dispatching workflow: " + wf.workflow : "Running: " + (wf.script || wf.label))]);

    const steps = [
      { delay: 400, msg: `==> Workflow: ${wf.label}` },
      { delay: 800, msg: `    Inputs: ${JSON.stringify(inputValues)}` },
      { delay: 1400, msg: "==> Validating secrets and permissions..." },
      { delay: 2200, msg: "✅ Secrets validated" },
      { delay: 2800, msg: "==> Executing workflow steps..." },
      ...(wf.id === "protect"
        ? inputValues.auto_discover
          ? [
              { delay: 3200, msg: "==> Auto-discover: scanning main (last 15 commits)..." },
              { delay: 3600, msg: "    Found 6 raw check(s)" },
              ...(inputValues.exclude_apps ? [{ delay: 3800, msg: "    ExcludeApps: removed 1 check(s) from " + inputValues.exclude_apps }] : []),
              { delay: 4000, msg: "    App: github-actions (id=15368) → 5 check(s)" },
              { delay: 4200, msg: inputValues.allow_list ? "    AllowList: " + inputValues.allow_list : "    AllowList: (none — all included)" },
              { delay: 4400, msg: inputValues.deny_list ? "    DenyList: " + inputValues.deny_list : "    DenyList: (none)" },
              { delay: 4600, msg: inputValues.use_checks_api !== false ? "    Format: checks[] with app_id (collision-safe)" : "    Format: contexts[] (legacy)" },
              { delay: 5000, msg: "    Staging:    ci / k8s-validate [github-actions]; ci / lockfiles [github-actions]; ci / test (local) [github-actions]" },
              { delay: 5200, msg: "    Production: ci / k8s-validate [github-actions]; ci / lockfiles [github-actions]; ci / test (local) [github-actions]" + (inputValues.production_extra ? "; " + inputValues.production_extra : "") },
              { delay: 5600, msg: "" },
              { delay: 5800, msg: "==> Protecting: staging" },
              { delay: 6200, msg: "✅ staging protected" },
              { delay: 6600, msg: "==> Protecting: production" },
              { delay: 7000, msg: "✅ production protected" },
            ]
          : [
              { delay: 3400, msg: "==> Protecting: staging" },
              { delay: 3800, msg: "    Required checks: ci / lockfiles; ci / k8s-validate" },
              { delay: 4400, msg: "✅ staging protected" },
              { delay: 4800, msg: "==> Protecting: production" },
              { delay: 5200, msg: "    Required checks: ci / lockfiles; ci / k8s-validate; argocd-healthcheck" },
              { delay: 5800, msg: "✅ production protected" },
            ]
        : wf.id === "protect-preview"
        ? [
            { delay: 3400, msg: "==> Scanning check contexts on " + (inputValues.scan_branch || "main") + "..." },
            ...(inputValues.exclude_apps ? [{ delay: 3600, msg: "    Excluding apps: " + inputValues.exclude_apps }] : []),
            { delay: 3800, msg: "    ci / lockfiles              github-actions    id=15368" },
            { delay: 4000, msg: "    ci / k8s-validate           github-actions    id=15368" },
            { delay: 4200, msg: "    ci / test (local)           github-actions    id=15368" },
            { delay: 4400, msg: "    ci / test (redis)           github-actions    id=15368" },
            { delay: 4600, msg: "    ci / kind-smoke             github-actions    id=15368" },
            { delay: 5000, msg: "==> DRY RUN: staging payload (" + (inputValues.use_checks_api !== false ? "checks[]" : "contexts[]") + ")" },
            { delay: 5400, msg: "==> DRY RUN: production payload generated" },
            { delay: 6000, msg: "📦 Artifact uploaded: branch-protection-preview" },
          ]
        : wf.id === "check-contexts"
        ? [
            { delay: 3200, msg: "==> Repo:   owner/QueenCalifia-CyberAI" },
            { delay: 3400, msg: "==> Branch: " + (inputValues.branch || "main") },
            { delay: 3600, msg: "==> Scanning last " + (inputValues.commits || "15") + " commit(s)..." },
            ...(inputValues.exclude_apps ? [{ delay: 3800, msg: "==> Excluding apps: " + inputValues.exclude_apps }] : []),
            { delay: 4200, msg: "" },
            { delay: 4400, msg: "  ci / k8s-validate       github-actions    id=15368" },
            { delay: 4600, msg: "  ci / kind-smoke         github-actions    id=15368" },
            { delay: 4800, msg: "  ci / lockfiles          github-actions    id=15368" },
            { delay: 5000, msg: "  ci / test (local)       github-actions    id=15368" },
            { delay: 5200, msg: "  ci / test (redis)       github-actions    id=15368" },
            { delay: 5400, msg: "" },
            { delay: 5600, msg: "── GitHub Apps detected ──" },
            { delay: 5800, msg: "  github-actions (app_id=15368) → 5 check(s)" },
            { delay: 6200, msg: "📦 Artifact uploaded: check-contexts-" + (inputValues.branch || "main") },
          ]
        : wf.id === "dns"
        ? [
            { delay: 3400, msg: `==> LB: resolving ingress controller...` },
            { delay: 4000, msg: `    LB address: a1b2c3.elb.amazonaws.com` },
            { delay: 4600, msg: `==> Host: ${inputValues.staging_host || "staging.example.com"}` },
            { delay: 5000, msg: "    DNS: CNAME → a1b2c3.elb.amazonaws.com" },
            { delay: 5400, msg: inputValues.strict_dns ? "  🔒 Strict: CNAME matches LB hostname" : "    (strict mode off)" },
            { delay: 5800, msg: "✅ OK via DNS" },
            { delay: 6200, msg: "✅ OK via LB" },
            { delay: 6600, msg: `==> Host: ${inputValues.prod_host || "app.example.com"}` },
            { delay: 7000, msg: "✅ OK via DNS" },
            { delay: 7400, msg: "✅ OK via LB" },
          ]
        : [
            { delay: 3400, msg: "==> Step 1/3 complete" },
            { delay: 4400, msg: "==> Step 2/3 complete" },
            { delay: 5400, msg: "==> Step 3/3 complete" },
          ]),
      { delay: 6000 + (wf.id === "dns" ? 2000 : 0), msg: `\n✅ ${wf.label} completed successfully` },
    ];

    steps.forEach(({ delay, msg }) => {
      setTimeout(() => setLogs((p) => [...p, msg]), delay);
    });

    setTimeout(
      () => setStatus("success"),
      steps[steps.length - 1].delay + 200
    );
  }, [wf, inputValues]);

  const statusColor =
    status === "running"
      ? C.amber
      : status === "success"
      ? C.green
      : status === "error"
      ? C.red
      : C.textDim;

  return (
    <div
      style={{
        flex: 1,
        padding: 28,
        overflowY: "auto",
        background: `radial-gradient(ellipse at 20% 0%, ${wf.dimColor} 0%, transparent 60%)`,
      }}
    >
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 6 }}>
        <span
          style={{
            fontSize: 32,
            width: 56,
            height: 56,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            borderRadius: 16,
            background: wf.dimColor,
            border: `1px solid ${wf.color}25`,
          }}
        >
          {wf.icon}
        </span>
        <div>
          <h2
            style={{
              fontFamily: FONT,
              fontWeight: 700,
              fontSize: 22,
              color: C.text,
              margin: 0,
              letterSpacing: "-0.02em",
            }}
          >
            {wf.label}
          </h2>
          <div
            style={{
              fontFamily: FONT,
              fontSize: 14,
              color: C.textSoft,
              marginTop: 2,
            }}
          >
            {wf.description}
          </div>
        </div>
      </div>

      {/* Workflow file badge */}
      <div style={{ marginBottom: 20, marginTop: 12 }}>
        {wf.workflow ? (
          <Badge color={wf.color}>
            <span style={{ opacity: 0.6 }}>.github/workflows/</span>
            {wf.workflow}
          </Badge>
        ) : wf.script ? (
          <Badge color={wf.color}>
            <span style={{ opacity: 0.6 }}>pwsh ./</span>
            {wf.script}
          </Badge>
        ) : null}
        <span style={{ marginLeft: 10 }}>
          <Badge color={CATEGORIES[wf.category]?.color}>
            {CATEGORIES[wf.category]?.label}
          </Badge>
        </span>
      </div>

      {/* Preflight */}
      <PreflightChecklist checks={wf.checks} />

      {/* Inputs */}
      {wf.inputs.length > 0 && (
        <div style={{ marginBottom: 20 }}>
          <div
            style={{
              fontFamily: MONO,
              fontSize: 11,
              color: C.textDim,
              textTransform: "uppercase",
              letterSpacing: "0.08em",
              marginBottom: 10,
            }}
          >
            Workflow inputs
          </div>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: wf.inputs.length > 2 ? "1fr 1fr" : "1fr",
              gap: 12,
            }}
          >
            {wf.inputs.map((inp) => (
              <div key={inp.key}>
                <label
                  style={{
                    display: "block",
                    fontFamily: FONT,
                    fontSize: 12,
                    color: C.textSoft,
                    marginBottom: 5,
                    fontWeight: 500,
                  }}
                >
                  {inp.label}
                </label>
                {inp.type === "text" ? (
                  <TextInput
                    value={inputValues[inp.key] ?? inp.default ?? ""}
                    onChange={(v) => setInput(inp.key, v)}
                    placeholder={inp.default}
                  />
                ) : inp.type === "select" ? (
                  <SelectInput
                    value={inputValues[inp.key] ?? inp.default}
                    onChange={(v) => setInput(inp.key, v)}
                    options={inp.options}
                  />
                ) : inp.type === "toggle" ? (
                  <ToggleInput
                    value={inputValues[inp.key] ?? inp.default}
                    onChange={(v) => setInput(inp.key, v)}
                    label=""
                  />
                ) : null}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Launch button */}
      <div style={{ display: "flex", alignItems: "center", gap: 14, marginTop: 4 }}>
        <button
          onClick={simulateRun}
          disabled={status === "running"}
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 8,
            padding: "11px 28px",
            borderRadius: 12,
            border: "none",
            background:
              status === "running"
                ? C.surface
                : `linear-gradient(135deg, ${wf.color}, ${wf.color}cc)`,
            color: status === "running" ? C.textDim : "#fff",
            fontFamily: FONT,
            fontWeight: 600,
            fontSize: 14,
            cursor: status === "running" ? "not-allowed" : "pointer",
            letterSpacing: "-0.01em",
            boxShadow:
              status === "running" ? "none" : `0 2px 16px ${wf.color}40`,
            transition: "all 0.2s ease",
          }}
        >
          {status === "running" ? (
            <>
              <Pulse color={C.amber} active /> Running…
            </>
          ) : (
            <>{wf.workflow ? "▶ Run workflow" : "▶ Run script"}</>
          )}
        </button>

        {status !== "idle" && (
          <Badge
            color={statusColor}
            bg={
              status === "success"
                ? C.greenDim
                : status === "error"
                ? C.redDim
                : C.amberDim
            }
          >
            <Pulse color={statusColor} active={status === "running"} />
            {status === "running"
              ? "in progress"
              : status === "success"
              ? "completed"
              : status === "error"
              ? "failed"
              : ""}
          </Badge>
        )}
      </div>

      {/* CLI equivalent */}
      {wf.id === "protect" && (
        <div
          style={{
            marginTop: 20,
            padding: 14,
            borderRadius: 10,
            background: C.void,
            border: `1px solid ${C.border}`,
          }}
        >
          <div
            style={{
              fontFamily: MONO,
              fontSize: 11,
              color: C.textDim,
              marginBottom: 6,
              textTransform: "uppercase",
              letterSpacing: "0.06em",
            }}
          >
            CLI equivalent
          </div>
          <code
            style={{
              fontFamily: MONO,
              fontSize: 12,
              color: C.accentBright,
              lineHeight: 1.7,
              wordBreak: "break-all",
            }}
          >
            {inputValues.auto_discover ? (
              <>
                pwsh ./scripts/github/protect_branches.ps1 \<br />
                &nbsp;&nbsp;-AutoDiscover \<br />
                &nbsp;&nbsp;-Branches @("{(inputValues.branches || "staging,production").split(",").join('","')}") \<br />
                &nbsp;&nbsp;-Approvals {inputValues.approvals || 2}
                {inputValues.exclude_apps ? <><br />&nbsp;&nbsp;-ExcludeApps @("{inputValues.exclude_apps.split(",").join('","')}")</> : null}
                {inputValues.allow_list ? <><br />&nbsp;&nbsp;-AllowList @("{inputValues.allow_list.split(",").join('","')}")</> : null}
                {inputValues.deny_list ? <><br />&nbsp;&nbsp;-DenyList @("{inputValues.deny_list.split(",").join('","')}")</> : null}
                {inputValues.production_extra ? <><br />&nbsp;&nbsp;-ProductionExtra @("{inputValues.production_extra.split(",").join('","')}")</> : null}
                {inputValues.use_checks_api === false ? <><br />&nbsp;&nbsp;-UseChecksApi $false</> : null}
                {inputValues.dry_run ? <><br />&nbsp;&nbsp;-DryRun</> : null}
              </>
            ) : (
              <>
                pwsh ./scripts/github/protect_branches.ps1 \<br />
                &nbsp;&nbsp;-Branches @("{(inputValues.branches || "staging,production").split(",").join('","')}") \<br />
                &nbsp;&nbsp;-Approvals {inputValues.approvals || 2}
                {inputValues.use_checks_api === false ? <><br />&nbsp;&nbsp;-UseChecksApi $false</> : null}
                {inputValues.dry_run ? <><br />&nbsp;&nbsp;-DryRun</> : null}
              </>
            )}
          </code>
        </div>
      )}

      {wf.id === "check-contexts" && (
        <div
          style={{
            marginTop: 20,
            padding: 14,
            borderRadius: 10,
            background: C.void,
            border: `1px solid ${C.border}`,
          }}
        >
          <div
            style={{
              fontFamily: MONO,
              fontSize: 11,
              color: C.textDim,
              marginBottom: 6,
              textTransform: "uppercase",
              letterSpacing: "0.06em",
            }}
          >
            CLI equivalent
          </div>
          <code
            style={{
              fontFamily: MONO,
              fontSize: 12,
              color: C.accentBright,
              lineHeight: 1.7,
              wordBreak: "break-all",
            }}
          >
            pwsh ./scripts/github/print_check_contexts.ps1 \<br />
            &nbsp;&nbsp;-Branch {inputValues.branch || "main"} \<br />
            &nbsp;&nbsp;-Commits {inputValues.commits || "15"}
            {inputValues.exclude_apps ? <><br />&nbsp;&nbsp;-ExcludeApps @("{inputValues.exclude_apps.split(",").join('","')}")</> : null}
          </code>
        </div>
      )}

      {wf.id === "protect-preview" && (
        <div
          style={{
            marginTop: 20,
            padding: 14,
            borderRadius: 10,
            background: C.greenDim,
            border: `1px solid ${C.green}25`,
          }}
        >
          <div
            style={{
              fontFamily: FONT,
              fontSize: 13,
              color: C.green,
              marginBottom: 4,
              fontWeight: 600,
            }}
          >
            💡 Review-before-apply workflow
          </div>
          <div
            style={{
              fontFamily: FONT,
              fontSize: 12,
              color: C.textSoft,
              lineHeight: 1.6,
            }}
          >
            This runs <code style={{ fontFamily: MONO, fontSize: 11, color: C.accentBright }}>protect_branches.ps1 -DryRun</code> and
            uploads the JSON payloads as a downloadable artifact.
            Scans <code style={{ fontFamily: MONO, fontSize: 11, color: C.accentBright }}>{inputValues.scan_branch || "main"}</code> for
            check contexts with app metadata.
            {inputValues.use_checks_api !== false ? " Payloads use collision-safe checks[] format with app_id." : " Using legacy contexts[] format."}
            {inputValues.exclude_apps ? ` Excluding apps: ${inputValues.exclude_apps}.` : ""}
          </div>
        </div>
      )}

      {/* Logs */}
      <LogViewer lines={logs} />
    </div>
  );
}

// ─── Topology visualization ──────────────────────────────────────────

function TopologyMini() {
  return (
    <div
      style={{
        padding: 16,
        borderRadius: 14,
        background: C.panel,
        border: `1px solid ${C.border}`,
      }}
    >
      <div
        style={{
          fontFamily: MONO,
          fontSize: 11,
          color: C.textDim,
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          marginBottom: 12,
        }}
      >
        Pipeline topology
      </div>
      <svg viewBox="0 0 260 60" style={{ width: "100%", height: 60 }}>
        {/* Connections */}
        <line x1="55" y1="30" x2="85" y2="30" stroke={C.borderLit} strokeWidth="1.5" strokeDasharray="4 3" />
        <line x1="155" y1="30" x2="185" y2="30" stroke={C.borderLit} strokeWidth="1.5" strokeDasharray="4 3" />

        {/* CI */}
        <rect x="2" y="12" width="50" height="36" rx="8" fill={C.surface} stroke={C.borderLit} strokeWidth="1" />
        <text x="27" y="34" textAnchor="middle" fill={C.textSoft} fontSize="10" fontFamily={MONO}>CI</text>

        {/* Staging */}
        <rect x="88" y="12" width="64" height="36" rx="8" fill={C.surface} stroke={C.green + "50"} strokeWidth="1" />
        <text x="120" y="34" textAnchor="middle" fill={C.green} fontSize="10" fontFamily={MONO}>staging</text>

        {/* Prod */}
        <rect x="188" y="12" width="64" height="36" rx="8" fill={C.surface} stroke={C.amber + "50"} strokeWidth="1" />
        <text x="220" y="34" textAnchor="middle" fill={C.amber} fontSize="10" fontFamily={MONO}>prod</text>
      </svg>
    </div>
  );
}

// ─── Main App ────────────────────────────────────────────────────────

export default function App() {
  const [selected, setSelected] = useState("protect");
  const [filter, setFilter] = useState("all");
  const [now, setNow] = useState(new Date());

  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 30000);
    return () => clearInterval(t);
  }, []);

  const filtered =
    filter === "all"
      ? WORKFLOWS
      : WORKFLOWS.filter((w) => w.category === filter);

  const activeWf = WORKFLOWS.find((w) => w.id === selected) || WORKFLOWS[0];

  return (
    <div
      style={{
        minHeight: "100vh",
        background: C.bg,
        color: C.text,
        fontFamily: FONT,
        display: "flex",
        flexDirection: "column",
      }}
    >
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,400;0,9..40,500;0,9..40,600;0,9..40,700;1,9..40,400&family=JetBrains+Mono:wght@400;500&display=swap');
        @keyframes qcPulse {
          0%, 100% { opacity: 1; transform: scale(1); }
          50% { opacity: 0.4; transform: scale(0.85); }
        }
        @keyframes qcFadeIn {
          from { opacity: 0; transform: translateY(6px); }
          to { opacity: 1; transform: translateY(0); }
        }
        * { box-sizing: border-box; }
        body { margin: 0; background: ${C.bg}; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: ${C.border}; border-radius: 3px; }
        ::selection { background: ${C.accent}40; }
      `}</style>

      {/* ── Top bar ─────────────────────────────────────────── */}
      <header
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "12px 24px",
          borderBottom: `1px solid ${C.border}`,
          background: C.panel,
          flexShrink: 0,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span
            style={{
              fontSize: 20,
              width: 36,
              height: 36,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              borderRadius: 10,
              background: `linear-gradient(135deg, ${C.accent}22, ${C.purple}18)`,
              border: `1px solid ${C.borderLit}`,
            }}
          >
            👑
          </span>
          <div>
            <span
              style={{
                fontWeight: 700,
                fontSize: 15,
                letterSpacing: "-0.02em",
                color: C.text,
              }}
            >
              QueenCalifia
            </span>
            <span
              style={{
                marginLeft: 8,
                fontFamily: MONO,
                fontSize: 11,
                color: C.textDim,
                padding: "2px 8px",
                borderRadius: 6,
                background: C.surface,
                border: `1px solid ${C.border}`,
              }}
            >
              DevOps
            </span>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span
            style={{
              fontFamily: MONO,
              fontSize: 11,
              color: C.textDim,
            }}
          >
            {now.toLocaleString("en-US", {
              hour: "2-digit",
              minute: "2-digit",
              timeZoneName: "short",
            })}
          </span>
          <Pulse color={C.green} active />
          <span style={{ fontSize: 11, color: C.green, fontFamily: MONO }}>
            operational
          </span>
        </div>
      </header>

      {/* ── Body ────────────────────────────────────────────── */}
      <div style={{ display: "flex", flex: 1, minHeight: 0 }}>
        {/* Sidebar */}
        <aside
          style={{
            width: 310,
            flexShrink: 0,
            borderRight: `1px solid ${C.border}`,
            display: "flex",
            flexDirection: "column",
            background: C.panel,
            overflowY: "auto",
          }}
        >
          {/* Category filters */}
          <div
            style={{
              display: "flex",
              gap: 6,
              padding: "14px 16px 8px",
              flexWrap: "wrap",
            }}
          >
            {[{ key: "all", label: "All" }, ...Object.entries(CATEGORIES).map(([k, v]) => ({ key: k, label: v.label, color: v.color }))].map(
              (cat) => (
                <button
                  key={cat.key}
                  onClick={() => setFilter(cat.key)}
                  style={{
                    padding: "4px 12px",
                    borderRadius: 99,
                    border: `1px solid ${filter === cat.key ? (cat.color || C.borderHot) : C.border}`,
                    background:
                      filter === cat.key
                        ? (cat.color || C.accent) + "15"
                        : "transparent",
                    color: filter === cat.key ? (cat.color || C.accentBright) : C.textDim,
                    fontFamily: FONT,
                    fontSize: 12,
                    fontWeight: 500,
                    cursor: "pointer",
                    transition: "all 0.15s",
                  }}
                >
                  {cat.label}
                </button>
              )
            )}
          </div>

          {/* Workflow cards */}
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              gap: 6,
              padding: "8px 12px",
              flex: 1,
            }}
          >
            {filtered.map((wf) => (
              <WorkflowCard
                key={wf.id}
                wf={wf}
                isActive={selected === wf.id}
                onSelect={() => setSelected(wf.id)}
              />
            ))}
          </div>

          {/* Topology */}
          <div style={{ padding: "12px 12px 16px" }}>
            <TopologyMini />
          </div>
        </aside>

        {/* Detail */}
        <main
          style={{
            flex: 1,
            minWidth: 0,
            display: "flex",
            flexDirection: "column",
            animation: "qcFadeIn 0.25s ease",
          }}
          key={activeWf.id}
        >
          <DetailPanel wf={activeWf} />
        </main>
      </div>
    </div>
  );
}
