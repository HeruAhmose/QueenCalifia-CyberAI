/**
 * Normalize remediation API payloads (vuln engine vs AutoRemediation) for dashboard UI.
 * @param {object|null} plan
 * @param {string} targetFallback
 */
export function normalizeRemediationPlan(plan, targetFallback = "") {
  if (!plan) return null;
  const rawPriority = plan.priority_actions;
  const rawActions = plan.actions;
  const hasPriority = Array.isArray(rawPriority) && rawPriority.length > 0;
  const hasActions = Array.isArray(rawActions) && rawActions.length > 0;

  const sevOf = (a) => {
    const s = String(a?.severity ?? "").toUpperCase();
    if (s) return s;
    return String(a?.risk_level ?? "").toUpperCase();
  };

  if (hasPriority) {
    const pa = rawPriority;
    const summaryFromActions = {
      critical: pa.filter((a) => sevOf(a) === "CRITICAL").length,
      high: pa.filter((a) => sevOf(a) === "HIGH").length,
      medium: pa.filter((a) => sevOf(a) === "MEDIUM").length,
      low: pa.filter((a) => {
        const s = sevOf(a);
        return s === "LOW" || s === "NONE" || s === "INFO" || !s;
      }).length,
    };
    const totalVen = Math.max(
      pa.length,
      Number(plan.total_vulnerabilities) || 0,
      Number(plan.total_actions) || 0
    );
    return {
      ...plan,
      priority_actions: pa,
      total_vulnerabilities: totalVen,
      total_actions: Number(plan.total_actions) || pa.length,
      summary: summaryFromActions,
    };
  }

  const actions = hasActions ? rawActions : [];
  const priority_actions = actions.map((action, index) => ({
    priority: index + 1,
    action_id: action.action_id,
    vuln_id: action.finding_id || action.action_id || `action-${index + 1}`,
    cve_id: action.cve_id || "",
    title: action.title || `Remediation action ${index + 1}`,
    severity: sevOf(action) || "LOW",
    cvss_score: action.cvss_score ?? null,
    affected_asset: plan.target_host || targetFallback || action.affected_asset || "",
    remediation:
      action.description ||
      action.remediation ||
      (Array.isArray(action.commands) ? action.commands.slice(0, 2).join(" ; ") : ""),
    category: action.category || "other",
    commands: Array.isArray(action.commands) ? action.commands : [],
    rollback_commands: Array.isArray(action.rollback_commands) ? action.rollback_commands : [],
  }));

  return {
    plan_id: plan.plan_id || `derived-${Date.now()}`,
    generated_at: plan.generated_at || new Date().toISOString(),
    total_vulnerabilities: Number(plan.total_vulnerabilities ?? plan.total_actions ?? priority_actions.length),
    total_actions: Number(plan.total_actions ?? priority_actions.length),
    target_host: plan.target_host || targetFallback || "",
    summary: {
      critical: priority_actions.filter((a) => a.severity === "CRITICAL").length,
      high: priority_actions.filter((a) => a.severity === "HIGH").length,
      medium: priority_actions.filter((a) => a.severity === "MEDIUM").length,
      low: priority_actions.filter(
        (a) => !["CRITICAL", "HIGH", "MEDIUM"].includes(a.severity)
      ).length,
    },
    priority_actions,
  };
}

function _findingSeverityUpper(f) {
  const s = f?.severity;
  if (s != null && s !== "") {
    if (typeof s === "number") {
      const map = { 4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "LOW" };
      return map[s] || "";
    }
    return String(s).toUpperCase();
  }
  return String(f?.risk_level || "").toUpperCase();
}

/**
 * Align severity buckets and totals with exported findings (source of truth for the UI).
 * Also handles missing `findings` when `vulnerabilities_found` is non-zero (async/Celery edge cases).
 * @param {object|null} raw
 */
export function enrichScanResultForUi(raw) {
  if (!raw || typeof raw !== "object") return raw;
  const findings = Array.isArray(raw.findings) ? raw.findings : [];

  const countNamed = (name) => findings.filter((f) => _findingSeverityUpper(f) === name).length;
  const c = countNamed("CRITICAL");
  const h = countNamed("HIGH");
  const m = countNamed("MEDIUM");
  const lowNamed = countNamed("LOW");
  const noneC = countNamed("NONE");
  const infoC = countNamed("INFO");
  const assigned = c + h + m + lowNamed + noneC + infoC;
  const remainder = Math.max(0, findings.length - assigned);
  const lowBucket = lowNamed + noneC + infoC + remainder;

  if (findings.length > 0) {
    return {
      ...raw,
      critical_count: c,
      high_count: h,
      medium_count: m,
      low_count: lowBucket,
      vulnerabilities_found: raw.vulnerabilities_found ?? findings.length,
      summary: { critical: c, high: h, medium: m, low: lowBucket },
    };
  }

  const vf = Number(raw.vulnerabilities_found) || 0;
  const sum =
    (Number(raw.critical_count) || 0) +
    (Number(raw.high_count) || 0) +
    (Number(raw.medium_count) || 0) +
    (Number(raw.low_count) || 0);

  if (sum === 0 && vf > 0) {
    return {
      ...raw,
      low_count: vf,
      vulnerabilities_found: vf,
      summary: { critical: 0, high: 0, medium: 0, low: vf },
    };
  }

  return raw;
}
