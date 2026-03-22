import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Counter, Trend } from 'k6/metrics';

const API_BASE = (__ENV.QC_API_BASE || 'http://localhost:5000').replace(/\/+$/, '');
const API_KEY = __ENV.QC_API_KEY || '';
const ENABLE_SCAN = (__ENV.QC_K6_ENABLE_SCAN || '1') === '1';
const EXPECT_BUDGET_HEADERS = (__ENV.QC_K6_EXPECT_BUDGET_HEADERS || '1') === '1';
const REPORT_DIR = (__ENV.QC_K6_REPORT_DIR || '/output').replace(/\/+$/, '');

const VUS = parseInt(__ENV.QC_K6_VUS || '20', 10);
const DURATION = __ENV.QC_K6_DURATION || '30s';

/** Full suite: exercise the same GET/POST mix as scripts/qc_perpetual_learner.py */
const FULL_SUITE = (__ENV.QC_K6_FULL_SUITE || '0') === '1';
const SAMPLES_PER_ITER = parseInt(__ENV.QC_K6_SAMPLES_PER_ITER || '12', 10);
const ENABLE_POSTS = (__ENV.QC_K6_ENABLE_POSTS || '0') === '1';
const ENABLE_CHAT = (__ENV.QC_K6_ENABLE_CHAT || '0') === '1';
const ENABLE_HEAVY = (__ENV.QC_K6_ENABLE_HEAVY || '0') === '1';
const SCAN_TARGET = (__ENV.QC_K6_SCAN_TARGET || '10.0.0.1').trim();

const P95_MS = parseInt(__ENV.QC_K6_P95_MS || (FULL_SUITE ? '12000' : '1500'), 10);
const HAS_API_KEY = Boolean(API_KEY && API_KEY.trim());
/** k6 counts 4xx as http_req_failed — without a key, almost every call is a "failure". */
const HTTP_FAIL_RATE = parseFloat(
  __ENV.QC_K6_HTTP_FAIL_RATE || (FULL_SUITE ? (HAS_API_KEY ? '0.25' : '0.99') : HAS_API_KEY ? '0.05' : '0.99'),
  10,
);
const ENFORCE_HTTP_FAIL = (__ENV.QC_K6_ENFORCE_HTTP_FAIL || '0') === '1';

const budgetHeadersOk = new Rate('qc_budget_headers_ok');
const response429 = new Counter('qc_responses_429');
const scanEnqueued = new Counter('qc_scan_enqueued');
const scan429 = new Counter('qc_scan_429');
const scanEnqueueMs = new Trend('qc_scan_enqueue_ms');
const fullGetChecks = new Rate('qc_full_get_ok');
const fullPostChecks = new Rate('qc_full_post_ok');

/**
 * Keep in sync with scripts/qc_perpetual_learner._all_get_paths() (minus admin keys).
 */
const GET_PATHS = [
  '/healthz',
  '/readyz',
  '/api/health',
  '/api/ready',
  '/api/training/readiness',
  '/api/training/capabilities-catalog',
  '/api/config',
  '/api/mesh/status',
  '/api/threats/active',
  '/api/dashboard',
  '/api/iocs',
  '/api/vulns/status',
  '/api/vulns/remediation',
  '/api/incidents',
  '/api/ir/status',
  '/api/audit/log',
  '/api/audit/integrity',
  '/api/chat/memories',
  '/api/forecast/portfolio/list',
  '/api/market/sources',
  '/api/market/snapshot?asset_type=crypto&symbol=BTC-USD',
  '/api/market/snapshot?asset_type=crypto&symbol=ETH-USD',
  '/api/market/snapshot?asset_type=crypto&symbol=SOL-USD',
  '/api/market/snapshot?asset_type=stock&symbol=AAPL',
  '/api/market/snapshot?asset_type=stock&symbol=MSFT',
  '/api/market/snapshot?asset_type=stock&symbol=GOOGL',
  '/api/market/snapshot?asset_type=stock&symbol=NVDA',
  '/api/market/snapshot?asset_type=forex&symbol=USD%2FEUR',
  '/api/market/fred/UNRATE',
  '/api/market/fred/CPIAUCSL',
  '/api/market/fred/GDP',
  '/api/identity/state',
  '/api/identity/memory/pending',
  '/api/identity/reflections/pending',
  '/api/identity/rules/pending',
  '/api/identity/self-notes/pending',
  '/api/v1/predictor/predictions',
  '/api/v1/predictor/status',
  '/api/v1/predictor/landscape',
  '/api/v1/telemetry/summary',
  '/api/v1/scanner/status',
  '/api/v1/scanner/findings',
  '/api/v1/scanner/baselines',
  '/api/v1/remediate/status',
  '/api/v1/remediate/log',
  '/api/v1/evolution/status',
  '/api/v1/evolution/health',
  '/api/v1/evolution/intelligence',
  '/api/v1/evolution/baselines',
  '/api/v1/evolution/storage',
  '/api/v1/evolution/backups',
  '/api/v1/evolution/evolutions',
  '/api/v1/quantum/readiness',
  '/api/v1/quantum/vault',
  '/api/v1/threat-intel/status',
  '/api/v1/threat-intel/feeds',
  '/api/v1/threat-intel/indicators',
  '/api/v1/threat-intel/cves/critical',
  '/api/v1/threat-intel/actors',
  '/api/v1/purple-team/heatmap',
  '/api/v1/blue-team/rules',
  '/api/v1/blue-team/iocs',
  '/api/v1/blue-team/soar/playbooks',
  '/api/v1/telemetry/advanced/status',
  '/api/v1/telemetry/advanced/beacons',
  '/api/v1/telemetry/advanced/risk-map',
  '/api/v1/telemetry/advanced/graph',
  '/api/v1/telemetry/advanced/health',
  '/metrics',
];

const thresholdObj = {
  http_req_duration: [`p(95)<${P95_MS}`],
  qc_budget_headers_ok: EXPECT_BUDGET_HEADERS ? ['rate>0.98'] : [],
};
if (HAS_API_KEY || ENFORCE_HTTP_FAIL) {
  thresholdObj.http_req_failed = [`rate<${HTTP_FAIL_RATE}`];
}
if (FULL_SUITE) {
  thresholdObj.qc_full_get_ok = ['rate>0.85'];
}

export const options = {
  vus: Number.isFinite(VUS) ? VUS : 20,
  duration: DURATION,
  thresholds: thresholdObj,
};

function makeRequestId() {
  return `k6-${__VU}-${__ITER}-${Date.now()}`;
}

function headers() {
  const h = { 'Content-Type': 'application/json' };
  if (API_KEY) h['X-QC-API-Key'] = API_KEY;
  h['X-Request-ID'] = makeRequestId();
  return h;
}

/** Treat like perpetual learner: endpoint reached without hard 5xx storm */
function statusOkGet(s) {
  return [200, 204, 400, 401, 403, 404, 429, 503].includes(s);
}

function statusOkPost(s) {
  return [200, 202, 400, 401, 403, 429, 503].includes(s);
}

function recordBudgetHeaders(res) {
  if (!EXPECT_BUDGET_HEADERS) return;
  if (res.status === 401) return;
  const ok = Boolean(res.headers['X-Budget-Capacity'] && res.headers['X-Budget-Remaining']);
  budgetHeadersOk.add(ok);
}

function recordStatus(res) {
  if (res.status === 429) response429.add(1);
}

function samplePaths(n) {
  const shuffled = [...GET_PATHS].sort(() => Math.random() - 0.5);
  const take = Math.max(1, Math.min(n, shuffled.length));
  return shuffled.slice(0, take);
}

function maybeScan() {
  if (!ENABLE_SCAN || Math.random() >= 0.15) return;
  group('scan enqueue', () => {
    const payload = JSON.stringify({
      target: SCAN_TARGET,
      scan_type: 'quick',
      async: true,
    });
    const res = http.post(`${API_BASE}/api/vulns/scan`, payload, { headers: headers(), timeout: '60s' });
    scanEnqueueMs.add(res.timings.duration);
    recordBudgetHeaders(res);
    recordStatus(res);
    if ([200, 202].includes(res.status)) scanEnqueued.add(1);
    if (res.status === 429) scan429.add(1);
    check(res, { 'scan 200|202|401|429': (r) => [200, 202, 401, 429].includes(r.status) });
  });
}

function maybePosts() {
  if (!ENABLE_POSTS || Math.random() >= 0.12) return;
  const roll = Math.random();
  let res;
  if (roll < 0.2) {
    const sip = `10.${__VU % 255}.${__ITER % 255}.${1 + (__ITER % 200)}`;
    const dip = `10.${(__VU + 1) % 255}.${__ITER % 255}.${1 + ((__ITER + 5) % 200)}`;
    res = http.post(
      `${API_BASE}/api/events/ingest`,
      JSON.stringify({
        source_ip: sip,
        dest_ip: dip,
        source_port: 1024 + (__ITER % 60000),
        dest_port: [80, 443, 53][__ITER % 3],
        protocol: 'tcp',
        event_type: 'flow',
        raw_data: { k6: true, vu: __VU },
      }),
      { headers: headers(), timeout: '45s' },
    );
  } else if (roll < 0.35) {
    res = http.post(
      `${API_BASE}/api/forecast/run`,
      JSON.stringify({ experiment_type: 'regime_detection', parameters: { lookback_days: 30 } }),
      { headers: headers(), timeout: '90s' },
    );
  } else if (roll < 0.5) {
    res = http.post(
      `${API_BASE}/api/v1/predictor/analyze`,
      JSON.stringify({
        type: 'network',
        source: `10.0.0.${1 + (__VU % 200)}`,
        data: { severity: 'low', k6: true },
      }),
      { headers: headers(), timeout: '60s' },
    );
  } else if (roll < 0.7) {
    res = http.post(
      `${API_BASE}/api/v1/evolution/learn`,
      JSON.stringify({ scan_report: { k6: true, hosts: [] } }),
      { headers: headers(), timeout: '60s' },
    );
  } else if (roll < 0.85) {
    res = http.post(`${API_BASE}/api/v1/evolution/evolve`, JSON.stringify({}), {
      headers: headers(),
      timeout: '60s',
    });
  } else {
    res = http.post(
      `${API_BASE}/api/v1/telemetry/advanced/process`,
      JSON.stringify({ stream: 'network', event: { id: `k6-${__VU}-${__ITER}`, k6: true } }),
      { headers: headers(), timeout: '60s' },
    );
  }
  recordBudgetHeaders(res);
  recordStatus(res);
  const ok = statusOkPost(res.status);
  fullPostChecks.add(ok);
  check(res, { 'post acceptable': () => ok });
}

function maybeChat() {
  if (!ENABLE_CHAT || Math.random() >= 0.08) return;
  const modes = ['cyber', 'research', 'lab'];
  const mode = modes[__ITER % modes.length];
  const payload = JSON.stringify({
    message: 'Stress ping: one sentence on operational posture.',
    session_id: `k6-${__VU}-${__ITER}`,
    user_id: 'k6-stress',
    mode,
  });
  const res = http.post(`${API_BASE}/api/chat/`, payload, { headers: headers(), timeout: '120s' });
  recordBudgetHeaders(res);
  recordStatus(res);
  let parsed = {};
  try {
    parsed = res.json();
  } catch (_) {}
  const ok = res.status === 200 && Boolean(parsed && parsed.reply);
  fullPostChecks.add(ok || statusOkPost(res.status));
  check(res, { 'chat 200 w reply or acceptable error': () => ok || statusOkPost(res.status) });
}

function maybeHeavy() {
  if (!ENABLE_HEAVY || Math.random() >= 0.04) return;
  if (Math.random() < 0.5) {
    const res = http.post(
      `${API_BASE}/api/vulns/scan`,
      JSON.stringify({
        target: SCAN_TARGET,
        scan_type: 'quick',
        mode: 'async',
        acknowledge_authorized: true,
      }),
      { headers: headers(), timeout: '60s' },
    );
    recordBudgetHeaders(res);
    recordStatus(res);
    check(res, { 'heavy scan': (r) => [200, 202, 401, 403, 429].includes(r.status) });
  } else {
    const res = http.post(
      `${API_BASE}/api/v1/one-click/scan-and-fix`,
      JSON.stringify({
        target: SCAN_TARGET,
        scan_type: 'quick',
        auto_approve: false,
        acknowledge_authorized: true,
      }),
      { headers: headers(), timeout: '180s' },
    );
    recordBudgetHeaders(res);
    recordStatus(res);
    check(res, { 'one-click': (r) => [200, 401, 403, 503].includes(r.status) });
  }
}

export default function () {
  if (!FULL_SUITE) {
    group('health', () => {
      const res = http.get(`${API_BASE}/api/health`, { headers: headers() });
      recordBudgetHeaders(res);
      recordStatus(res);
      check(res, { 'health 200|401|429': (r) => [200, 401, 429].includes(r.status) });
    });

    group('dashboard', () => {
      const res = http.get(`${API_BASE}/api/dashboard`, { headers: headers() });
      recordBudgetHeaders(res);
      recordStatus(res);
      check(res, { 'dashboard 200|401|429': (r) => [200, 401, 429].includes(r.status) });
    });

    group('incidents', () => {
      const res = http.get(`${API_BASE}/api/incidents`, { headers: headers() });
      recordBudgetHeaders(res);
      recordStatus(res);
      check(res, { 'incidents 200|401|429': (r) => [200, 401, 429].includes(r.status) });
    });

    maybeScan();
    sleep(0.2);
    return;
  }

  // --- Full stress: breadth across QC OS (identity, market, intel, evolution, etc.) ---
  group('health', () => {
    const res = http.get(`${API_BASE}/api/health`, { headers: headers(), timeout: '30s' });
    recordBudgetHeaders(res);
    recordStatus(res);
    check(res, { 'health': (r) => statusOkGet(r.status) });
  });

  group('dashboard', () => {
    const res = http.get(`${API_BASE}/api/dashboard`, { headers: headers(), timeout: '45s' });
    recordBudgetHeaders(res);
    recordStatus(res);
    check(res, { 'dashboard': (r) => statusOkGet(r.status) });
  });

  group('incidents', () => {
    const res = http.get(`${API_BASE}/api/incidents`, { headers: headers(), timeout: '45s' });
    recordBudgetHeaders(res);
    recordStatus(res);
    check(res, { 'incidents': (r) => statusOkGet(r.status) });
  });

  const paths = samplePaths(SAMPLES_PER_ITER);
  for (const path of paths) {
    const label = path.length > 48 ? `${path.slice(0, 45)}...` : path;
    group(`GET ${label}`, () => {
      const res = http.get(`${API_BASE}${path}`, { headers: headers(), timeout: '45s' });
      recordBudgetHeaders(res);
      recordStatus(res);
      const ok = statusOkGet(res.status);
      fullGetChecks.add(ok);
      check(res, { 'get ok': () => ok });
    });
  }

  maybeScan();
  maybePosts();
  maybeChat();
  maybeHeavy();

  sleep(FULL_SUITE ? 0.05 : 0.2);
}

function safeGet(metric, key, fallback = null) {
  try {
    return metric && metric.values && metric.values[key] !== undefined ? metric.values[key] : fallback;
  } catch (_) {
    return fallback;
  }
}

export function handleSummary(data) {
  const durMs = data && data.state ? data.state.testRunDurationMs : 0;
  const durS = durMs ? durMs / 1000 : 0.0001;

  const httpReqs = safeGet(data.metrics.http_reqs, 'count', 0);
  const p95 = safeGet(data.metrics.http_req_duration, 'p(95)', null);

  const cnt429 = safeGet(data.metrics.qc_responses_429, 'count', 0);
  const rate429 = httpReqs ? cnt429 / httpReqs : 0;

  const enq = safeGet(data.metrics.qc_scan_enqueued, 'count', 0);
  const enqThroughput = enq / durS;

  const budgetOkRate = safeGet(data.metrics.qc_budget_headers_ok, 'rate', null);
  const scanEnqP95 = safeGet(data.metrics.qc_scan_enqueue_ms, 'p(95)', null);

  const fullGetRate = safeGet(data.metrics.qc_full_get_ok, 'rate', null);
  const fullPostRate = safeGet(data.metrics.qc_full_post_ok, 'rate', null);

  const report = {
    started_at: data.state ? data.state.testRunStartTime : null,
    duration_seconds: durS,
    vus: options.vus,
    full_suite: FULL_SUITE,
    samples_per_iter: SAMPLES_PER_ITER,
    p95_ms: p95,
    http_requests: httpReqs,
    http_429_count: cnt429,
    http_429_rate: rate429,
    scan_enqueued: enq,
    scan_enqueue_throughput_per_s: enqThroughput,
    scan_enqueue_p95_ms: scanEnqP95,
    budget_headers_ok_rate: budgetOkRate,
    full_get_ok_rate: fullGetRate,
    full_post_ok_rate: fullPostRate,
  };

  const lines = [
    `QueenCalifia k6 Summary`,
    `- mode: ${FULL_SUITE ? 'FULL (all routes sample)' : 'smoke'}`,
    `- duration: ${durS.toFixed(1)}s | vus: ${options.vus}`,
    `- http p95: ${p95 !== null ? `${p95.toFixed(1)}ms` : 'n/a'}`,
    `- 429 rate: ${(rate429 * 100).toFixed(2)}% (${cnt429}/${httpReqs})`,
    `- scan enqueue: ${enq} (${enqThroughput.toFixed(2)}/s) | p95: ${scanEnqP95 !== null ? `${scanEnqP95.toFixed(1)}ms` : 'n/a'}`,
    EXPECT_BUDGET_HEADERS ? `- budget headers ok rate: ${budgetOkRate !== null ? (budgetOkRate * 100).toFixed(2) + '%' : 'n/a'}` : `- budget headers: not checked`,
    FULL_SUITE
      ? `- full GET ok rate: ${fullGetRate !== null ? (fullGetRate * 100).toFixed(2) + '%' : 'n/a'} | POST/chat ok rate: ${fullPostRate !== null ? (fullPostRate * 100).toFixed(2) + '%' : 'n/a'}`
      : ``,
    ``,
  ].join('\n');

  return {
    stdout: lines,
    [`${REPORT_DIR}/summary.json`]: JSON.stringify(report, null, 2) + '\n',
    [`${REPORT_DIR}/summary.txt`]: lines,
  };
}
