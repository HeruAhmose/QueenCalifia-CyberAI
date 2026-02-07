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

const budgetHeadersOk = new Rate('qc_budget_headers_ok');
const response429 = new Counter('qc_responses_429');
const scanEnqueued = new Counter('qc_scan_enqueued');
const scan429 = new Counter('qc_scan_429');
const scanEnqueueMs = new Trend('qc_scan_enqueue_ms');

export const options = {
  vus: Number.isFinite(VUS) ? VUS : 20,
  duration: DURATION,
  thresholds: {
    http_req_failed: ['rate<0.05'], // allow some 429s under budget/limits
    http_req_duration: ['p(95)<1500'],
    qc_budget_headers_ok: EXPECT_BUDGET_HEADERS ? ['rate>0.98'] : [],
  },
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

function recordBudgetHeaders(res) {
  if (!EXPECT_BUDGET_HEADERS) return;
  if (res.status === 401) return; // unauth'd responses may not include budgeting
  const ok = Boolean(res.headers['X-Budget-Capacity'] && res.headers['X-Budget-Remaining']);
  budgetHeadersOk.add(ok);
}

function recordStatus(res) {
  if (res.status === 429) response429.add(1);
}

export default function () {
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

  if (ENABLE_SCAN && Math.random() < 0.15) {
    group('scan enqueue', () => {
      const payload = JSON.stringify({
        target: '10.0.0.1',   // allowlisted by default compose
        scan_type: 'quick',
        async: true,
      });
      const res = http.post(`${API_BASE}/api/vulns/scan`, payload, { headers: headers() });
      scanEnqueueMs.add(res.timings.duration);
      recordBudgetHeaders(res);
      recordStatus(res);

      if ([200, 202].includes(res.status)) scanEnqueued.add(1);
      if (res.status === 429) scan429.add(1);

      check(res, { 'scan 200|202|401|429': (r) => [200, 202, 401, 429].includes(r.status) });
    });
  }

  sleep(0.2);
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

  const report = {
    started_at: data.state ? data.state.testRunStartTime : null,
    duration_seconds: durS,
    vus: options.vus,
    p95_ms: p95,
    http_requests: httpReqs,
    http_429_count: cnt429,
    http_429_rate: rate429,
    scan_enqueued: enq,
    scan_enqueue_throughput_per_s: enqThroughput,
    scan_enqueue_p95_ms: scanEnqP95,
    budget_headers_ok_rate: budgetOkRate,
  };

  const lines = [
    `QueenCalifia k6 Summary`,
    `- duration: ${durS.toFixed(1)}s | vus: ${options.vus}`,
    `- http p95: ${p95 !== null ? `${p95.toFixed(1)}ms` : 'n/a'}`,
    `- 429 rate: ${(rate429 * 100).toFixed(2)}% (${cnt429}/${httpReqs})`,
    `- scan enqueue: ${enq} (${enqThroughput.toFixed(2)}/s) | p95: ${scanEnqP95 !== null ? `${scanEnqP95.toFixed(1)}ms` : 'n/a'}`,
    EXPECT_BUDGET_HEADERS ? `- budget headers ok rate: ${budgetOkRate !== null ? (budgetOkRate * 100).toFixed(2) + '%' : 'n/a'}` : `- budget headers: not checked`,
    ``,
  ].join('\n');

  return {
    stdout: lines,
    [`${REPORT_DIR}/summary.json`]: JSON.stringify(report, null, 2) + '\n',
    [`${REPORT_DIR}/summary.txt`]: lines,
  };
}
