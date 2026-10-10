// diag-v3 (w021a) — full ECS task network map; masks ONLY secret values
const http = require('http');
const os = require('os');

function grab(host, path, cb) {
  const req = http.get({ host, port: 80, path, timeout: 4000 }, res => {
    let d = ''; res.on('data', c => d += c); res.on('end', () => cb(null, res.statusCode, d));
  });
  req.on('timeout', () => { req.destroy(); cb('TIMEOUT'); });
  req.on('error', e => cb(String(e.code || e.message)));
}

function maskSecret(v) {
  if (typeof v !== 'string' || !v) return null;
  if (v.length <= 8) return { len: v.length };
  return v.slice(0, 2) + '***' + v.slice(-2) + '(len' + v.length + ')';
}

function maskCredsRaw(obj) {
  // deep clone then mask only credential VALUES; all other fields stay untouched
  const o = JSON.parse(JSON.stringify(obj));
  ['AccessKeyId'].forEach(k => { if (typeof o[k] === 'string') o[k] = maskSecret(o[k]); });
  ['SecretAccessKey', 'Token'].forEach(k => {
    if (typeof o[k] === 'string') o[k] = maskSecret(o[k]);
  });
  return o;
}

http.createServer((req, res) => {
  if (req.url.startsWith('/diag')) {
    const rel = process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI || '/';
    const targets = [
      { name: 'ecs_credentials', host: '169.254.170.2', path: rel, secret: true },
      { name: 'ecs_metadata', host: '169.254.170.2', path: '/v2/metadata', secret: false },
      { name: 'ecs_metadata_network_probe', host: '169.254.170.2', path: '/v2/metadata/network', secret: false },
      { name: 'imds_instance_identity', host: '169.254.169.254', path: '/latest/dynamic/instance-identity/document', secret: false }
    ];
    let out = [];
    let i = 0;
    function next() {
      if (i >= targets.length) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          version: 'diag-v3', wave: 'w021a',
          ts: new Date().toISOString(),
          hostname: os.hostname(),
          relUri: rel,
          platform: os.platform(), arch: os.arch(), node: process.version,
          results: out
        }, null, 2));
        return;
      }
      const t = targets[i++];
      grab(t.host, t.path, (err, st, body) => {
        let parsed = null, parseErr = err ? String(err) : null;
        if (!err && body) { try { parsed = JSON.parse(body); } catch (_) { parseErr = 'NOT_JSON'; parsed = null; } }
        let val = parsed;
        if (parsed && t.secret) { try { val = maskCredsRaw(parsed); } catch (_) {} }
        out.push({ name: t.name, url: 'http://' + t.host + t.path, err: err ? String(err) : null, status: st || null, parseErr, data: val, rawSnippet: parsed ? undefined : (body || '').slice(0, 2000) });
        setTimeout(next, 150);
      });
    }
    next();
    return;
  }
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ ok: true, version: 'diag-v3', wave: 'w021a', ts: new Date().toISOString(), host: os.hostname() }));
}).listen(process.env.PORT || 3000);
