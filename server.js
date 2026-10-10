// diag-v4 (w022a) — diag-v3 logic + STS GetCallerIdentity + EC2 DescribeNetworkInterfaces via SIGv4
// Pure Node 22 built-ins only. Masks credential VALUES in output.
const http = require('http');
const https = require('https');
const crypto = require('crypto');
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
  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, ''); // YYYYMMDDTHHMMSSZ
  const dateStamp = amzDate.slice(0, 8);
  // canonical query from pathQ: parse, sort, re-encode
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
  const canonHeaders = 'host:' + host + '\n' +
    'x-amz-date:' + amzDate + '\n' +
    'x-amz-security-token:' + token + '\n';
  const signedHeaders = 'host;x-amz-date;x-amz-security-token';
  const payloadHash = sha256hex('');
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
  return { amzDate, authorization: auth };
}

function awsGet(urlStr, region, service, creds, cb) {
  const u = new URL(urlStr);
  const { amzDate, authorization } = awsSign('GET', u.host, u.pathname + '?' + u.searchParams.toString() || u.pathname, region, service, creds);
  const options = {
    host: u.host, path: u.pathname + (u.search || ''), method: 'GET', timeout: 8000,
    headers: {
      'Authorization': authorization,
      'x-amz-date': amzDate,
      'x-amz-security-token': creds.Token || ''
    }
  };
  const rq = https.request(options, res => {
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

http.createServer((req, res) => {
  if (req.url.startsWith('/diag')) {
    const rel = process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI || '/';
    const REGION = 'us-east-2';

    function doGet(urlStr, region, service, cb) {
      grab('169.254.170.2', rel, (cerr, cst, cbody) => {
        let creds = null;
        try { creds = JSON.parse(cbody); } catch (_) {}
        if (!creds || !creds.AccessKeyId) return cb('CREDS_UNAVAILABLE', cerr, cbody);
        awsGet(urlStr, region, service, creds, cb);
      });
    }

    const results = [];
    let phase = 0;
    function finish() {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        version: 'diag-v4', wave: 'w022a',
        ts: new Date().toISOString(),
        hostname: os.hostname(),
        relUri: rel,
        region: REGION,
        platform: os.platform(), arch: os.arch(), node: process.version,
        results
      }, null, 2));
    }

    // 1..4: legacy diag-v3 probes
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
          let parsed = null, parseErr = err ? String(err) : null;
          if (!err && body) { try { parsed = JSON.parse(body); } catch (_) { parseErr = 'NOT_JSON'; parsed = null; } }
          let val = parsed;
          if (parsed && t.secret) { try { val = maskCredsRaw(parsed); } catch (_) {} }
          results.push({ name: t.name, url: 'http://' + t.host + t.path, err: err ? String(err) : null, status: st || null, parseErr, data: val, rawSnippet: parsed ? undefined : (body || '').slice(0, 2000) });
          setTimeout(nx, 100);
        });
      })();
    }

    function runAws(name, urlStr, service, transform) {
      doGet(urlStr, REGION, service, (err, st, body) => {
        const block = { name, url: urlStr, err: err ? String(err) : null, status: st || null };
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
        results.push(block);
        nextPhase();
      });
    }

    function nextPhase() {
      if (phase === 0) { phase = 1; return legacyPhase(() => nextPhase()); }
      if (phase === 1) {
        phase = 2;
        return runAws('sts_get_caller_identity',
          'https://sts.us-east-2.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15',
          'sts', null);
      }
      if (phase === 2) {
        phase = 3;
        return runAws('ec2_describe_network_interfaces',
          'https://ec2.us-east-2.amazonaws.com/?Action=DescribeNetworkInterfaces&Version=2016-11-15',
          'ec2', parseEnis);
      }
      return finish();
    }
    nextPhase();
    return;
  }
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ ok: true, version: 'diag-v4', wave: 'w022a', ts: new Date().toISOString(), host: os.hostname() }));
}).listen(process.env.PORT || 3000);
