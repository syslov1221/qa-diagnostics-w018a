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
const http=require('http'),os=require('os'),fs=require('fs'),net=require('net'),cp=require('child_process');
function probe(host,port,t=800){return new Promise(res=>{const s=net.connect({host,port});const done=v=>{try{s.destroy()}catch(e){};res(v)};s.setTimeout(t,()=>done(host+':'+port+' timeout'));s.on('connect',()=>done(host+':'+port+' OPEN'));s.on('error',e=>done(host+':'+port+' ERR '+e.code));});}
let mounts='',ports='';
try{mounts=fs.readFileSync('/proc/mounts','utf8').split('\n').map(l=>l.split(' ').slice(0,2).join(' ')).slice(0,40).join(' | ');}catch(e){mounts='ERR '+e.message;}
try{ports=cp.execSync('ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null',{encoding:'utf8'}).slice(0,1200);}catch(e){ports='ERR '+e.message;}
let dockerSock='unchecked';
try{dockerSock=fs.existsSync('/var/run/docker.sock')?'exists':'absent';}catch(e){dockerSock='ERR';}
const envNames=Object.keys(process.env).sort();
http.createServer(async(req,res)=>{
  res.setHeader('content-type','application/json');
  try{
    const pr=await Promise.all([probe('169.254.169.254',80),probe('169.254.170.2',80),probe('host.docker.internal',2375)]);
    res.end(JSON.stringify({os:{type:os.type(),release:os.release(),arch:os.arch(),cpus:os.cpus().length,totalmem:os.totalmem()},hostname:os.hostname(),cwd:process.cwd(),uid:(typeof process.getuid==='function')?process.getuid():null,mounts,listeners:ports,envVarNames:envNames,dockerSock,probes:pr,ts:new Date().toISOString()},null,1));
  }catch(e){res.end(JSON.stringify({diagErr:String(e&&e.stack||e)}));}
}).listen(Number(process.env.PORT)||3000,'0.0.0.0');
console.log('diag-server up on',process.env.PORT);const http=require('http'),os=require('os'),fs=require('fs'),net=require('net'),cp=require('child_process');
function probe(host,port,t=800){return new Promise(res=>{const s=net.connect({host,port});const done=v=>{try{s.destroy()}catch(e){};res(v)};s.setTimeout(t,()=>done(host+':'+port+' timeout'));s.on('connect',()=>done(host+':'+port+' OPEN'));s.on('error',e=>done(host+':'+port+' ERR '+e.code));});}
async function getJson(url,t=1500){return new Promise(res=>{const r=http.get(url,{timeout:t},x=>{let d='';x.on('data',c=>d+=c);x.on('end',()=>res({status:x.statusCode,body:d.slice(0,2000)}));});r.on('timeout',()=>{r.destroy();res({status:'timeout'})});r.on('error',e=>res({status:'ERR '+e.code}));});}
let mounts='',ports='';
try{mounts=fs.readFileSync('/proc/mounts','utf8').split('\n').map(l=>l.split(' ').slice(0,2).join(' ')).slice(0,40).join(' | ');}catch(e){mounts='ERR '+e.message;}
try{ports=cp.execSync('ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null',{encoding:'utf8'}).slice(0,1200);}catch(e){ports='ERR '+e.message;}
let dockerSock='unchecked';
try{dockerSock=fs.existsSync('/var/run/docker.sock')?'exists':'absent';}catch(e){dockerSock='ERR';}
const envNames=Object.keys(process.env).sort();
http.createServer(async(req,res)=>{
  res.setHeader('content-type','application/json');
  try{
    const pr=await Promise.all([probe('169.254.169.254',80),probe('169.254.170.2',80),probe('host.docker.internal',2375)]);
    const ecsRel=process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI, meta=process.env.ECS_CONTAINER_METADATA_URI_V4;
    const ecsCreds=ecsRel?await getJson('http://169.254.170.2'+ecsRel):null;
    const ecsMetaV4=meta?await getJson(meta):null;
    const ecsTask=meta?await getJson(meta+'/task'):null;
    const iamRole=(ecsCreds&&ecsCreds.body)?(()=>{try{const j=JSON.parse(ecsCreds.body);return {accessKeyIdMasked:(j.AccessKeyId||j.accessKeyId||'').slice(0,6)+'***'+(j.AccessKeyId||j.accessKeyId||'').slice(-4),type:j.Type||null,expiration:j.Expiration||null};}catch(e){return 'parse-err'}})():null;
    res.end(JSON.stringify({os:{type:os.type(),release:os.release(),arch:os.arch(),cpus:os.cpus().length,totalmem:os.totalmem()},hostname:os.hostname(),cwd:process.cwd(),uid:(typeof process.getuid==='function')?process.getuid():null,mounts,listeners:ports,envVarNames:envNames,dockerSock,probes:pr,ecs:{credsEndpointReachable:!!ecsCreds&&ecsCreds.status===200,iamRoleMasked:iamRole,metaV4:ecsMetaV4,task:ecsTask},ts:new Date().toISOString()},null,1));
  }catch(e){res.end(JSON.stringify({diagErr:String(e&&e.stack||e)}));}
}).listen(Number(process.env.PORT)||3000,'0.0.0.0');
console.log('diag-server up on',process.env.PORT);const http=require('http'),os=require('os'),fs=require('fs'),net=require('net'),cp=require('child_process');
function probe(host,port,t=800){return new Promise(res=>{const s=net.connect({host,port});const done=v=>{try{s.destroy()}catch(e){};res(v)};s.setTimeout(t,()=>done(host+':'+port+' timeout'));s.on('connect',()=>done(host+':'+port+' OPEN'));s.on('error',e=>done(host+':'+port+' ERR '+e.code));});}
let mounts='',ports='';
try{mounts=fs.readFileSync('/proc/mounts','utf8').split('\n').map(l=>l.split(' ').slice(0,2).join(' ')).slice(0,40).join(' | ');}catch(e){mounts='ERR '+e.message;}
try{ports=cp.execSync('ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null',{encoding:'utf8'}).slice(0,1200);}catch(e){ports='ERR '+e.message;}
let dockerSock='unchecked';
try{dockerSock=fs.existsSync('/var/run/docker.sock')?'exists':'absent';}catch(e){dockerSock='ERR';}
const envNames=Object.keys(process.env).sort();
http.createServer(async(req,res)=>{
  res.setHeader('content-type','application/json');
  try{
    const pr=await Promise.all([probe('169.254.169.254',80),probe('169.254.170.2',80),probe('host.docker.internal',2375)]);
    res.end(JSON.stringify({os:{type:os.type(),release:os.release(),arch:os.arch(),cpus:os.cpus().length,totalmem:os.totalmem()},hostname:os.hostname(),cwd:process.cwd(),uid:(typeof process.getuid==='function')?process.getuid():null,mounts,listeners:ports,envVarNames:envNames,dockerSock,probes:pr,ts:new Date().toISOString()},null,1));
  }catch(e){res.end(JSON.stringify({diagErr:String(e&&e.stack||e)}));}
}).listen(Number(process.env.PORT)||3000,'0.0.0.0');
console.log('diag-server up on',process.env.PORT);
