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
