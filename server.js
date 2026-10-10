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
console.log('diag-server up on',process.env.PORT);
