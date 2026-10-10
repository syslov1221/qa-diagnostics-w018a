const http = require('http');
const os = require('os');
function grab(path, cb) {
  const req = http.get({ host: '169.254.170.2', port: 80, path, timeout: 2500 }, res => {
    let d=''; res.on('data',c=>d+=c); res.on('end',()=>cb(null,res.statusCode,d));
  });
  req.on('timeout',()=>{req.destroy();cb('TIMEOUT');});
  req.on('error',e=>cb(String(e.code||e.message)));
}
function maskVal(s){ if(typeof s!=='string'||s.length<12) return '***short***'; return s.slice(0,3)+'***'+s.slice(-3)+`(len${s.length})`; }
http.createServer((req,res)=>{
  if(req.url.startsWith('/diag')) {
    const rel=(process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI)||'/';
    grab(rel,(e1,s1,b1)=>grab('/v2/metadata',(e2,s2,b2)=>{
      let creds=null; try{const j=JSON.parse(b1); creds={AccessKeyId:maskVal(j.AccessKeyId||''),Expiration:j.Expiration||null,SecretAccessKey_len:(j.SecretAccessKey||'').length,Token_len:(j.Token||'').length,CodeIsPresent:!!j.Code};}catch(_){}
      let meta=b2; try{const j2=JSON.parse(b2); if(j2.TaskARN)meta={Cluster:j2.Cluster,TaskARN_tail:String(j2.TaskARN).slice(-28)};}catch(_){}
      res.writeHead(200,{'Content-Type':'application/json'});
      res.end(JSON.stringify({ts:new Date().toISOString(),rel,credsErr:e1||null,creds,metaErr:e2||null,meta},null,2));
    }));
    return;
  }
  res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify({ok:true,ts:new Date().toISOString(),host:os.hostname()}));
}).listen(process.env.PORT||3000);