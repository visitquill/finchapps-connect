import http from 'node:http';
import {randomBytes,createHash,createHmac,timingSafeEqual} from 'node:crypto';
import {pathToFileURL} from 'node:url';
const all=['demographics','medications','conditions','labs','vitals','allergies','immunizations','encounters'];
export const scopes={visitquill:['demographics','conditions','medications','labs'],dosefolio:['demographics','medications','allergies'],labprism:['demographics','labs'],pulsetrellis:['demographics','vitals','encounters'],carethreadatlas:all,allergyfolio:['demographics','allergies','medications'],vaxledger:['demographics','immunizations'],consentloom:all,fhirtrail:all,sourceweave:all};
const hash=v=>createHash('sha256').update(v).digest('hex');
export function verifySignature(raw,header,secret,now=Date.now()){
 if(!secret)return false;
 const parts=String(header||'').split(',').map(x=>x.trim()),t=parts.find(x=>x.startsWith('t='))?.slice(2);
 if(!t||!/^\d+$/.test(t)||Math.abs(now/1000-Number(t))>300)return false;
 const expected=createHmac('sha256',secret).update(`${t}.${raw}`).digest();
 return parts.filter(x=>x.startsWith('v1=')).some(x=>{const s=x.slice(3);return /^[a-f0-9]{64}$/i.test(s)&&timingSafeEqual(Buffer.from(s,'hex'),expected)});
}
export function createServer({key=process.env.FINCHNODE_API_KEY,webhookSecret=process.env.FINCHNODE_WEBHOOK_SECRET,fetcher=fetch,now=()=>Date.now()}={}){
 const sessions=new Map(),events=new Map(),limits=new Map();
 const ttl=30*60*1000;
 const fail=(status,message)=>Object.assign(new Error(message),{status});
 async function upstream(path,options={}){
  if(!key?.startsWith('ck_live_')||!webhookSecret)throw fail(503,'Production connection is awaiting operator configuration.');
  const r=await fetcher('https://api.finchnode.com/api/v1'+path,{...options,redirect:'error',headers:{Authorization:`Bearer ${key}`,'Content-Type':'application/json',...options.headers},signal:AbortSignal.timeout(20000)});
  if(!r.ok)throw fail([403,410].includes(r.status)?410:r.status===429?429:502,r.status===410||r.status===403?'Consent is inactive or does not cover this request. Please reconnect.':r.status===429?'FinchNode is busy. Wait a moment and retry.':'FinchNode could not complete the request. Please retry.');
  return r.json();
 }
 async function rawBody(req){let raw='';for await(const c of req){raw+=c;if(Buffer.byteLength(raw)>32768)throw fail(413,'Request too large.')}return raw;}
 function limited(id,max,window=60000){const t=now(),v=limits.get(id);if(!v||v.until<t){limits.set(id,{n:1,until:t+window});return false;}return ++v.n>max;}
 const server=http.createServer(async(req,res)=>{
  const send=(code,body)=>{res.writeHead(code,{'Content-Type':'application/json'});res.end(JSON.stringify(body));};
  res.setHeader('Cache-Control','private, no-store');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');
  try{
   const path=new URL(req.url,'http://localhost').pathname;
   if(req.method==='GET'&&path==='/health')return send(200,{status:'ok',mode:'production',configured:Boolean(key?.startsWith('ck_live_')&&webhookSecret)});
   if(req.method==='POST'&&path==='/webhooks/finchnode'){
    const raw=await rawBody(req);if(!verifySignature(raw,req.headers['finchnode-signature'],webhookSecret,now()))throw fail(401,'Invalid signature.');
    const event=JSON.parse(raw),id=req.headers['finchnode-event-id'];
    if(!id||!event.data||!(event.data.subject===null||typeof event.data.subject==='string'))throw fail(400,'Invalid event.');
    if(!events.has(id)){
     if(['consent.revoked','consent.expired','deletion.requested'].includes(event.type))for(const [token,s]of sessions)if(s.subject===event.data.subject)sessions.delete(token);
     events.set(id,now()+600000);
    }return send(200,{received:true});
   }
   const origin=req.headers.origin;
   const slug=Object.keys(scopes).find(x=>origin===`https://${x}.onrender.com`);
   if(!slug)throw fail(403,'Origin not allowed.');
   res.setHeader('Access-Control-Allow-Origin',origin);res.setHeader('Vary','Origin');
   if(req.method==='OPTIONS'){res.setHeader('Access-Control-Allow-Methods','GET, POST, DELETE, OPTIONS');res.setHeader('Access-Control-Allow-Headers','Authorization, Content-Type');return send(204,{});}
   if(limited('global',1000))throw fail(429,'Please retry shortly.');
   if(req.method==='POST'&&path==='/session'){
    if(sessions.size>=2000||limited('connect-global',100)||limited('connect:'+req.socket.remoteAddress,10))throw fail(429,'Connection limit reached. Please try later.');
    const body=JSON.parse(await rawBody(req)||'{}');
    if(Object.keys(body).some(k=>k!=='categories')||!Array.isArray(body.categories)||!body.categories.length||body.categories.some(c=>!scopes[slug].includes(c)))throw fail(400,'Choose supported categories.');
    const app=await upstream('/app');if(app.environment!=='production'||app.status!=='live')throw fail(503,'A live production application is required.');
    const token=randomBytes(32).toString('hex'),externalId=randomBytes(24).toString('hex');
    const categories=[...new Set(body.categories)];
    const connected=await upstream('/connect/sessions',{method:'POST',headers:{'Idempotency-Key':externalId},body:JSON.stringify({externalId,categories,returnUrl:origin+'/',syncMode:'one-time',durationDays:1})});
    if(connected.environment!=='production'||!/^cs_[a-f0-9]{20}$/.test(connected.id))throw fail(502,'Unexpected connection environment.');
    const url=new URL(connected.url);if(url.origin!=='https://finchnode.com'||url.pathname!==`/connect/${connected.id}`)throw fail(502,'Invalid Hosted Connect destination.');
    sessions.set(hash(token),{slug,externalId,categories,id:connected.id,expires:now()+ttl,subject:null});
    return send(201,{token,url:connected.url,expiresAt:now()+ttl});
   }
   const token=String(req.headers.authorization||'').replace(/^Bearer /,'');
   const sessionKey=hash(token),s=sessions.get(sessionKey);
   if(!s||s.slug!==slug||s.expires<now()){if(s&&s.expires<now())sessions.delete(sessionKey);throw fail(401,'Your private session has ended. Connect again to continue.');}
   if(limited(sessionKey,12))throw fail(429,'Please wait before refreshing again.');
   if(req.method==='DELETE'&&path==='/session'){
    sessions.delete(sessionKey);
    // Completed sharing is revoked by the user in FinchNode's data controls.
    if(!s.subject)try{await upstream(`/connect/sessions/${s.id}/cancel`,{method:'POST'})}catch{}
    return send(200,{disconnected:true});
   }
   if(req.method!=='GET'||!['/session','/records'].includes(path))throw fail(404,'Not found.');
   const c=await upstream(`/connect/sessions/${s.id}`);
   if(c.environment!=='production'||c.externalId!==s.externalId||c.id!==s.id){sessions.delete(sessionKey);throw fail(403,'Connection verification failed.');}
   if(['abandoned','canceled','expired','failed'].includes(c.status)){sessions.delete(sessionKey);throw fail(410,'The connection ended. Please reconnect.');}
   if(path==='/session')return send(200,{status:c.status,syncStatus:c.sync?.status,expiresAt:s.expires});
   if(c.status!=='completed'||!/^u_[a-f0-9]{16}$/.test(c.subject||''))throw fail(409,'Finish Hosted Connect, then refresh.');
   s.subject=c.subject;
   // Scope every read to this origin's own Connect grant, even for a shared FinchNode application.
   const granted=s.categories.filter(x=>c.categories.includes(x)&&c.sync?.grantedCategories?.includes(x));
   if(!granted.length)throw fail(410,'No categories were authorized.');
   let record;try{record=await upstream(`/users/${encodeURIComponent(s.subject)}/records?categories=${granted.join(',')}`)}catch(e){if(e.status===410)sessions.delete(sessionKey);throw e;}
   if(!sessions.has(sessionKey))throw fail(410,'Access ended during the request.');
   if(record.object!=='health_record'||record.id!==s.subject||record.consent?.status!=='active'||record.synthetic===true)throw fail(502,'Unexpected production record response.');
   if(record.consent.expiresAt&&Date.parse(record.consent.expiresAt)<=now())throw fail(410,'Consent has expired.');
   if(!Array.isArray(record.categories)||record.categories.some(x=>!granted.includes(x)))throw fail(502,'Record exceeded the requested scope.');
   return send(200,{...record,environment:'production'});
  }catch(e){send(e.status||500,{error:e.status?e.message:'Unable to complete this request.'});}
 });
 const cleanup=setInterval(()=>{for(const [k,v]of sessions)if(v.expires<now())sessions.delete(k);for(const [k,v]of events)if(v<now())events.delete(k);for(const [k,v]of limits)if(v.until<now())limits.delete(k);},60000);cleanup.unref();server.on('close',()=>clearInterval(cleanup));return server;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)createServer().listen(Number(process.env.PORT||3000),'0.0.0.0',()=>console.log('FinchApps production connection service listening'));
