const { neon } = require('@neondatabase/serverless');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const sql = neon(process.env.DATABASE_URL || '');
const JWT_SECRET = process.env.JWT_SECRET || '';

function now(){ return Date.now(); }
function normEmail(e){ return String(e||'').trim().toLowerCase(); }
function normName(n){ return String(n||'').trim().toLowerCase().replace(/[^a-z0-9_-]/g,'_').slice(0,40); }
function newUid(){ return crypto.randomUUID(); }
function hashPassword(password,salt=crypto.randomBytes(16).toString('hex')){
  return `${salt}:${crypto.scryptSync(password,salt,64).toString('hex')}`;
}
function verifyPassword(password,stored){
  const [salt,hash]=String(stored||'').split(':');
  if(!salt||!hash)return false;
  const got=crypto.scryptSync(password,salt,64).toString('hex');
  const a=Buffer.from(got,'hex'), b=Buffer.from(hash,'hex');
  return a.length===b.length && crypto.timingSafeEqual(a,b);
}
function sign(a){ return jwt.sign({uid:a.uid,email:a.email},JWT_SECRET,{expiresIn:'30d'}); }
function cleanPath(p){
  p=String(p||'').replace(/^\/+|\/+$/g,'');
  if(!p||p.includes('..')||/[.#$\[\]]/.test(p)) throw new Error('invalid path');
  return p;
}
function json(v){ return JSON.stringify(v); }
function resolveSpecial(v,current){
  if(v&&typeof v==='object'&&!Array.isArray(v)){
    if(v['.sv']==='timestamp')return now();
    if(v['.sv']&&typeof v['.sv']==='object'&&'increment' in v['.sv'])return Number(current||0)+Number(v['.sv'].increment||0);
    const o={}; for(const [k,x] of Object.entries(v))o[k]=resolveSpecial(x); return o;
  }
  if(Array.isArray(v))return v.map(x=>resolveSpecial(x));
  return v;
}
async function ensureSchema(){
  await sql`CREATE TABLE IF NOT EXISTS accounts (uid TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,email_key TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,created_at BIGINT NOT NULL)`;
  await sql`CREATE TABLE IF NOT EXISTS kv (path TEXT PRIMARY KEY,value JSONB NOT NULL)`;
  await sql`CREATE INDEX IF NOT EXISTS kv_path_prefix_idx ON kv (path text_pattern_ops)`;
}
async function getValue(p){
  const r=await sql`SELECT value FROM kv WHERE path=${p} LIMIT 1`;
  return r.length ? r[0].value : null;
}
async function readValue(p){
  if(p==='.info/connected')return true;
  const direct=await getValue(p); if(direct!==null)return direct;
  const rows=await sql`SELECT path,value FROM kv WHERE path LIKE ${p+'/%'} ORDER BY path`;
  if(!rows.length)return null;
  const root={};
  for(const row of rows){
    const rel=row.path.slice(p.length+1), parts=rel.split('/');
    let cur=root;
    for(let i=0;i<parts.length-1;i++){ if(!cur[parts[i]]||typeof cur[parts[i]]!=='object')cur[parts[i]]={}; cur=cur[parts[i]]; }
    cur[parts[parts.length-1]]=row.value;
  }
  return root;
}
async function delValue(p){ await sql`DELETE FROM kv WHERE path=${p} OR path LIKE ${p+'/%'}`; }
async function putValue(p,value){
  const v=resolveSpecial(value);
  await sql`DELETE FROM kv WHERE path=${p} OR path LIKE ${p+'/%'}`;
  await sql`INSERT INTO kv(path,value) VALUES(${p},${JSON.stringify(v)}::jsonb)`;
}
function deepMerge(a,b){
  if(!a||typeof a!=='object'||Array.isArray(a))a={};
  for(const [k,v] of Object.entries(b||{})){
    if(v===null)delete a[k];
    else if(v&&typeof v==='object'&&!Array.isArray(v)&&a[k]&&typeof a[k]==='object'&&!Array.isArray(a[k]))a[k]=deepMerge(a[k],v);
    else a[k]=v;
  }
  return a;
}
async function updateValue(p,value){ const cur=await readValue(p)||{}; await putValue(p,deepMerge(cur,value||{})); }
async function authUser(req){
  if(!JWT_SECRET) throw Object.assign(new Error('server_not_configured'),{status:500});
  const h=req.headers.authorization||'';
  if(!h.startsWith('Bearer '))throw Object.assign(new Error('auth/unauthenticated'),{status:401});
  try{return jwt.verify(h.slice(7),JWT_SECRET);}catch(_){throw Object.assign(new Error('auth/invalid-token'),{status:401});}
}
async function account(uid){ const r=await sql`SELECT uid,email,created_at FROM accounts WHERE uid=${uid} LIMIT 1`; return r[0]||null; }
async function allowed(u,op,p,value){
  if(p==='.info/connected')return op==='read';
  const parts=p.split('/'), top=parts[0];
  if(top==='users')return parts.length===2 && parts[1]===u.uid;
  if(top==='publicUsers'){ if(parts.length===1)return op==='read'; if(parts.length===2&&parts[1]===u.uid)return ['read','write','update','remove'].includes(op); return false; }
  if(top==='usernames'){
    if(op==='read')return true;
    const row=await getValue(p); return !row || row.uid===u.uid;
  }
  if(top==='publicChat')return op==='read' || (op==='write' && value && value.uid===u.uid);
  if(top==='publicChatRate')return parts[1]===u.uid;
  if(top==='chatInvites'){ if(parts.length<2)return false; if(parts[1]===u.uid)return true; return !!(value&&value.hostUid===u.uid); }
  if(top==='privateChats'){
    if(parts.length===1)return op==='read';
    const chat=await getValue('privateChats/'+parts[1]);
    if(parts.length>=3 && parts[2]==='messages')return !!(chat&&(chat.hostUid===u.uid||chat.members?.[u.uid]===true));
    if(parts.length>=3 && parts[2]==='members')return !!(chat&&(chat.hostUid===u.uid||parts[3]===u.uid));
    if(op==='read')return !!(chat&&(chat.hostUid===u.uid||chat.members?.[u.uid]===true));
    if(op==='write'||op==='update')return chat ? chat.hostUid===u.uid : !!(value&&value.hostUid===u.uid);
    if(op==='remove')return !!(chat&&chat.hostUid===u.uid);
  }
  if(['rooms','hostRooms','roomPlayers','roomChat','roomReactions','votes'].includes(top))return true;
  return false;
}
function send(res,status,payload){res.status(status).json(payload);}

module.exports = async (req,res)=>{
  try{
    if(!process.env.DATABASE_URL||!JWT_SECRET)return send(res,500,{error:'server_not_configured',message:'Set DATABASE_URL and JWT_SECRET in Vercel Environment Variables.'});
    await ensureSchema();
    const url=new URL(req.url,`https://${req.headers.host||'localhost'}`);
    let route=url.pathname.replace(/^\/api\/?/,'').replace(/\/+$/,'');
    if(req.method==='GET' && route==='health')return send(res,200,{ok:true,service:'HAMUGANG Cloud',time:now()});

    if(route==='auth/register'&&req.method==='POST'){
      const email=normEmail(req.body?.email), password=String(req.body?.password||''), username=String(req.body?.username||'').trim();
      if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return send(res,400,{error:'auth/invalid-email'});
      if(password.length<6)return send(res,400,{error:'auth/weak-password'});
      if(username && !/^[a-zA-Z0-9_-]{3,24}$/.test(username))return send(res,400,{error:'auth/invalid-username'});
      const ek=normEmail(email), uk=username?normName(username):'';
      if((await sql`SELECT 1 FROM accounts WHERE email_key=${ek} LIMIT 1`).length)return send(res,400,{error:'auth/email-already-in-use'});
      if(uk && (await getValue('usernames/'+uk)))return send(res,409,{error:'USERNAME_TAKEN'});
      const uid=newUid(), created=now();
      await sql`INSERT INTO accounts(uid,email,email_key,password_hash,created_at) VALUES(${uid},${email},${ek},${hashPassword(password)},${created})`;
      if(uk){
        try{ await sql`INSERT INTO kv(path,value) VALUES(${`usernames/${uk}`},${JSON.stringify({uid,email})}::jsonb)`; }
        catch(e){ await sql`DELETE FROM accounts WHERE uid=${uid}`; if(e.code==='23505')return send(res,409,{error:'USERNAME_TAKEN'}); throw e; }
      }
      return send(res,200,{token:sign({uid,email}),user:{uid,email,metadata:{creationTime:new Date(created).toISOString()}}});
    }
    if(route==='auth/login'&&req.method==='POST'){
      const email=normEmail(req.body?.email), password=String(req.body?.password||'');
      const r=await sql`SELECT * FROM accounts WHERE email_key=${email} LIMIT 1`, a=r[0];
      if(!a||!verifyPassword(password,a.password_hash))return send(res,401,{error:'auth/invalid-credential'});
      return send(res,200,{token:sign(a),user:{uid:a.uid,email:a.email,metadata:{creationTime:new Date(Number(a.created_at)).toISOString()}}});
    }
    if(route==='auth/me'&&req.method==='GET'){
      const u=await authUser(req), a=await account(u.uid); if(!a)return send(res,401,{error:'auth/user-not-found'});
      return send(res,200,{user:{uid:a.uid,email:a.email,metadata:{creationTime:new Date(Number(a.created_at)).toISOString()}}});
    }
    if(route==='auth/password'&&req.method==='POST'){
      const u=await authUser(req), a=(await sql`SELECT * FROM accounts WHERE uid=${u.uid} LIMIT 1`)[0];
      if(!a||!verifyPassword(String(req.body?.currentPassword||''),a.password_hash))return send(res,401,{error:'auth/wrong-password'});
      const np=String(req.body?.newPassword||''); if(np.length<6)return send(res,400,{error:'auth/weak-password'});
      await sql`UPDATE accounts SET password_hash=${hashPassword(np)} WHERE uid=${a.uid}`; return send(res,200,{ok:true});
    }
    if(route==='auth/reset-request'&&req.method==='POST')return send(res,200,{ok:true,message:'If the email exists, a reset request was recorded.'});

    const u=await authUser(req);
    if(!route.startsWith('db/'))return send(res,404,{error:'not_found'});
    const body=req.body||{};
    const p=cleanPath(body.path||'.info/connected');
    if(route==='db/read'&&req.method==='POST'){
      if(!(await allowed(u,'read',p)))return send(res,403,{error:'permission_denied'});
      return send(res,200,{value:await readValue(p)});
    }
    if(route==='db/write'&&req.method==='POST'){
      const value=body.value; if(!(await allowed(u,'write',p,value)))return send(res,403,{error:'permission_denied'});
      if(p.startsWith('usernames/')){const n=normName(p.split('/')[1]);if(n!==p.split('/')[1])return send(res,400,{error:'invalid username key'});const ex=await getValue(p);if(ex&&ex.uid!==u.uid)return send(res,409,{error:'USERNAME_TAKEN'});if(value&&value.uid!==u.uid)return send(res,403,{error:'permission_denied'});}
      if(p.startsWith('users/') && p.split('/').length===2){
        const current=await getValue(p);
        const v=resolveSpecial(value,current);
        if(current){ if(current.email && v.email && current.email!==v.email)return send(res,400,{error:'EMAIL_IMMUTABLE'}); if(current.username && v.username && current.username!==v.username)return send(res,400,{error:'USERNAME_IMMUTABLE'}); }
        if(v.email && v.email!==u.email)return send(res,400,{error:'EMAIL_IMMUTABLE'});
      }
      if(p.startsWith('publicChatRate/')){const old=await getValue(p), next=resolveSpecial(value);if(old&&next&&Number(next.lastSentAt||0)-Number(old.lastSentAt||0)<30000)return send(res,429,{error:'chat_cooldown'});}
      await putValue(p,value); return send(res,200,{ok:true});
    }
    if(route==='db/update'&&req.method==='POST'){
      const value=body.value||{}; if(!(await allowed(u,'update',p,value)))return send(res,403,{error:'permission_denied'});
      if(p.startsWith('users/')&&p.split('/').length===2){const current=await getValue(p);if(current?.email&&value.email&&current.email!==value.email)return send(res,400,{error:'EMAIL_IMMUTABLE'});if(current?.username&&value.username&&current.username!==value.username)return send(res,400,{error:'USERNAME_IMMUTABLE'});}
      await updateValue(p,value); return send(res,200,{ok:true});
    }
    if(route==='db/remove'&&req.method==='POST'){
      if(!(await allowed(u,'remove',p)))return send(res,403,{error:'permission_denied'});
      if(p.startsWith('usernames/')){const old=await getValue(p);if(old&&old.uid!==u.uid)return send(res,403,{error:'permission_denied'});}
      await delValue(p); return send(res,200,{ok:true});
    }
    if(route==='db/push'&&req.method==='POST'){
      const key=crypto.randomBytes(10).toString('base64url'), full=p+'/'+key, value=body.value;
      if(!(await allowed(u,'write',full,value)))return send(res,403,{error:'permission_denied'});
      await putValue(full,value); return send(res,200,{key});
    }
    if(route==='db/transaction'&&req.method==='POST'){
      const next=body.value; if(!(await allowed(u,'write',p,next)))return send(res,403,{error:'permission_denied'});
      const current=await readValue(p);
      if(next===null){await delValue(p);return send(res,200,{committed:true,value:null});}
      await putValue(p,next); return send(res,200,{committed:true,value:await readValue(p)});
    }
    return send(res,404,{error:'not_found'});
  }catch(e){
    console.error(e);
    return send(res,e.status||500,{error:e.message||'internal_error'});
  }
};
