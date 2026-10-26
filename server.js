const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 3000);
const PUBLIC = path.join(__dirname, 'public');
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'db.json');
const SESSION_DAYS = 7;
fs.mkdirSync(DATA_DIR, { recursive: true });

const initial = {
  users: [],
  messages: [],
  plans: [],
  relations: [],
  stats: [],
  activities: []
};
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, JSON.stringify(initial, null, 2));
function readDB() { try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch { return structuredClone(initial); } }
function saveDB(db) { fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2)); }
function send(res, status, data, headers={}) {
  res.writeHead(status, {'Content-Type':'application/json; charset=utf-8', 'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff', ...headers});
  res.end(JSON.stringify(data));
}
function body(req) {
  return new Promise((resolve, reject) => {
    let raw=''; req.on('data', c => { raw += c; if(raw.length > 100000) { reject(new Error('too_large')); req.destroy(); }});
    req.on('end', () => { try { resolve(raw ? JSON.parse(raw) : {}); } catch { reject(new Error('bad_json')); }});
  });
}
function hash(s, salt) { return crypto.scryptSync(s, salt, 64).toString('hex'); }
function safeUser(u) { return {id:u.id, username:u.username, role:u.role, joinedAt:u.joinedAt}; }
function getUser(req, db) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!token) return null;
  const session = db.sessions?.find(s => s.tokenHash === crypto.createHash('sha256').update(token).digest('hex') && s.expires > Date.now());
  return session ? db.users.find(u => u.id === session.userId) || null : null;
}
function needUser(req,res,db) { const u=getUser(req,db); if(!u) send(res,401,{error:'login_required'}); return u; }
function needLeader(req,res,db) { const u=needUser(req,res,db); if(!u) return null; if(u.role!=='leader') { send(res,403,{error:'leader_only'}); return null; } return u; }
function clean(v, max=200) { return String(v ?? '').trim().slice(0,max); }
async function api(req,res,url) {
  const db=readDB();
  let b={}; if(!['GET','HEAD'].includes(req.method)) { try { b=await body(req); } catch(e) { return send(res,400,{error:e.message==='too_large'?'too_large':'bad_json'}); } }
  if(url==='/api/health' && req.method==='GET') return send(res,200,{ok:true,app:'IRXGG',version:'1.0.0'});
  if(url==='/api/register' && req.method==='POST') {
    const username=clean(b.username,24), password=String(b.password||'');
    if(!/^[a-zA-Z0-9_]{3,24}$/.test(username) || password.length<8) return send(res,400,{error:'username_3_24_and_password_8_required'});
    if(db.users.some(u=>u.username.toLowerCase()===username.toLowerCase())) return send(res,409,{error:'username_taken'});
    const id=crypto.randomUUID(), salt=crypto.randomBytes(16).toString('hex');
    const user={id,username,salt,passwordHash:hash(password,salt),role:db.users.length===0?'leader':'member',joinedAt:new Date().toISOString()};
    db.users.push(user); db.sessions ||= [];
    const token=crypto.randomBytes(32).toString('hex');
    db.sessions.push({userId:id,tokenHash:crypto.createHash('sha256').update(token).digest('hex'),expires:Date.now()+SESSION_DAYS*86400000});
    db.activities.unshift({id:crypto.randomUUID(),text:`${username} به تیم پیوست`,at:new Date().toISOString()});
    saveDB(db); return send(res,201,{token,user:safeUser(user)});
  }
  if(url==='/api/login' && req.method==='POST') {
    const username=clean(b.username,24), password=String(b.password||'');
    const u=db.users.find(x=>x.username.toLowerCase()===username.toLowerCase());
    if(!u || hash(password,u.salt)!==u.passwordHash) return send(res,401,{error:'invalid_credentials'});
    db.sessions ||= [];
    const token=crypto.randomBytes(32).toString('hex');
    db.sessions.push({userId:u.id,tokenHash:crypto.createHash('sha256').update(token).digest('hex'),expires:Date.now()+SESSION_DAYS*86400000});
    saveDB(db); return send(res,200,{token,user:safeUser(u)});
  }
  if(url==='/api/me' && req.method==='GET') { const u=needUser(req,res,db); if(!u)return; return send(res,200,{user:safeUser(u)}); }
  if(url==='/api/dashboard' && req.method==='GET') {
    const u=needUser(req,res,db); if(!u)return;
    const users=db.users.map(safeUser);
    return send(res,200,{user:safeUser(u),users,messages:db.messages.slice(-100).reverse(),plans:db.plans.slice().sort((a,b)=>a.when.localeCompare(b.when)),relations:db.relations.slice().reverse(),stats:db.stats.slice().reverse(),activities:db.activities.slice(0,12)});
  }
  if(url==='/api/logout' && req.method==='POST') {
    const token=(req.headers.authorization||'').replace(/^Bearer\s+/i,'');
    db.sessions=(db.sessions||[]).filter(s=>s.tokenHash!==crypto.createHash('sha256').update(token).digest('hex'));
    saveDB(db); return send(res,200,{ok:true});
  }
  const user=getUser(req,db);
  if(!user) return send(res,401,{error:'login_required'});
  if(url==='/api/messages' && req.method==='POST') {
    const text=clean(b.text,1000); if(!text) return send(res,400,{error:'message_required'});
    const item={id:crypto.randomUUID(),userId:user.id,username:user.username,text,at:new Date().toISOString()};
    db.messages.push(item); db.messages=db.messages.slice(-500); saveDB(db); return send(res,201,{message:item});
  }
  if(url==='/api/plans' && req.method==='POST') {
    const title=clean(b.title,100), kind=['attack','defense','training'].includes(b.kind)?b.kind:'training', when=clean(b.when,40), notes=clean(b.notes,1000);
    if(!title || !when) return send(res,400,{error:'title_and_time_required'});
    const item={id:crypto.randomUUID(),title,kind,when,notes,createdBy:user.username,at:new Date().toISOString()};
    db.plans.push(item); saveDB(db); return send(res,201,{plan:item});
  }
  if(url==='/api/relations' && req.method==='POST') {
    const name=clean(b.name,60), kind=['enemy','ally'].includes(b.kind)?b.kind:'ally', notes=clean(b.notes,500);
    if(!name) return send(res,400,{error:'name_required'});
    const item={id:crypto.randomUUID(),name,kind,notes,createdBy:user.username,at:new Date().toISOString()};
    db.relations.push(item); saveDB(db); return send(res,201,{relation:item});
  }
  if(url==='/api/stats' && req.method==='POST') {
    const player=clean(b.player,60), kills=Number(b.kills), deaths=Number(b.deaths||0), assists=Number(b.assists||0);
    if(!player || !Number.isInteger(kills)||kills<0||kills>100000||!Number.isInteger(deaths)||deaths<0||deaths>100000||!Number.isInteger(assists)||assists<0||assists>100000) return send(res,400,{error:'invalid_stats'});
    const item={id:crypto.randomUUID(),player,kills,deaths,assists,createdBy:user.username,at:new Date().toISOString()};
    db.stats.push(item); saveDB(db); return send(res,201,{stat:item});
  }
  if(url==='/api/members' && req.method==='GET') return send(res,200,{users:db.users.map(safeUser)});
  if(url==='/api/members/role' && req.method==='POST') {
    const leader=needLeader(req,res,db); if(!leader)return;
    const target=db.users.find(u=>u.id===b.userId); if(!target)return send(res,404,{error:'member_not_found'});
    if(target.id===leader.id) return send(res,400,{error:'cannot_change_own_role'});
    target.role=b.role==='leader'?'leader':'member'; saveDB(db); return send(res,200,{user:safeUser(target)});
  }
  return send(res,404,{error:'not_found'});
}
const files={'/':'index.html','/index.html':'index.html','/style.css':'style.css','/app.js':'app.js','/manifest.webmanifest':'manifest.webmanifest','/icon.svg':'icon.svg'};
const types={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'application/javascript; charset=utf-8','.webmanifest':'application/manifest+json; charset=utf-8','.svg':'image/svg+xml'};
const server=http.createServer(async(req,res)=>{
  const pathname=new URL(req.url,'http://localhost').pathname;
  res.setHeader('X-Frame-Options','DENY'); res.setHeader('Referrer-Policy','no-referrer');
  if(pathname.startsWith('/api/')) { try { return await api(req,res,pathname); } catch(e) { console.error(e); return send(res,500,{error:'server_error'}); } }
  const file=files[pathname];
  if(!file || !['GET','HEAD'].includes(req.method)) { res.writeHead(404,{'Content-Type':'text/plain; charset=utf-8'}); return res.end('404 Not Found'); }
  res.writeHead(200,{'Content-Type':types[path.extname(file)],'Cache-Control':'no-cache'});
  if(req.method==='HEAD') return res.end();
  fs.createReadStream(path.join(PUBLIC,file)).pipe(res);
});
server.listen(PORT,'0.0.0.0',()=>console.log(`IRXGG running on http://localhost:${PORT}`));