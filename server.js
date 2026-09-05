const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');
const WebSocket = require('ws');
const QRCode = require('qrcode');

const PORT = Number(process.env.PORT || 3000);
const PUBLIC = path.join(__dirname, 'public');
const MESSAGE_TTL_MS = 60_000;
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 30;
const MAX_BODY = 256 * 1024;
const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) throw new Error('DATABASE_URL is required');
console.log('DATABASE_URL exists:', !!DATABASE_URL);
console.log('DATABASE_URL length:', DATABASE_URL.length);
console.log('DATABASE_URL starts with postgres:', DATABASE_URL.startsWith('postgres'));
console.log('DATABASE_URL starts with postgresql:', DATABASE_URL.startsWith('postgresql'));
console.log(
  'DATABASE_URL preview:',
  DATABASE_URL.substring(0, 20).replace(/:[^:@]+@/, ':***@')
);
const pool = new Pool({ connectionString: DATABASE_URL, max: Number(process.env.DB_POOL_MAX || 10), ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : undefined });
const sockets = new Map();
const rate = new Map();

const schema = `
CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY,
  username varchar(25) NOT NULL UNIQUE,
  connection_code_hash char(64) NOT NULL UNIQUE,
  public_key text NOT NULL,
  recovery_hash char(64),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sessions (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash char(64) NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
CREATE TABLE IF NOT EXISTS contact_requests (
  id uuid PRIMARY KEY,
  from_user uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  to_user uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status varchar(16) NOT NULL DEFAULT 'pending',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (from_user <> to_user)
);
CREATE INDEX IF NOT EXISTS requests_to_idx ON contact_requests(to_user, status, created_at DESC);
CREATE INDEX IF NOT EXISTS requests_from_idx ON contact_requests(from_user, created_at DESC);
CREATE TABLE IF NOT EXISTS blocks (
  blocker uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  blocked uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(blocker, blocked)
);
CREATE TABLE IF NOT EXISTS chats (
  id uuid PRIMARY KEY,
  user_a uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  user_b uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (user_a <> user_b),
  UNIQUE(user_a, user_b)
);
CREATE INDEX IF NOT EXISTS chats_user_a_idx ON chats(user_a);
CREATE INDEX IF NOT EXISTS chats_user_b_idx ON chats(user_b);
CREATE TABLE IF NOT EXISTS messages (
  id uuid PRIMARY KEY,
  chat_id uuid NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
  sender_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ciphertext text NOT NULL,
  iv text NOT NULL,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  edited boolean NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS messages_chat_exp_idx ON messages(chat_id, expires_at, created_at);
CREATE TABLE IF NOT EXISTS message_deletions (
  message_id uuid NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(message_id, user_id)
);
`;

function id() { return crypto.randomUUID(); }
function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }
function randomCode() { return crypto.randomBytes(8).toString('hex').toUpperCase().match(/.{1,4}/g).join('-'); }
function publicUser(r) { return { id:r.id, username:r.username, publicKey:r.public_key, createdAt:new Date(r.created_at).getTime() }; }
function json(res, status, body, headers={}) { const d=JSON.stringify(body); res.writeHead(status, {'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','Content-Length':Buffer.byteLength(d), ...headers}); res.end(d); }
function noContent(res) { res.writeHead(204, {'Cache-Control':'no-store'}); res.end(); }
function readBody(req) { return new Promise((resolve,reject)=>{let s='';req.on('data',c=>{s+=c;if(Buffer.byteLength(s)>MAX_BODY){reject(Object.assign(new Error('too_large'),{status:413}));req.destroy();}});req.on('end',()=>{try{resolve(s?JSON.parse(s):{})}catch{reject(Object.assign(new Error('bad_json'),{status:400}))}});req.on('error',reject)}); }
function clientIp(req){return String(req.headers['x-forwarded-for']||req.socket.remoteAddress||'').split(',')[0].trim();}
function limited(req, key, max=60, windowMs=60_000){const k=clientIp(req)+':'+key;const now=Date.now();let x=rate.get(k);if(!x||now-x.start>windowMs)x={start:now,count:0};x.count++;rate.set(k,x);return x.count<=max;}
function originOk(req){if(!process.env.ALLOWED_ORIGIN)return true;return req.headers.origin===process.env.ALLOWED_ORIGIN;}
async function auth(req){const h=req.headers.authorization||'';let token=h.startsWith('Bearer ')?h.slice(7):'';const cookie=String(req.headers.cookie||'').match(/(?:^|; )session=([^;]+)/);if(!token&&cookie)token=decodeURIComponent(cookie[1]);if(!token)return null;const q=await pool.query('SELECT u.*, s.id AS session_id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now()', [sha256(token)]);return q.rows[0]||null;}
function setSessionCookie(res, token){res.setHeader('Set-Cookie', `session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; ${process.env.COOKIE_SECURE === 'false' ? '' : 'Secure; '}Max-Age=${Math.floor(SESSION_TTL_MS/1000)}`);}
function sendUser(userId,event){const set=sockets.get(userId);if(!set)return;const raw=JSON.stringify(event);for(const ws of set){if(ws.readyState===WebSocket.OPEN)ws.send(raw)}}
async function chatFor(a,b){const lo=a<b?a:b, hi=a<b?b:a;const q=await pool.query('SELECT * FROM chats WHERE user_a=$1 AND user_b=$2 LIMIT 1',[lo,hi]);return q.rows[0]||null;}
async function chatMember(chatId,userId){const q=await pool.query('SELECT * FROM chats WHERE id=$1 AND (user_a=$2 OR user_b=$2)',[chatId,userId]);return q.rows[0]||null;}
async function otherUser(chat,userId){const id2=chat.user_a===userId?chat.user_b:chat.user_a;const q=await pool.query('SELECT * FROM users WHERE id=$1',[id2]);return q.rows[0]||null;}
async function expireMessages(){const q=await pool.query('DELETE FROM messages WHERE expires_at<=now() RETURNING id,chat_id');for(const m of q.rows){const c=await pool.query('SELECT user_a,user_b FROM chats WHERE id=$1',[m.chat_id]);if(c.rowCount){sendUser(c.rows[0].user_a,{type:'message.expired',messageId:m.id,chatId:m.chat_id});sendUser(c.rows[0].user_b,{type:'message.expired',messageId:m.id,chatId:m.chat_id});}}}
setInterval(()=>expireMessages().catch(e=>console.error('expiry',e)),1000);

async function api(req,res,url){
  if(!limited(req, url.pathname.split('/')[2]||'root', 180)) return json(res,429,{error:'rate_limited'});
  if(['POST','PATCH','DELETE'].includes(req.method)&&!originOk(req))return json(res,403,{error:'bad_origin'});
  if(url.pathname==='/api/health'&&req.method==='GET')return json(res,200,{ok:true,now:Date.now()});

  if(url.pathname==='/api/register'&&req.method==='POST'){
    if(!limited(req,'register',10))return json(res,429,{error:'rate_limited'});
    const b=await readBody(req);const username=String(b.username||'').trim();const publicKey=String(b.publicKey||'').trim();
    if(!/^@[a-zA-Z0-9_]{3,24}$/.test(username)||!publicKey)return json(res,400,{error:'invalid_registration'});
    const userId=id(), code=randomCode(), recoveryKey=crypto.randomBytes(24).toString('base64url'), token=crypto.randomBytes(32).toString('base64url');
    try{const q=await pool.query('INSERT INTO users(id,username,connection_code_hash,public_key,recovery_hash) VALUES($1,$2,$3,$4,$5) RETURNING *',[userId,username,sha256(code),publicKey,sha256(recoveryKey)]);await pool.query('INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+$4::interval)',[id(),userId,sha256(token),`${SESSION_TTL_MS} milliseconds`]);setSessionCookie(res,token);return json(res,201,{token,user:publicUser(q.rows[0]),connectionCode:code,recoveryKey});}catch(e){if(e.code==='23505')return json(res,409,{error:'username_taken'});throw e;}
  }

  if(url.pathname==='/api/login'&&req.method==='POST'){
    const b=await readBody(req);const username=String(b.username||'').trim();const recoveryKey=String(b.recoveryKey||'').trim();
    if(!/^@[a-zA-Z0-9_]{3,24}$/.test(username)||!recoveryKey)return json(res,400,{error:'invalid_login'});
    const q=await pool.query('SELECT * FROM users WHERE lower(username)=lower($1) AND recovery_hash=$2 LIMIT 1',[username,sha256(recoveryKey)]);
    if(!q.rowCount)return json(res,401,{error:'invalid_credentials'});
    const token=crypto.randomBytes(32).toString('base64url');await pool.query('INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+$4::interval)',[id(),q.rows[0].id,sha256(token),`${SESSION_TTL_MS} milliseconds`]);setSessionCookie(res,token);return json(res,200,{token,user:publicUser(q.rows[0])});
  }
  const me=await auth(req);
  if(url.pathname==='/api/session'&&req.method==='DELETE'){if(!me)return json(res,401,{error:'unauthorized'});await pool.query('DELETE FROM sessions WHERE user_id=$1',[me.id]);res.setHeader('Set-Cookie','session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0');return noContent(res)}
  if(!me)return json(res,401,{error:'unauthorized'});

  if(url.pathname==='/api/me'&&req.method==='GET')return json(res,200,{user:publicUser(me),connectionCode:null});
  if(url.pathname==='/api/me'&&req.method==='PATCH'){
    const b=await readBody(req);const username=String(b.username||'').trim();if(!/^@[a-zA-Z0-9_]{3,24}$/.test(username))return json(res,400,{error:'username_invalid'});
    try{const q=await pool.query('UPDATE users SET username=$1,updated_at=now() WHERE id=$2 RETURNING *',[username,me.id]);return json(res,200,{user:publicUser(q.rows[0])})}catch(e){if(e.code==='23505')return json(res,409,{error:'username_taken'});throw e;}
  }
  if(url.pathname==='/api/me/connection-code'&&req.method==='POST'){
    const code=randomCode();await pool.query('UPDATE users SET connection_code_hash=$1,updated_at=now() WHERE id=$2',[sha256(code),me.id]);return json(res,200,{connectionCode:code});
  }
  if(url.pathname==='/api/me/recovery-key'&&req.method==='POST'){const recoveryKey=crypto.randomBytes(24).toString('base64url');await pool.query('UPDATE users SET recovery_hash=$1,updated_at=now() WHERE id=$2',[sha256(recoveryKey),me.id]);await pool.query('DELETE FROM sessions WHERE user_id=$1',[me.id]);return json(res,200,{recoveryKey})}
  if(url.pathname==='/api/me/qr'&&req.method==='GET'){
    // QR encodes a one-time-ish share URL containing the public username; the current connection code is intentionally not stored plaintext.
    // For a shareable QR, the client can request /api/me/share below, which returns a short-lived signed payload.
    const payload=await sharePayload(me.id);const svg=await QRCode.toString(payload,{type:'svg',margin:1,width:280});return json(res,200,{svg});
  }
  if(url.pathname==='/api/me/share'&&req.method==='POST'){return json(res,200,{shareUrl:await sharePayload(me.id)})}
  if(url.pathname==='/api/me'&&req.method==='DELETE'){
    await pool.query('DELETE FROM users WHERE id=$1',[me.id]);res.setHeader('Set-Cookie','session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0');return noContent(res);
  }
  if(url.pathname==='/api/users/lookup'&&req.method==='GET'){
    const qv=String(url.searchParams.get('q')||'').trim();let q;
    if(/^@[a-zA-Z0-9_]{3,24}$/.test(qv))q=await pool.query('SELECT * FROM users WHERE lower(username)=lower($1) AND id<>$2 LIMIT 1',[qv,me.id]);
    else q=await pool.query('SELECT * FROM users WHERE connection_code_hash=$1 AND id<>$2 LIMIT 1',[sha256(qv.toUpperCase()),me.id]);
    if(!q.rowCount)return json(res,404,{error:'not_found'});return json(res,200,{user:publicUser(q.rows[0])});
  }
  if(url.pathname==='/api/requests'&&req.method==='GET'){
    const q=await pool.query(`SELECT r.*, fu.username from_username, fu.public_key from_public_key FROM contact_requests r JOIN users fu ON fu.id=r.from_user WHERE r.to_user=$1 ORDER BY r.created_at DESC LIMIT 100`,[me.id]);
    const out=q.rows.map(r=>({id:r.id,status:r.status,createdAt:new Date(r.created_at).getTime(),from:{id:r.from_user,username:r.from_username,publicKey:r.from_public_key}}));return json(res,200,{requests:out});
  }
  if(url.pathname==='/api/requests'&&req.method==='POST'){
    const b=await readBody(req);const target=String(b.target||'').trim();let q;
    if(target.startsWith('@'))q=await pool.query('SELECT * FROM users WHERE lower(username)=lower($1) LIMIT 1',[target]);else q=await pool.query('SELECT * FROM users WHERE connection_code_hash=$1 LIMIT 1',[sha256(target.toUpperCase())]);
    if(!q.rowCount||q.rows[0].id===me.id)return json(res,404,{error:'target_not_found'});const targetUser=q.rows[0];
    const blocked=await pool.query('SELECT 1 FROM blocks WHERE (blocker=$1 AND blocked=$2) OR (blocker=$2 AND blocked=$1)',[me.id,targetUser.id]);if(blocked.rowCount)return json(res,403,{error:'blocked'});
    const c=await chatFor(me.id,targetUser.id);if(c)return json(res,409,{error:'chat_exists',chatId:c.id});
    const pending=await pool.query(`SELECT id FROM contact_requests WHERE ((from_user=$1 AND to_user=$2) OR (from_user=$2 AND to_user=$1)) AND status='pending' LIMIT 1`,[me.id,targetUser.id]);if(pending.rowCount)return json(res,409,{error:'request_exists'});
    const rid=id();await pool.query('INSERT INTO contact_requests(id,from_user,to_user) VALUES($1,$2,$3)',[rid,me.id,targetUser.id]);sendUser(targetUser.id,{type:'chat.request',request:{id:rid,from:publicUser(me),createdAt:Date.now()}});return json(res,201,{requestId:rid});
  }
  if(url.pathname==='/api/requests/respond'&&req.method==='POST'){
    const b=await readBody(req);const action=String(b.action||'');if(!['accept','reject','block'].includes(action))return json(res,400,{error:'invalid_action'});
    const client=await pool.connect();let q,r;try{await client.query('BEGIN');q=await client.query('SELECT * FROM contact_requests WHERE id=$1 AND to_user=$2 AND status=\'pending\' FOR UPDATE',[b.requestId,me.id]);if(!q.rowCount){await client.query('ROLLBACK');return json(res,404,{error:'request_not_found'})}r=q.rows[0];await client.query('UPDATE contact_requests SET status=$1,updated_at=now() WHERE id=$2',[action,r.id]);if(action==='block')await client.query('INSERT INTO blocks(blocker,blocked) VALUES($1,$2) ON CONFLICT DO NOTHING',[me.id,r.from_user]);let chat=null;if(action==='accept'){const lo=r.from_user<r.to_user?r.from_user:r.to_user,hi=r.from_user<r.to_user?r.to_user:r.from_user;const cq=await client.query('INSERT INTO chats(id,user_a,user_b) VALUES($1,$2,$3) ON CONFLICT(user_a,user_b) DO UPDATE SET created_at=chats.created_at RETURNING *',[id(),lo,hi]);chat=cq.rows[0];}await client.query('COMMIT');if(chat){const other=await otherUser(chat,me.id);const ev={type:'chat.accepted',chat:{id:chat.id,other:publicUser(me)}};sendUser(r.from_user,ev);return json(res,200,{status:action,chat:{id:chat.id,other:publicUser(other)}})}sendUser(r.from_user,{type:'chat.request.updated',requestId:r.id,status:action});return json(res,200,{status:action})}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
  }
  if(url.pathname==='/api/chats'&&req.method==='GET'){
    const q=await pool.query(`SELECT c.*, u.id other_id,u.username other_username,u.public_key other_public_key FROM chats c JOIN users u ON u.id=CASE WHEN c.user_a=$1 THEN c.user_b ELSE c.user_a END WHERE c.user_a=$1 OR c.user_b=$1 ORDER BY c.created_at DESC`,[me.id]);return json(res,200,{chats:q.rows.map(r=>({id:r.id,other:{id:r.other_id,username:r.other_username,publicKey:r.other_public_key},createdAt:new Date(r.created_at).getTime()}))});
  }
  const cm=url.pathname.match(/^\/api\/chats\/([^/]+)\/messages$/);
  if(cm&&req.method==='GET'){
    const c=await chatMember(cm[1],me.id);if(!c)return json(res,403,{error:'forbidden'});await expireMessages();const q=await pool.query(`SELECT m.* FROM messages m LEFT JOIN message_deletions d ON d.message_id=m.id AND d.user_id=$2 WHERE m.chat_id=$1 AND m.expires_at>now() AND d.message_id IS NULL ORDER BY m.created_at`,[cm[1],me.id]);return json(res,200,{messages:q.rows.map(r=>({...r,createdAt:new Date(r.created_at).getTime(),expiresAt:new Date(r.expires_at).getTime()}))});
  }
  if(cm&&req.method==='POST'){
    const c=await chatMember(cm[1],me.id);if(!c)return json(res,403,{error:'forbidden'});const b=await readBody(req);if(!String(b.ciphertext||'')||!String(b.iv||''))return json(res,400,{error:'empty_message'});const created=Date.now(),mid=id();const q=await pool.query('INSERT INTO messages(id,chat_id,sender_id,ciphertext,iv,created_at,expires_at) VALUES($1,$2,$3,$4,$5,to_timestamp($6/1000),to_timestamp($7/1000)) RETURNING *',[mid,cm[1],me.id,b.ciphertext,b.iv,created,created+MESSAGE_TTL_MS]);const m={...q.rows[0],createdAt:created,expiresAt:created+MESSAGE_TTL_MS};for(const u of [c.user_a,c.user_b])sendUser(u,{type:'message.created',message:m});return json(res,201,{message:m});
  }
  const mm=url.pathname.match(/^\/api\/messages\/([^/]+)$/);
  if(mm&&req.method==='PATCH'){
    const q=await pool.query('SELECT m.*,c.user_a,c.user_b FROM messages m JOIN chats c ON c.id=m.chat_id WHERE m.id=$1',[mm[1]]);if(!q.rowCount)return json(res,404,{error:'not_found'});const m=q.rows[0];if(![m.user_a,m.user_b].includes(me.id))return json(res,403,{error:'forbidden'});if(m.sender_id!==me.id)return json(res,403,{error:'not_owner'});if(new Date(m.expires_at).getTime()<=Date.now()){await pool.query('DELETE FROM messages WHERE id=$1',[m.id]);return json(res,410,{error:'expired'})}const b=await readBody(req);const u=await pool.query('UPDATE messages SET ciphertext=$1,iv=$2,edited=true WHERE id=$3 RETURNING *',[String(b.ciphertext||''),String(b.iv||''),m.id]);const out={...u.rows[0],createdAt:new Date(u.rows[0].created_at).getTime(),expiresAt:new Date(u.rows[0].expires_at).getTime()};for(const x of [m.user_a,m.user_b])sendUser(x,{type:'message.updated',message:out});return json(res,200,{message:out});
  }
  if(mm&&req.method==='DELETE'){
    const q=await pool.query('SELECT m.*,c.user_a,c.user_b FROM messages m JOIN chats c ON c.id=m.chat_id WHERE m.id=$1',[mm[1]]);if(!q.rowCount)return json(res,404,{error:'not_found'});const m=q.rows[0];if(![m.user_a,m.user_b].includes(me.id))return json(res,403,{error:'forbidden'});const mode=url.searchParams.get('mode')||'all';if(mode==='me'){await pool.query('INSERT INTO message_deletions(message_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[m.id,me.id]);return json(res,200,{deleted:true,mode:'me'})}if(m.sender_id!==me.id)return json(res,403,{error:'not_owner'});await pool.query('DELETE FROM messages WHERE id=$1',[m.id]);for(const x of [m.user_a,m.user_b])sendUser(x,{type:'message.deleted',chatId:m.chat_id,messageId:m.id,mode:'all'});return json(res,200,{deleted:true,mode:'all'});
  }
  const ch=url.pathname.match(/^\/api\/chats\/([^/]+)$/);
  if(ch&&req.method==='DELETE'){
    const c=await chatMember(ch[1],me.id);if(!c)return json(res,403,{error:'forbidden'});await pool.query('DELETE FROM chats WHERE id=$1',[ch[1]]);for(const x of [c.user_a,c.user_b])sendUser(x,{type:'conversation.deleted',chatId:ch[1]});return json(res,200,{deleted:true});
  }
  return null;
}
async function sharePayload(userId){const q=await pool.query('SELECT username,id FROM users WHERE id=$1',[userId]);if(!q.rowCount)throw new Error('not_found');const payload=Buffer.from(JSON.stringify({v:1,u:q.rows[0].username,id:q.rows[0].id,iat:Date.now()})).toString('base64url');return `${process.env.PUBLIC_BASE_URL||''}/?connect=${payload}`;}

async function handler(req,res){try{const url=new URL(req.url,`http://${req.headers.host}`);if(url.pathname.startsWith('/api/')){const handled=await api(req,res,url);if(handled!==null)return;}let file=url.pathname==='/'?'/index.html':url.pathname;const safe=path.normalize(file).replace(/^([.][.][/\\])+/, '');const full=path.join(PUBLIC,safe);if(!full.startsWith(PUBLIC))return json(res,403,{error:'forbidden'});fs.readFile(full,(err,data)=>{if(err)return json(res,404,{error:'not_found'});const ext=path.extname(full);const types={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.json':'application/json; charset=utf-8','.svg':'image/svg+xml'};res.writeHead(200,{'Content-Type':types[ext]||'application/octet-stream','Cache-Control':ext==='.html'?'no-store':'public,max-age=3600','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'self'; connect-src 'self' wss: https:; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"});res.end(data)})}catch(e){console.error(e);if(!res.headersSent)json(res,e.status||500,{error:'server_error'})}}

async function main(){await pool.query(schema);const cols=await pool.query("SELECT column_name FROM information_schema.columns WHERE table_name='users' AND column_name='recovery_hash'");if(!cols.rowCount)await pool.query("ALTER TABLE users ADD COLUMN recovery_hash char(64)");const oldUsers=await pool.query("SELECT id FROM users WHERE recovery_hash IS NULL");for(const u of oldUsers.rows)await pool.query('UPDATE users SET recovery_hash=$1 WHERE id=$2',[sha256(u.id),u.id]);await pool.query("ALTER TABLE users ALTER COLUMN recovery_hash SET NOT NULL"); await pool.query('DELETE FROM sessions WHERE expires_at<=now()');const useTls=process.env.HTTPS_KEY&&process.env.HTTPS_CERT;let server;if(useTls){server=https.createServer({key:fs.readFileSync(process.env.HTTPS_KEY),cert:fs.readFileSync(process.env.HTTPS_CERT)},handler)}else server=http.createServer(handler);const wss=new WebSocket.Server({server,path:'/ws'});wss.on('connection',async(ws,req)=>{try{const cookies=String(req.headers.cookie||'').match(/(?:^|; )session=([^;]+)/);let token=cookies?decodeURIComponent(cookies[1]):'';if(!token){const prot=String(req.headers['sec-websocket-protocol']||'').split(',').map(x=>x.trim());token=prot[1]||''}const q=await pool.query('SELECT u.id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now()',[sha256(token)]);if(!q.rowCount)return ws.close(1008,'unauthorized');const uid=q.rows[0].id;if(!sockets.has(uid))sockets.set(uid,new Set());sockets.get(uid).add(ws);ws.send(JSON.stringify({type:'ready',userId:uid}));ws.on('close',()=>{const set=sockets.get(uid);if(set){set.delete(ws);if(!set.size)sockets.delete(uid)}})}catch{ws.close(1011)}});server.listen(PORT,()=>console.log(`Private Messenger listening on ${useTls?'https':'http'}://localhost:${PORT}`))}
main().catch(e=>{console.error(e);process.exit(1)});
