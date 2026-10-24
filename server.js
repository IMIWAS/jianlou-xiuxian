/**
 * 捡漏修仙系统 · 云端后端
 * 零外部依赖：Node 原生 http + crypto(scrypt) + JSON 文件数据库
 * 运行：node server.js  （默认 8000 端口，监听 0.0.0.0，手机连同一 WiFi 即可用）
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

const PORT = process.env.PORT || 8000;
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const TOKEN_TTL = 30 * 24 * 3600 * 1000; // token 30 天有效

/* ---------------- 迷你 JSON 数据库 ---------------- */
function loadDb() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch (e) { return { users: [], tokens: {}, saves: {} }; }
}
function saveDb(db) {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DB_FILE); // 原子写入，防写一半断电
}

/* ---------------- 密码 & Token ---------------- */
function hashPassword(pw, salt) {
  return crypto.scryptSync(pw, salt, 32).toString('hex');
}
function issueToken(db, userId) {
  const token = crypto.randomBytes(32).toString('hex');
  db.tokens[token] = { userId, expiresAt: Date.now() + TOKEN_TTL };
  return token;
}
function authUser(db, req) {
  const h = req.headers['authorization'] || '';
  const t = h.replace(/^Bearer\s+/i, '');
  const rec = db.tokens[t];
  if (!rec) return null;
  if (rec.expiresAt < Date.now()) { delete db.tokens[t]; saveDb(db); return null; }
  const user = db.users.find(u => u.id === rec.userId);
  return user ? { token: t, user } : null;
}
const isPhone = p => /^1[3-9]\d{9}$/.test(p);
const pubUser = u => ({ id: u.id, phone: u.phone, nickname: u.nickname });

/* ---------------- 工具 ---------------- */
function readBody(req) {
  return new Promise((resolve, reject) => {
    let b = '';
    req.on('data', c => { b += c; if (b.length > 1e6) { reject(new Error('too big')); req.destroy(); } });
    req.on('end', () => { try { resolve(b ? JSON.parse(b) : {}); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}
function send(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}

/* ---------------- API ---------------- */
async function handleApi(req, res, url) {
  const db = loadDb();

  // 注册
  if (url === '/api/auth/register' && req.method === 'POST') {
    const { phone, password, nickname } = await readBody(req);
    if (!isPhone(phone || '')) return send(res, 400, { error: '手机号格式不对，道友再瞧瞧' });
    if (!password || password.length < 6) return send(res, 400, { error: '密码至少 6 位' });
    if (db.users.some(u => u.phone === phone)) return send(res, 409, { error: '该手机号已在协会登记过了' });
    const salt = crypto.randomBytes(16).toString('hex');
    const user = {
      id: crypto.randomUUID(),
      phone,
      nickname: (nickname || '').trim() || ('漏友' + phone.slice(-4)),
      salt, hash: hashPassword(password, salt),
      createdAt: Date.now()
    };
    db.users.push(user);
    const token = issueToken(db, user.id);
    saveDb(db);
    return send(res, 200, { token, user: pubUser(user) });
  }

  // 登录
  if (url === '/api/auth/login' && req.method === 'POST') {
    const { phone, password } = await readBody(req);
    const user = db.users.find(u => u.phone === phone);
    if (!user) return send(res, 404, { error: '此手机号尚未登记，先去注册' });
    if (hashPassword(password || '', user.salt) !== user.hash) return send(res, 401, { error: '密码不对，再想想' });
    const token = issueToken(db, user.id);
    saveDb(db);
    return send(res, 200, { token, user: pubUser(user) });
  }

  // 以下需要登录
  const auth = authUser(db, req);
  if (!auth) return send(res, 401, { error: '未登录或令牌已过期' });

  // 当前用户
  if (url === '/api/me' && req.method === 'GET') {
    return send(res, 200, { user: pubUser(auth.user) });
  }

  // 拉取存档
  if (url === '/api/save' && req.method === 'GET') {
    const rec = db.saves[auth.user.id];
    return send(res, 200, { state: rec ? rec.state : null });
  }

  // 上传存档（整体覆盖，带 updatedAt 做最后写入胜出）
  if (url === '/api/save' && req.method === 'PUT') {
    const { state } = await readBody(req);
    if (!state || typeof state !== 'object') return send(res, 400, { error: '存档格式不对' });
    const old = db.saves[auth.user.id];
    if (old && (old.state.updatedAt || 0) > (state.updatedAt || 0)) {
      return send(res, 200, { ok: true, ignored: true }); // 云端更新，忽略旧写入
    }
    db.saves[auth.user.id] = { state, savedAt: Date.now() };
    saveDb(db);
    return send(res, 200, { ok: true });
  }

  // 登出
  if (url === '/api/auth/logout' && req.method === 'POST') {
    delete db.tokens[auth.token];
    saveDb(db);
    return send(res, 200, { ok: true });
  }

  send(res, 404, { error: '没有这个接口' });
}

/* ---------------- 静态文件 ---------------- */
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon', '.json': 'application/json; charset=utf-8'
};
function serveStatic(req, res, url) {
  let p = decodeURIComponent(url);
  if (p === '/') p = '/index.html';
  const file = path.join(ROOT, path.normalize(p).replace(/^([/\\])+/, ''));
  if (!file.startsWith(ROOT) || file.startsWith(DATA_DIR)) { // 防目录穿越 + db.json 不外泄
    res.writeHead(403); return res.end('Forbidden');
  }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); return res.end('404 Not Found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream' });
    res.end(data);
  });
}

/* ---------------- 启动 ---------------- */
const server = http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];
  try {
    if (url.startsWith('/api/')) await handleApi(req, res, url);
    else if (req.method === 'GET') serveStatic(req, res, url);
    else { res.writeHead(405); res.end(); }
  } catch (e) {
    send(res, 500, { error: '服务器开小差了：' + e.message });
  }
});

server.listen(PORT, '0.0.0.0', () => {
  const lan = Object.values(os.networkInterfaces()).flat()
    .find(i => i && i.family === 'IPv4' && !i.internal);
  console.log('====================================');
  console.log('  捡漏修仙系统 · 云端服务器已启动');
  console.log('  本机访问: http://127.0.0.1:' + PORT);
  if (lan) console.log('  手机访问: http://' + lan.address + ':' + PORT + '  (需同一 WiFi)');
  console.log('====================================');
});
