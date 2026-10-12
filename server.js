const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = __dirname;
const PORT = process.env.PORT || 8080;

const ADMIN_HASH = '7c4ef8b7e0b8b6a8e776f5161acc3a323673a7f13edca8386aeb74137214b671';
const adminTokens = new Set();

function sha256(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.ico': 'image/x-icon',
  '.json': 'application/json',
  '.xml': 'application/xml',
  '.php': 'text/html; charset=utf-8',
};

const server = http.createServer((req, res) => {
  let reqPath = decodeURIComponent(req.url.split('?')[0]);

  if (req.method === 'POST' && reqPath === '/admin/login') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        const hash = sha256(data.password || '');
        if (hash === ADMIN_HASH) {
          const token = crypto.randomBytes(32).toString('hex');
          adminTokens.add(token);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, token: token }));
        } else {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, message: 'كلمة المرور غير صحيحة' }));
        }
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, message: 'خطأ في الطلب' }));
      }
    });
    return;
  }

  if (reqPath.startsWith('/admin/') || reqPath === '/admin') {
    if (reqPath === '/admin' || reqPath === '/admin/') {
      const cookies = (req.headers.cookie || '').split(';').reduce((acc, c) => {
        const [k, v] = c.trim().split('=');
        if (k) acc[k] = v;
        return acc;
      }, {});
      if (!cookies.admin_token || !adminTokens.has(cookies.admin_token)) {
        const loginPage = path.join(ROOT, 'admin', 'login.html');
        if (fs.existsSync(loginPage)) {
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          fs.createReadStream(loginPage).pipe(res);
          return;
        }
      }
    }
  }

  if (!reqPath.endsWith('/') && !path.extname(reqPath)) {
    const dirPath = path.join(ROOT, reqPath);
    if (fs.existsSync(dirPath) && fs.statSync(dirPath).isDirectory()) {
      res.writeHead(301, { 'Location': reqPath + '/' });
      return res.end();
    }
  }

  if (reqPath.endsWith('/')) reqPath += 'index.html';

  const filePath = path.join(ROOT, reqPath);

  if (!fs.existsSync(filePath)) {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    return res.end('Not found: ' + reqPath);
  }

  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME[ext] || 'application/octet-stream';

  res.writeHead(200, { 'Content-Type': contentType });
  fs.createReadStream(filePath).pipe(res);
});

server.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
  console.log(`Arabic:  http://localhost:${PORT}/ar/`);
  console.log(`English: http://localhost:${PORT}/en/`);
  console.log(`Admin:   http://localhost:${PORT}/admin/`);
});
