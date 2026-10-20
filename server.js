// Servidor estático mínimo, sin dependencias. Railway define PORT.
const http=require('http'),fs=require('fs'),path=require('path');
const PORT=process.env.PORT||3000;
// Solo se entregan estos archivos; el código del servidor no queda expuesto.
const T={'index.html':'text/html; charset=utf-8','sw.js':'text/javascript; charset=utf-8','manifest.webmanifest':'application/manifest+json','icon-192.png':'image/png','icon-512.png':'image/png'};
http.createServer((q,r)=>{let p=decodeURIComponent(q.url.split('?')[0]).replace(/^\/+/,'')||'index.html';
if(!T[p]){r.writeHead(404,{'Content-Type':'text/plain; charset=utf-8'});return r.end('No encontrado')}
fs.readFile(path.join(__dirname,p),(e,d)=>{if(e){r.writeHead(404,{'Content-Type':'text/plain; charset=utf-8'});return r.end('No encontrado')}
r.writeHead(200,{'Content-Type':T[p],'Cache-Control':p==='sw.js'||p==='index.html'?'no-cache':'public, max-age=3600','X-Content-Type-Options':'nosniff'});r.end(d)})
}).listen(PORT,()=>console.log('WMS TMS GPS escuchando en el puerto '+PORT));
