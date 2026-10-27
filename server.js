// WMS + TMS + GPS · servidor Express + PostgreSQL. Una empresa; los usuarios los crea el Administrador.
const express=require('express'),{Pool}=require('pg'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),path=require('path'),fs=require('fs');
const PORT=process.env.PORT||3000,PROD=process.env.NODE_ENV==='production'||!!process.env.RAILWAY_ENVIRONMENT;
// Clave para firmar sesiones: si JWT_SECRET no existe o no es válida, el servidor genera una y la guarda en la base de datos.
let SECRET=process.env.JWT_SECRET||'';
if(SECRET&&!/^[A-Za-z0-9_\-+\/=.]{32,}$/.test(SECRET)){console.warn('JWT_SECRET no es válida (usa 32 o más letras y números, sin espacios ni símbolos de código). Se usará una clave generada automáticamente.');SECRET=''}
// El servidor siempre arranca; si la base de datos falla, muestra el motivo en pantalla y reintenta solo.
const DBURL=process.env.DATABASE_URL||'';
let DBOK=false,DBERR=DBURL?'Conectando con la base de datos…':'Falta la variable DATABASE_URL en Railway (servicio WMS_TMS → Variables).',pool=null;
if(DBURL.includes('${{'))DBERR='La variable DATABASE_URL no se resolvió: quedó escrita como texto con llaves. Bórrala y créala de nuevo como referencia al servicio Postgres.';
else if(DBURL){const local=/localhost|127\.0\.0\.1|\.railway\.internal/.test(DBURL);pool=new Pool({connectionString:DBURL,ssl:process.env.PGSSL==='disable'||local?false:{rejectUnauthorized:false}});pool.on('error',e=>console.error('Error del pool:',e.message))}
const ROLES=['Administrador','Bodeguero','Solicitante','Transporte'],COMUN=['seen','tut'];
// Qué partes de los datos puede modificar cada perfil (control mínimo en el servidor).
const PERMITE={Administrador:null,Bodeguero:['prods','lots','movs','reqs','blk','ords',...COMUN],Solicitante:['reqs',...COMUN],Transporte:['ords','reqs','veh','pl','gps','gv',...COMUN]};
const DUMMY=bcrypt.hashSync('relleno-contra-enumeracion',10);
const app=express();app.set('trust proxy',1);app.disable('x-powered-by');
const h=f=>(q,r,n)=>Promise.resolve(f(q,r,n)).catch(n);
app.use((q,r,n)=>{r.set({'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'same-origin'});if(PROD)r.set('Strict-Transport-Security','max-age=15552000');
 if(q.method!=='GET'&&q.method!=='HEAD'&&q.headers.origin){try{if(new URL(q.headers.origin).host!==q.headers.host)return r.status(403).json({error:'Origen no permitido'})}catch(e){return r.status(403).json({error:'Origen no permitido'})}}n()});
app.use(['/api','/health'],(q,r,n)=>{r.set('Cache-Control','no-store');DBOK?n():r.status(503).json({error:'El sistema no puede conectarse a la base de datos. '+DBERR})});
app.use(express.json({limit:'6mb'}));
const intentos=new Map();
function limite(clave,max,ms){const t=Date.now(),a=(intentos.get(clave)||[]).filter(x=>t-x<ms);if(a.length>=max){intentos.set(clave,a);return false}a.push(t);intentos.set(clave,a);return true}
setInterval(()=>{const t=Date.now();for(const[k,v]of intentos)if(!v.some(x=>t-x<9e5))intentos.delete(k)},6e5).unref();
const okCorreo=c=>typeof c==='string'&&c.length<=254&&/^[^\s@]{1,64}@[^\s@]+\.[^\s@]{2,}$/.test(c),okClave=c=>typeof c==='string'&&c.length>=10&&c.length<=128,txt=(s,mx)=>typeof s==='string'&&s.trim().length>=2&&s.trim().length<=mx;
const cookie=(t,mx)=>'wms_t='+t+'; HttpOnly; SameSite=Lax; Path=/; Max-Age='+mx+(PROD?'; Secure':'');
const leer=q=>{const m=(q.headers.cookie||'').match(/(?:^|;\s*)wms_t=([^;]+)/);return m?m[1]:null};
const publico=u=>({id:u.id,nombre:u.name,correo:u.email,perfil:u.role,activo:u.active});
async function auditar(c,cid,uid,a,d){try{await c.query('insert into audit(company_id,user_id,action,detail) values($1,$2,$3,$4)',[cid,uid,a,d||null])}catch(e){}}
const auth=h(async(q,r,n)=>{const t=leer(q);if(!t)return r.status(401).json({error:'No autenticado'});let p;try{p=jwt.verify(t,SECRET)}catch(e){return r.status(401).json({error:'Sesión vencida'})}
 const u=(await pool.query('select u.*,c.name as empresa from users u join companies c on c.id=u.company_id where u.id=$1',[p.uid])).rows[0];
 if(!u||!u.active||u.tv!==p.tv)return r.status(401).json({error:'Sesión no válida'});q.u=u;n()});
const solo=rol=>(q,r,n)=>q.u.role===rol?n():r.status(403).json({error:'Solo el '+rol+' puede hacer esto.'});
const sesion=(r,u)=>r.set('Set-Cookie',cookie(jwt.sign({uid:u.id,tv:u.tv},SECRET,{expiresIn:'7d'}),604800));
app.get('/health',h(async(q,r)=>{await pool.query('select 1');r.json({ok:true})}));
// Configuración inicial: solo funciona una vez, cuando todavía no existe ningún usuario.
app.get('/api/setup',h(async(q,r)=>r.json({necesaria:!(await pool.query('select 1 from users limit 1')).rowCount})));
app.post('/api/setup',h(async(q,r)=>{const{empresa,nombre,correo,clave}=q.body||{};
 if(!limite('setup:'+q.ip,10,36e5))return r.status(429).json({error:'Demasiados intentos. Espera un momento.'});
 if(!txt(empresa,80)||!txt(nombre,80)||!okCorreo(correo)||!okClave(clave))return r.status(400).json({error:'Revisa los datos: empresa y nombre (2 a 80 caracteres), un correo válido y una contraseña de al menos 10 caracteres.'});
 const em=correo.trim().toLowerCase(),hash=await bcrypt.hash(clave,10),c=await pool.connect();
 try{await c.query('begin');await c.query('select pg_advisory_xact_lock(7001)');
  if((await c.query('select 1 from users limit 1')).rowCount){await c.query('rollback');return r.status(409).json({error:'El sistema ya fue configurado. Ingresa con tu cuenta.'})}
  const co=(await c.query('insert into companies(name) values($1) returning id',[empresa.trim()])).rows[0];
  const u=(await c.query("insert into users(company_id,email,name,role,pass_hash) values($1,$2,$3,'Administrador',$4) returning *",[co.id,em,nombre.trim(),hash])).rows[0];
  await c.query("insert into states(company_id,data) values($1,'{}'::jsonb)",[co.id]);await auditar(c,co.id,u.id,'sistema_configurado',empresa.trim());await c.query('commit');
  sesion(r,u);r.status(201).json({ok:true})}catch(e){try{await c.query('rollback')}catch(_){}throw e}finally{c.release()}}));
app.post('/api/auth/login',h(async(q,r)=>{const{correo,clave}=q.body||{};if(typeof correo!=='string'||typeof clave!=='string')return r.status(400).json({error:'Faltan datos.'});
 const em=correo.trim().toLowerCase();if(!limite('log:'+q.ip+':'+em,10,9e5))return r.status(429).json({error:'Demasiados intentos. Espera 15 minutos.'});
 const u=(await pool.query('select * from users where email=$1',[em])).rows[0],ok=await bcrypt.compare(clave,u?u.pass_hash:DUMMY);
 if(!u||!ok)return r.status(401).json({error:'Correo o contraseña incorrectos.'});
 if(!u.active)return r.status(403).json({error:'Tu cuenta está inactiva. Pide al administrador de tu empresa que la active.'});
 await auditar(pool,u.company_id,u.id,'ingreso');sesion(r,u);r.json({ok:true})}));
app.post('/api/auth/logout',(q,r)=>{r.set('Set-Cookie',cookie('',0));r.json({ok:true})});
app.get('/api/me',auth,(q,r)=>r.json({user:{id:q.u.id,name:q.u.name,email:q.u.email,role:q.u.role},empresa:q.u.empresa}));
app.get('/api/state',auth,h(async(q,r)=>{const s=(await pool.query('select data,version from states where company_id=$1',[q.u.company_id])).rows[0];
 if(q.query.since!==undefined&&+q.query.since===s.version)return r.json({unchanged:true,version:s.version});r.json({data:s.data,version:s.version})}));
function cambios(rol,a,b){const ok=PERMITE[rol];if(!ok)return null;a=a||{};for(const k of new Set([...Object.keys(a),...Object.keys(b)]))if(!ok.includes(k)&&JSON.stringify(a[k])!==JSON.stringify(b[k]))return k;return null}
app.put('/api/state',auth,h(async(q,r)=>{const{data,version}=q.body||{};if(!data||typeof data!=='object'||Array.isArray(data)||!Number.isInteger(version))return r.status(400).json({error:'Datos inválidos.'});
 const c=await pool.connect();try{await c.query('begin');const s=(await c.query('select data,version from states where company_id=$1 for update',[q.u.company_id])).rows[0];
  if(s.version!==version){await c.query('rollback');return r.status(409).json({error:'Otro usuario guardó antes.',version:s.version})}
  const k=cambios(q.u.role,s.data,data);if(k){await c.query('rollback');return r.status(403).json({error:'Tu perfil ('+q.u.role+') no puede modificar «'+k+'».'})}
  const up=(await c.query('update states set data=$1::jsonb,version=version+1,updated_at=now(),updated_by=$2 where company_id=$3 returning version',[JSON.stringify(data),q.u.id,q.u.company_id])).rows[0];
  await c.query('commit');r.json({version:up.version})}catch(e){try{await c.query('rollback')}catch(_){}throw e}finally{c.release()}}));
app.get('/api/users',auth,solo('Administrador'),h(async(q,r)=>r.json({users:(await pool.query('select * from users where company_id=$1 order by id',[q.u.company_id])).rows.map(publico)})));
app.post('/api/users',auth,solo('Administrador'),h(async(q,r)=>{const{nombre,correo,perfil,clave}=q.body||{};
 if(!txt(nombre,80)||!okCorreo(correo)||!ROLES.includes(perfil)||!okClave(clave))return r.status(400).json({error:'Revisa los datos: nombre, correo válido, perfil y una contraseña temporal de al menos 10 caracteres.'});
 const em=correo.trim().toLowerCase();if((await pool.query('select 1 from users where email=$1',[em])).rowCount)return r.status(409).json({error:'Ese correo ya está registrado.'});
 const u=(await pool.query('insert into users(company_id,email,name,role,pass_hash) values($1,$2,$3,$4,$5) returning *',[q.u.company_id,em,nombre.trim(),perfil,await bcrypt.hash(clave,10)])).rows[0];
 await auditar(pool,q.u.company_id,q.u.id,'usuario_creado',em);r.status(201).json({user:publico(u)})}));
app.patch('/api/users/:id',auth,solo('Administrador'),h(async(q,r)=>{const id=+q.params.id,{nombre,perfil,activo,clave}=q.body||{};
 const u=Number.isInteger(id)?(await pool.query('select * from users where id=$1 and company_id=$2',[id,q.u.company_id])).rows[0]:null;if(!u)return r.status(404).json({error:'Usuario no encontrado.'});
 const np=perfil===undefined?u.role:perfil,na=activo===undefined?u.active:activo,nn=nombre===undefined?u.name:nombre;
 if(!ROLES.includes(np)||typeof na!=='boolean'||!txt(nn,80)||(clave!==undefined&&!okClave(clave)))return r.status(400).json({error:'Datos inválidos. La contraseña necesita al menos 10 caracteres.'});
 if(u.id===q.u.id&&!na)return r.status(400).json({error:'No puedes desactivar tu propia cuenta.'});
 if(u.role==='Administrador'&&u.active&&(np!=='Administrador'||!na)&&!(await pool.query("select 1 from users where company_id=$1 and role='Administrador' and active and id<>$2",[q.u.company_id,u.id])).rowCount)return r.status(400).json({error:'La empresa debe conservar al menos un Administrador activo.'});
 const hash=clave!==undefined?await bcrypt.hash(clave,10):u.pass_hash,sube=clave!==undefined||!na||np!==u.role;
 const n=(await pool.query('update users set name=$1,role=$2,active=$3,pass_hash=$4,tv=tv+$5 where id=$6 returning *',[nn.trim(),np,na,hash,sube?1:0,u.id])).rows[0];
 await auditar(pool,q.u.company_id,q.u.id,'usuario_modificado',u.email+(clave!==undefined?' (clave)':''));r.json({user:publico(n)})}));
const ARCH={'index.html':'text/html; charset=utf-8','sw.js':'text/javascript; charset=utf-8','manifest.webmanifest':'application/manifest+json','icon-192.png':'image/png','icon-512.png':'image/png'};
app.get(/^\/(?!api\/).*/,(q,r)=>{const p=decodeURIComponent(q.path).replace(/^\/+/,'')||'index.html';if(!ARCH[p])return r.status(404).type('text/plain; charset=utf-8').send('No encontrado');
 r.set({'Content-Type':ARCH[p],'Cache-Control':p==='sw.js'||p==='index.html'?'no-cache':'public, max-age=3600'});fs.createReadStream(path.join(__dirname,p)).on('error',()=>r.status(404).end()).pipe(r)});
app.use((e,q,r,n)=>{if(e.type==='entity.parse.failed'||e.type==='entity.too.large')return r.status(400).json({error:'Solicitud inválida.'});console.error(e);r.status(500).json({error:'Error del servidor.'})});
const SQL=`create table if not exists companies(id serial primary key,name text not null,created_at timestamptz default now());
create table if not exists users(id serial primary key,company_id int not null references companies(id) on delete cascade,email text not null unique,name text not null,role text not null check(role in ('Administrador','Bodeguero','Solicitante','Transporte')),active boolean not null default true,pass_hash text not null,tv int not null default 0,created_at timestamptz default now());
create table if not exists states(company_id int primary key references companies(id) on delete cascade,data jsonb not null default '{}',version int not null default 1,updated_at timestamptz default now(),updated_by int);
create table if not exists settings(k text primary key,v text not null);
create table if not exists audit(id bigserial primary key,company_id int,user_id int,action text not null,detail text,at timestamptz default now())`;
const MOTIVO=e=>{const c=e&&e.code;if(['ECONNREFUSED','ENOTFOUND','ETIMEDOUT','EAI_AGAIN','ECONNRESET'].includes(c))return 'No se pudo contactar el servidor de la base ('+c+'). Revisa que el servicio Postgres esté Online y que DATABASE_URL apunte a él.';if(c==='28P01'||c==='28000')return 'La base rechazó el usuario o la contraseña de DATABASE_URL.';if(c==='3D000')return 'La base indicada en DATABASE_URL no existe.';if(/SSL/i.test(String(e&&e.message)))return 'Falló la conexión segura (SSL) con la base.';return 'Error al preparar la base'+(c?' (código '+c+')':'')+'.'};
async function prepararDB(){try{await pool.query(SQL);if(!SECRET){await pool.query("insert into settings(k,v) values('jwt',$1) on conflict (k) do nothing",[require('crypto').randomBytes(48).toString('hex')]);SECRET=(await pool.query("select v from settings where k='jwt'")).rows[0].v}DBOK=true;DBERR='';console.log('Base de datos lista.')}catch(e){DBERR=MOTIVO(e);console.error('No se pudo preparar la base de datos:',e.message);setTimeout(prepararDB,10000)}}
app.listen(PORT,()=>console.log('WMS TMS GPS escuchando en el puerto '+PORT));
if(pool)prepararDB();else console.error(DBERR);
