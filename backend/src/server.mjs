import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import multer from 'multer';
import {randomBytes,createHash} from 'node:crypto';
import {mkdir,unlink} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {pool,transaction} from './db.mjs';
import {check,text,id,qty,money,day,normalizeQuote,totals,clientQuote,room,remainingDemand} from './domain.mjs';
const app=express();
const base=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const uploadDir=path.join(base,'uploads');await mkdir(uploadDir,{recursive:true});
if(process.env.TRUST_PROXY==='true'||process.env.RENDER==='true')app.set('trust proxy',1);
app.disable('x-powered-by');app.use(helmet());app.use(express.json({limit:'2mb'}));app.use(cookieParser());
const hash=x=>createHash('sha256').update(x).digest('hex');
const secure=process.env.NODE_ENV==='production';
const cookieOptions={httpOnly:true,sameSite:'strict',secure,path:'/'};
const configuredOrigins=(process.env.APP_ORIGIN||'').split(',').map(s=>s.trim()).filter(Boolean);
const allowedOrigins=new Set([...configuredOrigins,process.env.RENDER_EXTERNAL_URL,'http://localhost:5173','http://127.0.0.1:5173'].filter(Boolean));
app.use('/api',(req,res,next)=>{
 const reqOrigin=req.get('origin');
 if(!['GET','HEAD','OPTIONS'].includes(req.method)&&reqOrigin&&!allowedOrigins.has(reqOrigin))return res.status(403).json({error:'Untrusted browser origin. Check APP_ORIGIN in backend/.env.'});
 next();
});
const route=fn=>(req,res,next)=>Promise.resolve(fn(req,res)).catch(next);
const loginAttempts=new Map();
setInterval(()=>{for(const [k,v] of loginAttempts)if(Date.now()>v.until)loginAttempts.delete(k);},60000).unref();
app.post('/api/login',route(async(req,res)=>{
 const key=req.ip;const attempts=loginAttempts.get(key)||{count:0,until:Date.now()+900000};
 check(attempts.count<10,'Too many login attempts; try again after 15 minutes.');attempts.count++;loginAttempts.set(key,attempts);
 const username=text(req.body.username,100);const password=text(req.body.password,200);
 const u=(await pool.query('SELECT * FROM users WHERE username=$1 AND active=true',[username])).rows[0];
 if(!u||!await bcrypt.compare(password,u.password_hash))return res.status(401).json({error:'Invalid username or password'});
 loginAttempts.delete(key);const token=randomBytes(32).toString('hex');
 const hours=Number(process.env.SESSION_HOURS||8);check(Number.isFinite(hours)&&hours>0&&hours<=168,'Invalid SESSION_HOURS configuration');
 await transaction(async c=>{await c.query('DELETE FROM sessions WHERE expires_at<now()');await c.query("INSERT INTO sessions VALUES($1,$2,now()+$3*interval '1 hour')",[hash(token),u.id,hours]);await c.query('INSERT INTO audit_logs(user_id,action,details,ip) VALUES($1,$2,$3,$4)',[u.id,'login',{},req.ip]);});
 res.cookie('session',token,{...cookieOptions,maxAge:hours*3600000});res.json({id:u.id,username:u.username,display_name:u.display_name,role:u.role});
}));
app.use('/api',async(req,res,next)=>{
 try{
  const token=req.cookies.session;
  if(!token)return res.status(401).json({error:'Please sign in'});
  const u=(await pool.query('SELECT u.id,u.username,u.display_name,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now() AND u.active=true',[hash(token)])).rows[0];
  if(!u)return res.status(401).json({error:'Session expired. Sign in again.'});req.user=u;next();
 }catch(e){next(e);}
});
const authRouter=express.Router();
const admin=req=>check(req.user.role==='Admin','Administrator permission required');
const audit=async(c,req,action,details)=>c.query('INSERT INTO audit_logs(user_id,action,details,ip) VALUES($1,$2,$3,$4)',[req.user.id,action,details,req.ip]);
const write=(url,action,fn)=>authRouter.post(url,route(async(req,res)=>{
 const data=await transaction(async c=>{const result=await fn(c,req);await audit(c,req,action,{record_id:result?.id||req.params.id||null});return result;});res.json(data||{ok:true});
}));
const one=async(c,sql,args=[],message='Record not found')=>{const r=(await c.query(sql,args)).rows[0];check(r,message);return r;};
const party=async(c,pid,kind)=>one(c,'SELECT * FROM parties WHERE id=$1 AND kind=$2 AND archived=false',[id(pid),kind],'Select an active '+kind);
async function lockOrder(c,oid){return one(c,'SELECT * FROM orders WHERE id=$1 FOR UPDATE',[id(oid)]);}
async function activeOrder(c,oid){const o=await lockOrder(c,oid);check(o.status==='active','Order is cancelled');return o;}
async function lockItem(c,itemid){const found=await one(c,'SELECT order_id FROM order_items WHERE id=$1',[id(itemid)]);await activeOrder(c,found.order_id);return one(c,'SELECT * FROM order_items WHERE id=$1 FOR UPDATE',[itemid]);}
async function demand(c,item){
 const reserved=Number((await c.query("SELECT COALESCE(sum(quantity_milli),0) n FROM stock_reservations WHERE order_item_id=$1 AND status='reserved'",[item.id])).rows[0].n);
 const committed=Number((await c.query("SELECT COALESCE(sum(pi.quantity_milli-pi.received_milli),0) n FROM purchase_order_items pi JOIN purchase_orders p ON p.id=pi.po_id WHERE pi.order_item_id=$1 AND p.status='open'",[item.id])).rows[0].n);
 return remainingDemand(item,reserved,committed);
}
authRouter.get('/me',(req,res)=>res.json(req.user));
write('/logout','logout',async(c,req)=>{await c.query('DELETE FROM sessions WHERE token_hash=$1',[hash(req.cookies.session)]);});
authRouter.get('/bootstrap',route(async(req,res)=>{
 const tables=['parties','quotations','orders','purchase_orders','receipts','deliveries','stock_lots','stock_reservations','stock_requests','catalog'];const out={};
 await transaction(async c=>{await c.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');for(const t of tables)out[t]=(await c.query(`SELECT * FROM ${t} ORDER BY id DESC LIMIT 1000`)).rows;
 out.order_items=(await c.query('SELECT * FROM order_items ORDER BY id DESC LIMIT 5000')).rows;
 out.po_items=(await c.query('SELECT * FROM purchase_order_items ORDER BY id DESC LIMIT 5000')).rows;
 out.movements=(await c.query('SELECT * FROM stock_movements ORDER BY id DESC LIMIT 1000')).rows;
 if(req.user.role==='Admin'){out.users=(await c.query('SELECT id,username,display_name,role,active FROM users ORDER BY id')).rows;out.audit=(await c.query('SELECT a.*,u.username FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 300')).rows;}
 });out.company={name:process.env.COMPANY_NAME||'Your Company',address:process.env.COMPANY_ADDRESS||''};out.limit_notice='Lists display the most recent 1,000 records (5,000 item rows); audit displays 300 events. JSON export includes all business records.';res.json(out);
}));
write('/users','create_account',async(c,req)=>{admin(req);const b=req.body;check(['Admin','User'].includes(b.role),'Invalid role');check(typeof b.password==='string'&&b.password.length>=12&&Buffer.byteLength(b.password)<=72,'Password must be 12-72 bytes');return (await c.query('INSERT INTO users(username,display_name,password_hash,role) VALUES($1,$2,$3,$4) RETURNING id',[text(b.username,100),text(b.display_name,100),await bcrypt.hash(b.password,12),b.role])).rows[0];});
write('/users/:id','update_account',async(c,req)=>{admin(req);await c.query('LOCK TABLE users IN EXCLUSIVE MODE');const uid=id(req.params.id);const u=await one(c,'SELECT * FROM users WHERE id=$1',[uid]);const b=req.body;check(['Admin','User'].includes(b.role)&&typeof b.active==='boolean','Invalid account fields');
 if(u.role==='Admin'&&u.active&&(b.role!=='Admin'||!b.active)){const n=Number((await c.query("SELECT count(*) n FROM users WHERE active AND role='Admin'")).rows[0].n);check(n>1,'Keep at least one active Admin');}
 await c.query('UPDATE users SET role=$1,active=$2 WHERE id=$3',[b.role,b.active,uid]);
 if(b.password){check(typeof b.password==='string'&&b.password.length>=12&&Buffer.byteLength(b.password)<=72,'Password must be 12-72 bytes');await c.query('UPDATE users SET password_hash=$1 WHERE id=$2',[await bcrypt.hash(b.password,12),uid]);}
 await c.query('DELETE FROM sessions WHERE user_id=$1',[uid]);return {id:uid};
});
write('/catalog','add_catalog_item',async(c,req)=>{const b=req.body;return (await c.query('INSERT INTO catalog(name,description,unit) VALUES($1,$2,$3) RETURNING id',[text(b.name,200),text(b.description),text(b.unit,60)])).rows[0];});
write('/parties','save_contact',async(c,req)=>{const b=req.body;check(['client','supplier'].includes(b.kind),'Invalid contact type');const vals=[b.kind,text(b.name,200),String(b.contact||''),String(b.phone||''),String(b.email||''),String(b.address||'')];
 if(b.id){return (await c.query('UPDATE parties SET kind=$1,name=$2,contact=$3,phone=$4,email=$5,address=$6 WHERE id=$7 AND kind=$1 RETURNING id',[...vals,id(b.id)])).rows[0]||check(false,'Contact not found or type cannot be changed');}
 return (await c.query('INSERT INTO parties(kind,name,contact,phone,email,address) VALUES($1,$2,$3,$4,$5,$6) RETURNING id',vals)).rows[0];
});
write('/parties/:id/archive','archive_contact',async(c,req)=>{admin(req);await c.query('UPDATE parties SET archived=$1 WHERE id=$2',[req.body.archived===true,id(req.params.id)]);return {id:req.params.id};});
write('/quotations','save_quotation',async(c,req)=>{const b=req.body;await party(c,b.client_id,'client');const data=normalizeQuote(b);for(const l of data.lines)for(const o of l.offers)await party(c,o.supplier_id,'supplier');
 if(b.id){const q=await one(c,'SELECT * FROM quotations WHERE id=$1 FOR UPDATE',[id(b.id)]);check(q.status==='draft','Only draft quotations may be edited');check(Number(b.revision)===q.revision,'Revision changed; reload the quotation');return (await c.query('UPDATE quotations SET number=$1,client_id=$2,data=$3 WHERE id=$4 RETURNING id',[text(b.number,100),id(b.client_id),data,q.id])).rows[0];}
 return (await c.query('INSERT INTO quotations(number,client_id,data,created_by) VALUES($1,$2,$3,$4) RETURNING id',[text(b.number,100),id(b.client_id),data,req.user.id])).rows[0];
});
write('/quotations/:id/finalize','finalize_quotation',async(c,req)=>{const q=await one(c,'SELECT * FROM quotations WHERE id=$1 FOR UPDATE',[id(req.params.id)]);check(q.status==='draft','Quotation is not a draft');const p=await party(c,q.client_id,'client');const snapshot={...q,client:p};await c.query('INSERT INTO quotation_versions(quotation_id,revision,snapshot,finalized_by) VALUES($1,$2,$3,$4)',[q.id,q.revision,snapshot,req.user.id]);await c.query("UPDATE quotations SET status='final' WHERE id=$1",[q.id]);return {id:q.id};});
write('/quotations/:id/revise','revise_quotation',async(c,req)=>{const q=await one(c,'SELECT * FROM quotations WHERE id=$1 FOR UPDATE',[id(req.params.id)]);check(['final','lost'].includes(q.status),'Only final/lost quotations may be revised; accepted orders are locked');await c.query("UPDATE quotations SET revision=revision+1,status='draft' WHERE id=$1",[q.id]);return {id:q.id};});
write('/quotations/:id/lost','close_quotation',async(c,req)=>{const q=await one(c,'SELECT * FROM quotations WHERE id=$1 FOR UPDATE',[id(req.params.id)]);check(q.status==='final','Finalize before marking lost');await c.query("UPDATE quotations SET status='lost' WHERE id=$1",[q.id]);return {id:q.id};});
authRouter.get('/quotations/:id/versions',route(async(req,res)=>res.json((await pool.query('SELECT revision,finalized_at FROM quotation_versions WHERE quotation_id=$1 ORDER BY revision',[id(req.params.id)])).rows)));
write('/quotations/:id/accept','accept_quotation',async(c,req)=>{const q=await one(c,'SELECT * FROM quotations WHERE id=$1 FOR UPDATE',[id(req.params.id)]);check(q.status==='final','Only a finalized current quotation can be accepted');const b=req.body;check(Array.isArray(b.lines)&&b.lines.length>0,'Choose accepted quantities');const o=(await c.query('INSERT INTO orders(quotation_id,revision,acceptance_reference) VALUES($1,$2,$3) RETURNING *',[q.id,q.revision,text(b.reference,500)])).rows[0];const seen=new Set();
 for(const a of b.lines){check(!seen.has(a.key),'Duplicate item');seen.add(a.key);const l=q.data.lines.find(x=>x.key===a.key&&x.included);check(l,'Invalid quotation line');const n=qty(a.quantity);check(n<=l.quantity_milli,'Accepted quantity exceeds quotation');await c.query('INSERT INTO order_items(order_id,line_key,description,unit,ordered_milli,cost_cents,price_cents,supplier_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',[o.id,l.key,l.description,l.unit,n,l.cost_cents,l.price_cents,l.offers[l.selected_offer]?.supplier_id||null]);}
 await c.query("UPDATE quotations SET status='accepted' WHERE id=$1",[q.id]);return {id:o.id};
});
write('/orders/:id/cancel','cancel_order',async(c,req)=>{const o=await activeOrder(c,req.params.id);await c.query("UPDATE orders SET status='cancelled' WHERE id=$1",[o.id]);await c.query("UPDATE purchase_orders SET status='cancelled' WHERE order_id=$1",[o.id]);await c.query("UPDATE stock_reservations SET status='released' WHERE status='reserved' AND order_item_id IN(SELECT id FROM order_items WHERE order_id=$1)",[o.id]);return {id:o.id};});
write('/purchase-orders','create_purchase_order',async(c,req)=>{const b=req.body;await activeOrder(c,b.order_id);await party(c,b.supplier_id,'supplier');check(Array.isArray(b.lines)&&b.lines.length>0,'Add purchase lines');const p=(await c.query('INSERT INTO purchase_orders(number,supplier_id,order_id,terms) VALUES($1,$2,$3,$4) RETURNING *',[text(b.number,100),id(b.supplier_id),id(b.order_id),String(b.terms||'')])).rows[0];const seen=new Set();
 for(const l of b.lines){const iid=id(l.item_id);check(!seen.has(iid),'Duplicate purchase line');seen.add(iid);const item=await lockItem(c,iid);check(item.order_id===p.order_id,'Item belongs to another order');const n=qty(l.quantity);check(n<=await demand(c,item),'Quantity exceeds uncommitted order demand');await c.query('INSERT INTO purchase_order_items(po_id,order_item_id,quantity_milli,cost_cents) VALUES($1,$2,$3,$4)',[p.id,item.id,n,money(l.cost)]);}
 return {id:p.id};
});
write('/purchase-orders/:id/cancel','cancel_purchase_order',async(c,req)=>{const p=await one(c,'SELECT * FROM purchase_orders WHERE id=$1',[id(req.params.id)]);await lockOrder(c,p.order_id);await c.query("UPDATE purchase_orders SET status='cancelled' WHERE id=$1",[p.id]);return {id:p.id};});
write('/purchase-orders/:id/receive','receive_purchase',async(c,req)=>{const p=await one(c,'SELECT * FROM purchase_orders WHERE id=$1',[id(req.params.id)]);await activeOrder(c,p.order_id);const fresh=await one(c,'SELECT * FROM purchase_orders WHERE id=$1 FOR UPDATE',[p.id]);check(fresh.status==='open','Purchase order is cancelled');const b=req.body;check(Array.isArray(b.lines)&&b.lines.length>0,'Enter received quantities');const lines=[];const seen=new Set();
 for(const l of b.lines){const li=await one(c,'SELECT * FROM purchase_order_items WHERE id=$1 AND po_id=$2 FOR UPDATE',[id(l.id),p.id]);check(!seen.has(li.id),'Duplicate receipt line');seen.add(li.id);const n=qty(l.quantity);check(n<=Number(li.quantity_milli)-Number(li.received_milli),'Receipt exceeds remaining PO quantity');const item=await one(c,'SELECT * FROM order_items WHERE id=$1 FOR UPDATE',[li.order_item_id]);await c.query('UPDATE purchase_order_items SET received_milli=received_milli+$1 WHERE id=$2',[n,li.id]);await c.query('UPDATE order_items SET received_milli=received_milli+$1 WHERE id=$2',[n,item.id]);lines.push({item_id:item.id,description:item.description,unit:item.unit,quantity_milli:n,cost_cents:Number(li.cost_cents)});}
 return (await c.query('INSERT INTO receipts(po_id,reference,received_at,notes,lines,created_by) VALUES($1,$2,$3,$4,$5,$6) RETURNING id',[p.id,text(b.reference,200),day(b.date),String(b.notes||''),JSON.stringify(lines),req.user.id])).rows[0];
});
write('/orders/:id/deliver','deliver_order',async(c,req)=>{const o=await activeOrder(c,req.params.id);const b=req.body;check(Array.isArray(b.lines)&&b.lines.length>0,'Enter delivery quantities');const lines=[];const seen=new Set();for(const l of b.lines){const item=await one(c,'SELECT * FROM order_items WHERE id=$1 AND order_id=$2 FOR UPDATE',[id(l.item_id),o.id]);check(!seen.has(item.id),'Duplicate delivery item');seen.add(item.id);const n=qty(l.quantity);check(n<=room(item)&&n<=Number(item.ordered_milli)-Number(item.delivered_milli),'Delivery exceeds allocated stock or accepted quantity');await c.query('UPDATE order_items SET delivered_milli=delivered_milli+$1 WHERE id=$2',[n,item.id]);lines.push({item_id:item.id,description:item.description,unit:item.unit,quantity_milli:n});}
 return (await c.query('INSERT INTO deliveries(order_id,reference,delivered_at,accepted_by,notes,lines,created_by) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id',[o.id,text(b.reference,200),day(b.date),text(b.accepted_by,200),String(b.notes||''),JSON.stringify(lines),req.user.id])).rows[0];
});
write('/stock/from-order','transfer_leftover_to_stock',async(c,req)=>{const b=req.body;const it=await one(c,'SELECT * FROM order_items WHERE id=$1',[id(b.item_id)]);await lockOrder(c,it.order_id);const item=await one(c,'SELECT * FROM order_items WHERE id=$1 FOR UPDATE',[it.id]);const n=qty(b.quantity);check(n<=room(item),'Transfer exceeds undelivered items held at office');check(['available','for_return','damaged'].includes(b.status),'Invalid stock condition');const reason=text(b.reason,300);const cost=money(b.cost);await c.query('UPDATE order_items SET residual_milli=residual_milli+$1 WHERE id=$2',[n,item.id]);const lot=(await c.query('INSERT INTO stock_lots(description,unit,quantity_milli,cost_cents,status,reason,location,source_item_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id',[item.description,item.unit,n,cost,b.status,reason,String(b.location||''),item.id])).rows[0];await c.query('INSERT INTO stock_movements(lot_id,quantity_milli,kind,reference,created_by) VALUES($1,$2,$3,$4,$5)',[lot.id,n,'order_leftover','Order '+item.order_id,req.user.id]);return lot;
});
write('/stock','add_opening_stock',async(c,req)=>{admin(req);const b=req.body;const n=qty(b.quantity);const lot=(await c.query("INSERT INTO stock_lots(description,unit,quantity_milli,cost_cents,status,reason,location) VALUES($1,$2,$3,$4,'available',$5,$6) RETURNING id",[text(b.description),text(b.unit,60),n,money(b.cost),text(b.reason,300),String(b.location||'')])).rows[0];await c.query('INSERT INTO stock_movements(lot_id,quantity_milli,kind,reference,created_by) VALUES($1,$2,$3,$4,$5)',[lot.id,n,'opening',b.reason,req.user.id]);return lot;});
write('/stock/:id/status','set_stock_condition',async(c,req)=>{admin(req);const lid=id(req.params.id);check(['available','for_return','damaged'].includes(req.body.status),'Invalid condition');const lot=await one(c,'SELECT * FROM stock_lots WHERE id=$1 FOR UPDATE',[lid]);const r=await c.query("SELECT 1 FROM stock_reservations WHERE lot_id=$1 AND status='reserved'",[lid]);check(!r.rowCount,'Release reservations before changing condition');await c.query('UPDATE stock_lots SET status=$1 WHERE id=$2',[req.body.status,lid]);await c.query('INSERT INTO stock_movements(lot_id,quantity_milli,kind,reference,created_by) VALUES($1,0,$2,$3,$4)',[lot.id,'condition',text(req.body.reason,300)+' -> '+req.body.status,req.user.id]);return {id:lid};});
write('/stock/:id/reserve','reserve_stock',async(c,req)=>{const b=req.body;const item=await lockItem(c,b.item_id);const lot=await one(c,'SELECT * FROM stock_lots WHERE id=$1 FOR UPDATE',[id(req.params.id)]);check(lot.status==='available','Stock is not available');check(lot.unit.toLowerCase()===item.unit.toLowerCase(),'Units differ; use the same base unit before reserving');check(b.confirm_match===true,'Confirm the stock specification matches the order');const n=qty(b.quantity);const r=Number((await c.query("SELECT COALESCE(sum(quantity_milli),0) n FROM stock_reservations WHERE lot_id=$1 AND status='reserved'",[lot.id])).rows[0].n);check(n<=Number(lot.quantity_milli)-r,'Insufficient available stock');check(n<=await demand(c,item),'Reservation exceeds uncommitted order demand');return (await c.query('INSERT INTO stock_reservations(lot_id,order_item_id,quantity_milli,created_by) VALUES($1,$2,$3,$4) RETURNING id',[lot.id,item.id,n,req.user.id])).rows[0];});
write('/reservations/:id/action','stock_reservation_action',async(c,req)=>{const r0=await one(c,'SELECT * FROM stock_reservations WHERE id=$1',[id(req.params.id)]);const item=await lockItem(c,r0.order_item_id);const lot=await one(c,'SELECT * FROM stock_lots WHERE id=$1 FOR UPDATE',[r0.lot_id]);const r=await one(c,'SELECT * FROM stock_reservations WHERE id=$1 FOR UPDATE',[r0.id]);check(r.status==='reserved','Reservation is no longer active');check(['release','issue'].includes(req.body.action),'Invalid action');if(req.body.action==='issue'){check(lot.status==='available'&&Number(lot.quantity_milli)>=Number(r.quantity_milli),'Insufficient usable stock');await c.query('UPDATE stock_lots SET quantity_milli=quantity_milli-$1 WHERE id=$2',[r.quantity_milli,lot.id]);await c.query('UPDATE order_items SET received_milli=received_milli+$1 WHERE id=$2',[r.quantity_milli,item.id]);await c.query('INSERT INTO stock_movements(lot_id,quantity_milli,kind,reference,created_by) VALUES($1,$2,$3,$4,$5)',[lot.id,-Number(r.quantity_milli),'issue','Order '+item.order_id,req.user.id]);}
 await c.query('UPDATE stock_reservations SET status=$1 WHERE id=$2',[req.body.action==='issue'?'issued':'released',r.id]);return {id:r.id};});
write('/stock/:id/adjustments','request_stock_adjustment',async(c,req)=>{await one(c,'SELECT id FROM stock_lots WHERE id=$1',[id(req.params.id)]);const b=req.body;check(['add','remove'].includes(b.direction),'Invalid direction');return (await c.query('INSERT INTO stock_requests(lot_id,delta_milli,reason,created_by) VALUES($1,$2,$3,$4) RETURNING id',[req.params.id,qty(b.quantity)*(b.direction==='remove'?-1:1),text(b.reason,500),req.user.id])).rows[0];});
write('/adjustments/:id/review','review_stock_adjustment',async(c,req)=>{admin(req);const r=await one(c,'SELECT * FROM stock_requests WHERE id=$1 FOR UPDATE',[id(req.params.id)]);check(r.status==='pending','Request already reviewed');check(['approve','reject'].includes(req.body.action),'Invalid action');if(req.body.action==='approve'){const lot=await one(c,'SELECT * FROM stock_lots WHERE id=$1 FOR UPDATE',[r.lot_id]);const reserved=Number((await c.query("SELECT COALESCE(sum(quantity_milli),0) n FROM stock_reservations WHERE lot_id=$1 AND status='reserved'",[lot.id])).rows[0].n);check(Number(lot.quantity_milli)+Number(r.delta_milli)>=reserved,'Adjustment would consume reserved stock');await c.query('UPDATE stock_lots SET quantity_milli=quantity_milli+$1 WHERE id=$2',[r.delta_milli,lot.id]);await c.query('INSERT INTO stock_movements(lot_id,quantity_milli,kind,reference,created_by) VALUES($1,$2,$3,$4,$5)',[lot.id,r.delta_milli,'adjustment',r.reason,req.user.id]);}await c.query('UPDATE stock_requests SET status=$1,reviewed_by=$2 WHERE id=$3',[req.body.action==='approve'?'approved':'rejected',req.user.id,r.id]);return {id:r.id};});
const fileTypes=new Map([['.pdf','application/pdf'],['.png','image/png'],['.jpg','image/jpeg'],['.jpeg','image/jpeg'],['.txt','text/plain']]);
const upload=multer({storage:multer.diskStorage({destination:uploadDir,filename:(req,file,cb)=>cb(null,randomBytes(20).toString('hex')+path.extname(file.originalname).toLowerCase())}),limits:{fileSize:10*1024*1024,files:1},fileFilter:(req,file,cb)=>cb(null,fileTypes.has(path.extname(file.originalname).toLowerCase()))});
const attachmentTables={quotation:'quotations',order:'orders',purchase_order:'purchase_orders',receipt:'receipts',delivery:'deliveries'};
authRouter.post('/attachments/:kind/:id',upload.single('file'),route(async(req,res)=>{check(req.file,'Use a PDF, PNG, JPG, or TXT file up to 10 MB');try{const result=await transaction(async c=>{const table=attachmentTables[req.params.kind];check(table,'Invalid attachment type');await one(c,`SELECT id FROM ${table} WHERE id=$1`,[id(req.params.id)]);const row=(await c.query('INSERT INTO attachments(kind,record_id,original_name,stored_name,mime,created_by) VALUES($1,$2,$3,$4,$5,$6) RETURNING id',[req.params.kind,req.params.id,path.basename(req.file.originalname),req.file.filename,fileTypes.get(path.extname(req.file.originalname).toLowerCase()),req.user.id])).rows[0];await audit(c,req,'upload_document',{id:row.id,kind:req.params.kind,record_id:req.params.id});return row;});res.json(result);}catch(e){await unlink(req.file.path);throw e;}}));
authRouter.get('/attachments/:kind/:id',route(async(req,res)=>res.json((await pool.query('SELECT id,original_name,created_at FROM attachments WHERE kind=$1 AND record_id=$2 ORDER BY id',[req.params.kind,id(req.params.id)])).rows)));
authRouter.get('/attachment/:id',route(async(req,res)=>{const f=await one(pool,'SELECT * FROM attachments WHERE id=$1',[id(req.params.id)]);res.type(f.mime);res.download(path.join(uploadDir,f.stored_name),f.original_name);}));
authRouter.get('/print/:kind/:id',route(async(req,res)=>{
 const kind=req.params.kind;const rid=id(req.params.id);const company={name:process.env.COMPANY_NAME||'Your Company',address:process.env.COMPANY_ADDRESS||''};
 if(kind==='quotation'){
  const q=await one(pool,'SELECT * FROM quotations WHERE id=$1',[rid]);
  const rev=req.query.revision===undefined?q.revision:Number(req.query.revision);check(Number.isInteger(rev)&&rev>=0,'Invalid revision');
  const v=await one(pool,'SELECT snapshot FROM quotation_versions WHERE quotation_id=$1 AND revision=$2',[rid,rev],'Finalize this revision before printing');return res.json(clientQuote(v.snapshot,company));
 }
 if(kind==='po'){
  const p=await one(pool,'SELECT * FROM purchase_orders WHERE id=$1',[rid]);const supplier=await one(pool,'SELECT * FROM parties WHERE id=$1',[p.supplier_id]);const lines=(await pool.query('SELECT i.description,i.unit,pi.quantity_milli,pi.cost_cents AS price_cents FROM purchase_order_items pi JOIN order_items i ON i.id=pi.order_item_id WHERE pi.po_id=$1 ORDER BY pi.id',[p.id])).rows;return res.json({type:'purchase_order',company,number:p.number,date:p.created_at,client:supplier,terms:p.terms,status:p.status,lines});
 }
 check(['receipt','delivery'].includes(kind),'Invalid document type');const table=kind==='receipt'?'receipts':'deliveries';const d=await one(pool,`SELECT * FROM ${table} WHERE id=$1`,[rid]);const lines=d.lines.map(({description,unit,quantity_milli})=>({description,unit,quantity_milli}));return res.json({type:kind,company,number:d.reference,date:d.received_at||d.delivered_at,accepted_by:d.accepted_by,terms:d.notes,lines});
}));
authRouter.get('/export',route(async(req,res)=>{admin(req);const tables=['parties','quotations','quotation_versions','orders','order_items','purchase_orders','purchase_order_items','receipts','deliveries','stock_lots','stock_reservations','stock_movements','stock_requests','catalog','audit_logs'];const data={format:'office-procurement-export-v1',created_at:new Date().toISOString()};await transaction(async c=>{await c.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');for(const table of tables)data[table]=(await c.query(`SELECT * FROM ${table} ORDER BY id`)).rows;});res.attachment('procurement-export.json').json(data);}));
write('/import/parties','import_contacts',async(c,req)=>{admin(req);check(Array.isArray(req.body.rows)&&req.body.rows.length<=1000,'Import up to 1000 contacts');let count=0;for(const b of req.body.rows){check(['client','supplier'].includes(b.kind),'Invalid contact type');await c.query('INSERT INTO parties(kind,name,contact,phone,email,address) VALUES($1,$2,$3,$4,$5,$6)',[b.kind,text(b.name,200),String(b.contact||''),String(b.phone||''),String(b.email||''),String(b.address||'')]);count++;}return {count};});
app.use('/api',authRouter);
app.use('/api',(req,res)=>res.status(404).json({error:'API route not found'}));
app.use(express.static(path.resolve(base,'../frontend/dist')));
app.get('*',(req,res)=>res.sendFile(path.resolve(base,'../frontend/dist/index.html')));
app.use((err,req,res,next)=>{
 console.error(err.message);if(res.headersSent)return next(err);
 const conflict=err.code==='23505';res.status(conflict?409:err.status||500).json({error:conflict?'A record with that number/name already exists.':err.status||err instanceof multer.MulterError?err.message:'The request could not be completed. Check the server log.'});
});
const server=app.listen(Number(process.env.PORT||3000),process.env.HOST||'0.0.0.0',()=>console.log('Office Procurement API listening on port',process.env.PORT||3000));
process.on('SIGTERM',()=>server.close(()=>pool.end().then(()=>process.exit(0))));
