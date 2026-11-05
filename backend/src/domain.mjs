export function check(ok,message='Invalid request'){if(!ok){const e=new Error(message);e.status=400;throw e;}}
export function text(v,max=2000){check(typeof v==='string'&&v.trim().length>0&&v.length<=max,'Missing or invalid text');return v.trim();}
export function scaled(v,scale=100,allowZero=true){
 check(typeof v==='number'||typeof v==='string','Invalid number');
 const s=String(v).trim();check(/^\d+(\.\d+)?$/.test(s),'Enter a non-negative decimal number');
 const n=Number(s);check(Number.isFinite(n)&&n<=100000000,'Number is out of range');
 const result=Math.round(n*scale);check(Math.abs(n*scale-result)<0.00001,'Too many decimal places');
 check(allowZero?result>=0:result>0,'Amount/quantity must be positive');return result;
}
export const qty=v=>scaled(v,1000,false);
export const money=v=>scaled(v,100,true);
export function id(v){check(/^\d+$/.test(String(v))&&Number(v)>0&&Number.isSafeInteger(Number(v)),'Invalid record ID');return String(v);}
export function day(v){check(typeof v==='string'&&/^\d{4}-\d{2}-\d{2}$/.test(v)&&new Date(v+'T00:00:00Z').toISOString().slice(0,10)===v,'Invalid date');return v;}
export function lineAmount(cents,milli){return Number((BigInt(cents)*BigInt(milli)+500n)/1000n);}
export function normalizeQuote(body){
 check(Array.isArray(body.lines)&&body.lines.length>0&&body.lines.length<=200,'Use 1-200 quotation lines');
 const keys=new Set();
 const lines=body.lines.map((l,i)=>{
  const key=String(l.key||i+1);check(!keys.has(key),'Duplicate line key');keys.add(key);
  const offers=(l.offers||[]).map(o=>({supplier_id:id(o.supplier_id),cost_cents:money(o.cost),notes:String(o.notes||'').slice(0,1000)}));
  check(offers.length<=30,'Too many supplier offers');
  const selected=Number(l.selected_offer??0);check(offers.length===0||Number.isInteger(selected)&&selected>=0&&selected<offers.length,'Select a valid supplier offer');
  const cost=offers[selected]?.cost_cents??money(l.cost||0);
  const markupType=l.markup_type==='percent'?'percent':'amount';const markup=money(l.markup||0);
  const price=l.price!==''&&l.price!==null&&l.price!==undefined?money(l.price):cost+(markupType==='percent'?Math.round(cost*markup/10000):markup);
  check(price<=10000000000,'Selling price out of range');
  return {key,description:text(l.description),unit:text(l.unit,60),quantity_milli:qty(l.quantity),offers,selected_offer:selected,cost_cents:cost,markup_type:markupType,markup,price_cents:price,included:l.included!==false};
 });
 check(lines.some(x=>x.included),'Select at least one line for the client copy');
 const extra_cents=money(body.extra_cost||0);
 return {lines,extra_cents,terms:String(body.terms||'').slice(0,10000),date:day(body.date),valid_until:day(body.valid_until),payment_terms:text(body.payment_terms,300),vat_inclusive:body.vat_inclusive!==false,vat_rate:scaled(body.vat_rate??12,100),notes:String(body.notes||'').slice(0,10000)};
}
export function totals(data){const lines=data.lines.filter(x=>x.included);const revenue=lines.reduce((a,l)=>a+lineAmount(l.price_cents,l.quantity_milli),0);const cost=lines.reduce((a,l)=>a+lineAmount(l.cost_cents,l.quantity_milli),data.extra_cents||0);return {revenue_cents:revenue,cost_cents:cost,profit_cents:revenue-cost,margin:revenue?(revenue-cost)/revenue*100:0};}
export function clientQuote(q,company){const d=q.data;return {type:'quotation',number:q.number,revision:q.revision,company,client:q.client,date:d.date,valid_until:d.valid_until,payment_terms:d.payment_terms,terms:d.terms,vat_inclusive:d.vat_inclusive,vat_rate:d.vat_rate,lines:d.lines.filter(l=>l.included).map(l=>({description:l.description,unit:l.unit,quantity_milli:l.quantity_milli,price_cents:l.price_cents})),total_cents:totals(d).revenue_cents};}
export function room(item){return Number(item.received_milli)-Number(item.delivered_milli)-Number(item.residual_milli);}
export function remainingDemand(item,reserved,committed){return Number(item.ordered_milli)-Number(item.received_milli)+Number(item.residual_milli)-Number(reserved)-Number(committed);}
