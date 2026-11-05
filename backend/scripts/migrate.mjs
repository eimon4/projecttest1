import {pool,transaction} from '../src/db.mjs';
import {readFile,readdir} from 'node:fs/promises';
try {
 await transaction(async c=>{
  await c.query("SELECT pg_advisory_xact_lock(492711)");
  await c.query('CREATE TABLE IF NOT EXISTS schema_migrations(name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ DEFAULT now())');
  for(const name of (await readdir(new URL('../../database/',import.meta.url))).filter(x=>x.endsWith('.sql')).sort()){
   if((await c.query('SELECT 1 FROM schema_migrations WHERE name=$1',[name])).rowCount)continue;
   await c.query(await readFile(new URL('../../database/'+name,import.meta.url),'utf8'));
   await c.query('INSERT INTO schema_migrations(name) VALUES($1)',[name]);console.log('Applied',name);
  }
 });console.log('Database ready. Existing application tables are not overwritten.');
}catch(e){console.error(e.message);process.exitCode=1;}finally{await pool.end();}
