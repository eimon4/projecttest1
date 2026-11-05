import 'dotenv/config';
import pg from 'pg';
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required. Copy backend/.env.example to backend/.env.');
const ssl = process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: process.env.DATABASE_SSL_REJECT_UNAUTHORIZED === 'true' } : false;
export const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, ssl });
export async function transaction(work){const c=await pool.connect();try{await c.query('BEGIN');const out=await work(c);await c.query('COMMIT');return out;}catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}}
