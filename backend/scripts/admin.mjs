import {pool} from '../src/db.mjs';import bcrypt from 'bcryptjs';
const [username,password,displayName='Administrator']=process.argv.slice(2);
try{if(!username||!password||password.length<12)throw new Error('Usage: npm run create-admin -- username "password-at-least-12-characters" "Display Name"');
 await pool.query("INSERT INTO users(username,display_name,password_hash,role) VALUES($1,$2,$3,'Admin')",[username,displayName,await bcrypt.hash(password,12)]);
 console.log('Admin created. Existing accounts are never overwritten.');
}catch(e){console.error(e.message);process.exitCode=1;}finally{await pool.end();}
