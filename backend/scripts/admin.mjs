import {pool} from '../src/db.mjs';
import bcrypt from 'bcryptjs';

const [username, password, displayName='Administrator'] = process.argv.slice(2);

try {
  if (!username || !password || password.length < 12) {
    throw new Error('Usage: npm run create-admin -- username "password-at-least-12-characters" "Display Name"');
  }
  const hash = await bcrypt.hash(password, 12);
  const res = await pool.query(`
    INSERT INTO users(username, display_name, password_hash, role, active)
    VALUES($1, $2, $3, 'Admin', true)
    ON CONFLICT (username) DO UPDATE
    SET password_hash = EXCLUDED.password_hash,
        role = 'Admin',
        active = true
    RETURNING id, username
  `, [username, displayName, hash]);
  console.log(`Success! Admin user '${res.rows[0].username}' is ready.`);
} catch(e) {
  console.error(e.message);
  process.exitCode = 1;
} finally {
  await pool.end();
}
