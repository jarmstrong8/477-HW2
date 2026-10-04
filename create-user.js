'use strict';

// Creates a login account from the command line, so no credentials are hard-coded:
//   node create-user.js <email> <password>

const bcrypt = require('bcryptjs');
const { db, validateLogin, BCRYPT_ROUNDS } = require('./server');

const [email = '', password = ''] = process.argv.slice(2);
const normalized = email.trim().toLowerCase();

const errors = validateLogin(normalized, password);
if (Object.keys(errors).length > 0) {
  console.error(Object.values(errors).join('\n'));
  process.exit(1);
}

try {
  db.prepare("INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'customer')")
    .run(normalized, bcrypt.hashSync(password, BCRYPT_ROUNDS));
  console.log(`Created user ${normalized}`);
} catch (err) {
  console.error(err.code === 'SQLITE_CONSTRAINT_UNIQUE' ? 'That email already exists.' : err.message);
  process.exit(1);
}
