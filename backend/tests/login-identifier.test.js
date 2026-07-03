const test = require('node:test');
const assert = require('node:assert/strict');
const bcrypt = require('bcryptjs');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '..', '.env') });

const db = require('../db');

test('finds a user by account number for login', async () => {
  const email = `acct-login-${Date.now()}@example.com`;
  const passwordHash = await bcrypt.hash('Password123!', 10);

  const createdUser = await db.createUser(null, email, 'Account', 'Login', passwordHash, false);
  assert.ok(createdUser, 'expected a created user');
  assert.ok(createdUser.accountNumber, 'expected an account number to be generated');

  const foundByEmail = await db.getUserByEmailOrAccountNumber(email);
  assert.equal(foundByEmail?.email, email);

  const foundByAccountNumber = await db.getUserByEmailOrAccountNumber(createdUser.accountNumber);
  assert.equal(foundByAccountNumber?.email, email);
});
