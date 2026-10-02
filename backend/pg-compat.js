/**
 * MySQL → PostgreSQL compatibility layer (Neon)
 * =============================================
 * The application was written against MySQL/TiDB using `mysql2/promise`.
 * The database is now Neon (PostgreSQL). Rather than rewrite ~210 query call
 * sites, this module exposes the small slice of the mysql2 API the app uses
 * (`createPool`, `pool.execute/query`, `getConnection`, `release`,
 * `beginTransaction/commit/rollback`) on top of `pg`, and translates each
 * statement on the way through.
 *
 * What it translates:
 *   1. Placeholders      `?`            → `$1, $2, ...`  (string-literal aware)
 *   2. Identifier case   Postgres folds unquoted identifiers to lowercase, so
 *                        `SELECT firstName` returns the key `firstname`. Result
 *                        keys are mapped back to the camelCase the app expects.
 *   3. DDL dialect       AUTO_INCREMENT → SERIAL, inline INDEX → CREATE INDEX,
 *                        TINYINT(1)/BOOLEAN → SMALLINT, LONGTEXT → TEXT, ...
 *   4. Write results     mysql2's `insertId` / `affectedRows` are synthesised
 *                        via `RETURNING id` and `rowCount`.
 *   5. information_schema  `TABLE_SCHEMA = ?` → `current_schema()`.
 *
 * Booleans are stored as SMALLINT (0/1) to match MySQL's TINYINT(1) semantics,
 * because the application passes `1`/`0` rather than `true`/`false`.
 */

const { Pool } = require('pg');

// ---------------------------------------------------------------------------
// 1. camelCase identifier dictionary
// ---------------------------------------------------------------------------
// Postgres lowercases unquoted identifiers. These are the mixed-case column
// and alias names used in the app's SQL; result keys are restored to these.
const CAMEL_IDENTIFIERS = [
  'COLUMN_NAME',
  'TABLE_NAME',
  'TABLE_SCHEMA',
  'accountId',
  'accountName',
  'accountNumber',
  'accountStatus',
  'accountType',
  'adminId',
  'adminNotes',
  'adminReply',
  'alertSent',
  'availableBalance',
  'backImage',
  'bankName',
  'budgetLimit',
  'cardId',
  'cardNumber',
  'cardNumberMasked',
  'cardStatus',
  'cardType',
  'cardholderName',
  'checkNumber',
  'createTableSQL',
  'createUser',
  'createdAt',
  'credentialId',
  'currentAmount',
  'defaultSrc',
  'deleteProfileImageFile',
  'deliveryAddress',
  'deliveryStatus',
  'endDate',
  'ensureCardsTable',
  'ensureInvestmentsTable',
  'ensureSupportTables',
  'estimatedReturn',
  'expirationDate',
  'fileData',
  'fileName',
  'firstName',
  'fromAccountNumber',
  'fromFirstName',
  'fromLastName',
  'fromUserId',
  'frontImage',
  'generateReferralCode',
  'getAllUsers',
  'getConnection',
  'getUserByEmail',
  'getUserById',
  'getUserTransactions',
  'hashedPassword',
  'holderName',
  'initializePool',
  'insertResult',
  'interestRate',
  'isAdmin',
  'isDataUrl',
  'isFinite',
  'isLocked',
  'isMatured',
  'isPrimary',
  'isRead',
  'isVerified',
  'issuedAt',
  'lastName',
  'ledgerBalance',
  'loanType',
  'maturityDate',
  'monthlyPayment',
  'newBalance',
  'newPassword',
  'nextRunDate',
  'normalizedLimit',
  'openedAt',
  'parseFloat',
  'passwordColumnDetecting',
  'passwordHash',
  'profileImage',
  'profileImageValue',
  'publicKey',
  'rawNumber',
  'recipientAccountNumber',
  'recipientEmail',
  'recipientFirst',
  'recipientId',
  'recipientLast',
  'recordTransaction',
  'referralCode',
  'referredBy',
  'referredUserId',
  'referrerId',
  'rejectionReason',
  'releaseErr',
  'requireAdmin',
  'resetToken',
  'resetTokenExpiry',
  'rewardAmount',
  'routingNumber',
  'safeLimit',
  'senderAccountNumber',
  'senderEmail',
  'senderFirst',
  'senderLast',
  'senderType',
  'setCardStatus',
  'setClauses',
  'storeProfileDataUrl',
  'storedPath',
  'swiftCode',
  'targetAmount',
  'targetDate',
  'toAccountNumber',
  'toFirstName',
  'toLastName',
  'toString',
  'toUserId',
  'transactionId',
  'transferRestricted',
  'transferRestrictionReason',
  'updateUserBalance',
  'updatedAt',
  'useDefaults',
  'userEmail',
  'userId',
  'userName',
  'usersTables',
  'whereClause',];

const CAMEL_BY_LOWER = new Map(CAMEL_IDENTIFIERS.map((n) => [n.toLowerCase(), n]));

/** Restore camelCase keys on a result row. */
function normalizeRow(row) {
  if (!row || typeof row !== 'object') return row;
  const out = {};
  for (const key of Object.keys(row)) {
    out[CAMEL_BY_LOWER.get(key) || key] = row[key];
  }
  return out;
}

// ---------------------------------------------------------------------------
// 2. Dialect translation
// ---------------------------------------------------------------------------

/** Replace `?` placeholders with `$n`, ignoring those inside string literals. */
function convertPlaceholders(sql, skipIndexes = new Set()) {
  let out = '';
  let n = 0;
  let seen = 0;
  let quote = null;
  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i];
    if (quote) {
      out += ch;
      if (ch === quote && sql[i - 1] !== '\\') quote = null;
      continue;
    }
    if (ch === "'" || ch === '"') { quote = ch; out += ch; continue; }
    if (ch === '?') {
      if (skipIndexes.has(seen)) { out += '?'; } else { out += '$' + (++n); }
      seen++;
      continue;
    }
    out += ch;
  }
  return out;
}

/** Postgres reserved words that must be quoted when used as identifiers. */
const RESERVED = new Set(['limit', 'order', 'user', 'group', 'end', 'desc', 'asc', 'to', 'from', 'check', 'default', 'references', 'primary', 'unique', 'window', 'offset']);

/** `\`col\`` → `col` (or `"col"` when reserved). */
function translateBackticks(sql) {
  return sql.replace(/`([a-zA-Z_][a-zA-Z0-9_]*)`/g, (_, id) =>
    RESERVED.has(id.toLowerCase()) ? `"${id.toLowerCase()}"` : id);
}

/** Convert a MySQL CREATE TABLE into Postgres, lifting inline indexes out. */
function translateCreateTable(sql) {
  const extras = [];
  const tableMatch = sql.match(/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`"]?(\w+)[`"]?/i);
  const table = tableMatch ? tableMatch[1] : null;

  // `UNIQUE KEY name (cols)` → plain `UNIQUE (cols)` constraint.
  // MUST run before the plain-index rule below, which would otherwise match
  // the `KEY name (cols)` tail and demote a unique constraint to an index.
  sql = sql.replace(/,?\s*UNIQUE\s+KEY\s+[`"]?\w+[`"]?\s*\(([^)]+)\)/gi, (_, cols) => `, UNIQUE (${cols})`);

  // Inline `INDEX name (cols)` / `KEY name (cols)` are not valid in Postgres.
  // `PRIMARY KEY (...)` and `FOREIGN KEY (...)` are untouched: they have no
  // identifier between the keyword and the column list.
  sql = sql.replace(/,?\s*(?:INDEX|KEY)\s+[`"]?(\w+)[`"]?\s*\(([^)]+)\)/gi, (_, name, cols) => {
    if (table) {
      const cleanCols = cols.replace(/[`"]/g, '').trim();
      extras.push(`CREATE INDEX IF NOT EXISTS ${table}_${name} ON ${table} (${cleanCols})`);
    }
    return '';
  });

  return { sql, extras };
}

/** Apply all MySQL→Postgres type and syntax fixes. */
function translateDialect(sql) {
  let extras = [];

  if (/CREATE\s+TABLE/i.test(sql)) {
    const r = translateCreateTable(sql);
    sql = r.sql;
    extras = r.extras;
  }

  sql = translateBackticks(sql);

  sql = sql
    // Auto-increment primary keys
    .replace(/\bINT(?:EGER)?\s+PRIMARY\s+KEY\s+AUTO_INCREMENT\b/gi, 'SERIAL PRIMARY KEY')
    .replace(/\bINT(?:EGER)?\s+AUTO_INCREMENT\s+PRIMARY\s+KEY\b/gi, 'SERIAL PRIMARY KEY')
    .replace(/\bINT(?:EGER)?\s+NOT\s+NULL\s+AUTO_INCREMENT\b/gi, 'SERIAL NOT NULL')
    .replace(/\s+AUTO_INCREMENT\b/gi, '')
    // Types
    .replace(/\bTINYINT\s*\(\s*1\s*\)/gi, 'SMALLINT')
    .replace(/\bTINYINT\b/gi, 'SMALLINT')
    .replace(/\bBOOLEAN\b/gi, 'SMALLINT')
    .replace(/\b(?:LONG|MEDIUM|TINY)TEXT\b/gi, 'TEXT')
    .replace(/\bDATETIME\b/gi, 'TIMESTAMP')
    .replace(/\bDOUBLE\b(?!\s+PRECISION)/gi, 'DOUBLE PRECISION')
    .replace(/\bUNSIGNED\b/gi, '')
    // Boolean literals now that the columns are SMALLINT
    .replace(/=\s*TRUE\b/gi, '= 1')
    .replace(/=\s*FALSE\b/gi, '= 0')
    .replace(/\bDEFAULT\s+TRUE\b/gi, 'DEFAULT 1')
    .replace(/\bDEFAULT\s+FALSE\b/gi, 'DEFAULT 0')
    // MySQL cast targets that Postgres does not know
    .replace(/\bAS\s+CHAR\s*(\(\s*\d+\s*\))?\s*\)/gi, 'AS TEXT)')
    .replace(/\bAS\s+SIGNED(\s+INTEGER)?\s*\)/gi, 'AS INTEGER)')
    .replace(/\bAS\s+UNSIGNED(\s+INTEGER)?\s*\)/gi, 'AS INTEGER)')
    // MySQL-only table/column clauses
    .replace(/\s+ON\s+UPDATE\s+CURRENT_TIMESTAMP\b/gi, '')
    .replace(/\s+ENGINE\s*=\s*\w+/gi, '')
    .replace(/\s+DEFAULT\s+CHARSET\s*=\s*\w+/gi, '')
    .replace(/\s+COLLATE\s*=?\s*[\w_]+/gi, '')
    // Tidy up artefacts from removing inline indexes
    .replace(/,(\s*,)+/g, ',')
    .replace(/\(\s*,/g, '(')
    .replace(/,\s*\)/g, ')');

  return { sql, extras };
}

/**
 * `information_schema.TABLES WHERE TABLE_SCHEMA = ?` passes a MySQL database
 * name, which never matches in Postgres. Swap in current_schema() and drop
 * that parameter.
 */
function rewriteInformationSchema(sql, params) {
  if (!/information_schema/i.test(sql) || !/TABLE_SCHEMA\s*=\s*\?/i.test(sql)) {
    return { sql, params, skip: new Set() };
  }
  // Which placeholder (0-based) is the schema one?
  const before = sql.slice(0, sql.search(/TABLE_SCHEMA\s*=\s*\?/i));
  const idx = (before.match(/\?/g) || []).length;
  const newSql = sql.replace(/TABLE_SCHEMA\s*=\s*\?/i, 'table_schema = current_schema()');
  const newParams = params.filter((_, i) => i !== idx);
  return { sql: newSql, params: newParams, skip: new Set() };
}

/** Coerce JS values to what node-postgres expects. */
function normalizeParams(params = []) {
  return params.map((v) => {
    if (v === undefined) return null;
    if (typeof v === 'boolean') return v ? 1 : 0;   // SMALLINT booleans
    return v;
  });
}

const WRITE_RE = /^\s*(INSERT|UPDATE|DELETE|REPLACE)\b/i;
const INSERT_RE = /^\s*INSERT\b/i;
const RETURNING_RE = /\bRETURNING\b/i;

// ---------------------------------------------------------------------------
// 3. Execution
// ---------------------------------------------------------------------------

/**
 * Run one statement through the translator and return a mysql2-shaped result.
 * @returns {Promise<[rows|ResultHeader, fields]>}
 */
async function runStatement(client, rawSql, rawParams = []) {
  let params = normalizeParams(rawParams);
  let sql = String(rawSql);

  const info = rewriteInformationSchema(sql, params);
  sql = info.sql;
  params = info.params;

  const { sql: translated, extras } = translateDialect(sql);
  sql = translated;

  const isWrite = WRITE_RE.test(sql);
  const isInsert = INSERT_RE.test(sql);

  // Synthesize mysql2's insertId.
  let wantInsertId = false;
  if (isInsert && !RETURNING_RE.test(sql)) {
    wantInsertId = true;
    sql = sql.replace(/;\s*$/, '') + ' RETURNING id';
  }

  const text = convertPlaceholders(sql);

  let result;
  try {
    result = await client.query(text, params);
  } catch (err) {
    // Table has no `id` column → retry without RETURNING.
    if (wantInsertId && err.code === '42703') {
      const fallback = convertPlaceholders(sql.replace(/\s+RETURNING id$/i, ''));
      result = await client.query(fallback, params);
      wantInsertId = false;
    } else {
      err.sql = text;
      throw err;
    }
  }

  // Inline indexes lifted out of a CREATE TABLE.
  for (const extra of extras) {
    try {
      await client.query(extra);
    } catch (e) {
      if (e.code !== '42P07') console.warn('[PG] index skipped:', e.message);
    }
  }

  if (isWrite) {
    const header = {
      affectedRows: result.rowCount || 0,
      changedRows: result.rowCount || 0,
      insertId: wantInsertId && result.rows && result.rows[0] ? result.rows[0].id : 0
    };
    return [header, undefined];
  }

  return [(result.rows || []).map(normalizeRow), result.fields];
}

// ---------------------------------------------------------------------------
// 4. mysql2-shaped API
// ---------------------------------------------------------------------------

/** Wraps a pg client so it looks like a mysql2 pooled connection. */
function wrapConnection(client, release) {
  return {
    execute: (sql, params) => runStatement(client, sql, params),
    query: (sql, params) => runStatement(client, sql, params),
    beginTransaction: () => client.query('BEGIN'),
    commit: () => client.query('COMMIT'),
    rollback: () => client.query('ROLLBACK'),
    release,
    destroy: release,
    escape: (v) => client.escapeLiteral ? client.escapeLiteral(String(v)) : `'${String(v).replace(/'/g, "''")}'`
  };
}

/**
 * Build a connection config from Neon's DATABASE_URL, or from the discrete
 * PGHOST / DB_HOST style variables. Neon requires TLS.
 */
function buildConfig(options = {}) {
  const url =
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL ||
    process.env.DATABASE_URL_UNPOOLED ||
    process.env.POSTGRES_URL_NON_POOLING ||
    '';

  const base = {
    max: Number(process.env.DB_POOL_MAX || 10),
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: Number(process.env.DB_CONNECT_TIMEOUT || 15000),
    // Neon presents a publicly-trusted certificate, so verification stays ON.
    // DB_SSL=false disables TLS entirely (local Postgres only);
    // DB_SSL_NO_VERIFY=true keeps TLS but skips verification (last resort).
    ssl: process.env.DB_SSL === 'false'
      ? false
      : { rejectUnauthorized: process.env.DB_SSL_NO_VERIFY !== 'true' }
  };

  // When a connection URL is present it wins outright. The caller (db.js)
  // still passes legacy MySQL options (host/port/user/ssl/connectionLimit);
  // mixing those into a pg config would override the URL's own host and
  // credentials, so they are deliberately ignored here.
  if (url) return { ...base, connectionString: url };

  return {
    ...base,
    host: process.env.PGHOST || process.env.DB_HOST || 'localhost',
    port: Number(process.env.PGPORT || process.env.DB_PORT || 5432),
    user: process.env.PGUSER || process.env.DB_USER || 'postgres',
    password: process.env.PGPASSWORD || process.env.DB_PASSWORD || '',
    database: process.env.PGDATABASE || process.env.DB_NAME || 'neondb',
    ...options
  };
}

/** mysql2-compatible `createPool`. */
function createPool(options) {
  const pool = new Pool(buildConfig(options));

  pool.on('error', (err) => {
    console.error('[PG] Idle client error:', err.message);
  });

  return {
    execute: (sql, params) => runStatement(pool, sql, params),
    query: (sql, params) => runStatement(pool, sql, params),
    async getConnection() {
      const client = await pool.connect();
      let released = false;
      return wrapConnection(client, () => {
        if (released) return;
        released = true;
        client.release();
      });
    },
    end: () => pool.end(),
    _pgPool: pool
  };
}

module.exports = {
  createPool,
  // exported for tests
  _internal: { convertPlaceholders, translateDialect, normalizeRow, rewriteInformationSchema, buildConfig }
};
