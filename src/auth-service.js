const express = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const client = require("prom-client");
const { sendError } = require("./lib/errors");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";
const ACCESS_TTL = process.env.ACCESS_TTL || "2h";
const REFRESH_TTL_DAYS = Number(process.env.REFRESH_TTL_DAYS || 7);
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const register = new client.Registry();
client.collectDefaultMetrics({ register });
const httpCounter = new client.Counter({
  name: "auth_http_requests_total",
  help: "Total HTTP requests on auth service",
  labelNames: ["route", "method", "status"],
});
register.registerMetric(httpCounter);

app.use((req, res, next) => {
  res.on("finish", () => {
    httpCounter.inc({ route: req.path, method: req.method, status: res.statusCode });
  });
  next();
});

const VALID_ROLES = ["viewer", "manager", "admin"];

const hashRefreshToken = (token) => crypto.createHash("sha256").update(token).digest("hex");

const issueTokens = async (user) => {
  const accessToken = jwt.sign(
    { sub: user.id, role: user.role, username: user.username },
    JWT_SECRET,
    { expiresIn: ACCESS_TTL }
  );
  const refreshToken = crypto.randomBytes(48).toString("hex");
  const refreshHash = hashRefreshToken(refreshToken);
  const expiresAt = new Date(Date.now() + REFRESH_TTL_DAYS * 24 * 60 * 60 * 1000);
  await pool.query("INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)", [
    user.id,
    refreshHash,
    expiresAt,
  ]);
  return { accessToken, refreshToken, expiresIn: ACCESS_TTL };
};

const initDb = async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(120) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(20) NOT NULL DEFAULT 'viewer',
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id SERIAL PRIMARY KEY,
      user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL,
      expires_at TIMESTAMP NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
};

app.get("/health", (_req, res) => res.json({ status: "ok", service: "auth" }));
app.get("/metrics", async (_req, res) => {
  res.set("Content-Type", register.contentType);
  res.end(await register.metrics());
});

app.post("/register", async (req, res) => {
  const { username, password, role = "viewer" } = req.body;
  if (!username || !password) return sendError(res, 400, "VALIDATION_ERROR", "username and password are required");
  if (!VALID_ROLES.includes(role)) return sendError(res, 400, "VALIDATION_ERROR", `role must be one of: ${VALID_ROLES.join(", ")}`);
  const passwordHash = await bcrypt.hash(password, 10);
  try {
    const result = await pool.query(
      "INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id, username, role",
      [username, passwordHash, role]
    );
    return res.status(201).json(result.rows[0]);
  } catch (error) {
    if (error.code === "23505") return sendError(res, 409, "USERNAME_EXISTS", "username already exists");
    return sendError(res, 500, "INTERNAL_ERROR", "internal error");
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return sendError(res, 400, "VALIDATION_ERROR", "username and password are required");
  const result = await pool.query("SELECT * FROM users WHERE username=$1", [username]);
  const user = result.rows[0];
  if (!user) return sendError(res, 401, "INVALID_CREDENTIALS", "invalid credentials");
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return sendError(res, 401, "INVALID_CREDENTIALS", "invalid credentials");
  const tokens = await issueTokens(user);
  return res.json({
    token: tokens.accessToken,
    refresh_token: tokens.refreshToken,
    expires_in: tokens.expiresIn,
    role: user.role,
    username: user.username,
  });
});

app.post("/refresh", async (req, res) => {
  const { refresh_token: refreshToken } = req.body;
  if (!refreshToken) return sendError(res, 400, "VALIDATION_ERROR", "refresh_token is required");
  const refreshHash = hashRefreshToken(refreshToken);
  const tokenRow = await pool.query(
    `SELECT rt.*, u.id, u.username, u.role
     FROM refresh_tokens rt
     JOIN users u ON u.id = rt.user_id
     WHERE rt.token_hash = $1 AND rt.expires_at > NOW()`,
    [refreshHash]
  );
  if (!tokenRow.rows[0]) return sendError(res, 401, "INVALID_REFRESH", "invalid or expired refresh token");
  await pool.query("DELETE FROM refresh_tokens WHERE id=$1", [tokenRow.rows[0].id]);
  const tokens = await issueTokens(tokenRow.rows[0]);
  return res.json({
    token: tokens.accessToken,
    refresh_token: tokens.refreshToken,
    expires_in: tokens.expiresIn,
  });
});

app.get("/me", async (req, res) => {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.replace("Bearer ", "");
  if (!token) return sendError(res, 401, "AUTH_REQUIRED", "missing token");
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return res.json(decoded);
  } catch (_err) {
    return sendError(res, 401, "AUTH_INVALID", "invalid token");
  }
});

app.post("/validate", async (req, res) => {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.replace("Bearer ", "");
  if (!token) return sendError(res, 401, "AUTH_REQUIRED", "missing token");
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return res.json({ valid: true, user: decoded });
  } catch (_err) {
    return sendError(res, 401, "AUTH_INVALID", "invalid token");
  }
});

initDb()
  .then(() => app.listen(PORT, () => console.log(`auth-service running on ${PORT}`)))
  .catch((e) => {
    console.error("DB init failed", e);
    process.exit(1);
  });

module.exports = app;
