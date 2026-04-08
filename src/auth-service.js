const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const client = require("prom-client");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";
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
};

app.get("/health", (_req, res) => res.json({ status: "ok", service: "auth" }));
app.get("/metrics", async (_req, res) => {
  res.set("Content-Type", register.contentType);
  res.end(await register.metrics());
});

app.post("/register", async (req, res) => {
  const { username, password, role = "viewer" } = req.body;
  if (!username || !password) return res.status(400).json({ error: "username and password are required" });
  const passwordHash = await bcrypt.hash(password, 10);
  try {
    const result = await pool.query(
      "INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id, username, role",
      [username, passwordHash, role]
    );
    return res.status(201).json(result.rows[0]);
  } catch (error) {
    if (error.code === "23505") return res.status(409).json({ error: "username already exists" });
    return res.status(500).json({ error: "internal error" });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "username and password are required" });
  const result = await pool.query("SELECT * FROM users WHERE username=$1", [username]);
  const user = result.rows[0];
  if (!user) return res.status(401).json({ error: "invalid credentials" });
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: "invalid credentials" });
  const token = jwt.sign({ sub: user.id, role: user.role, username: user.username }, JWT_SECRET, { expiresIn: "2h" });
  return res.json({ token });
});

app.get("/me", async (req, res) => {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "missing token" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return res.json(decoded);
  } catch (_err) {
    return res.status(401).json({ error: "invalid token" });
  }
});

initDb()
  .then(() => app.listen(PORT, () => console.log(`auth-service running on ${PORT}`)))
  .catch((e) => {
    console.error("DB init failed", e);
    process.exit(1);
  });
