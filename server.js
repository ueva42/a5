import express from "express";
import session from "express-session";
import bcrypt from "bcrypt";
import pg from "pg";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

// Pfade
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// App
const app = express();
const PORT = process.env.PORT || 3000;

// DB-Verbindung
const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // kommt später von Railway
  ssl:
    process.env.DATABASE_URL && (process.env.DATABASE_URL.includes("railway") || process.env.PGSSLMODE === "require")
      ? { rejectUnauthorized: false }
      : false,
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "temple-secret",
    resave: false,
    saveUninitialized: false,
  })
);

// Statische Dateien (unsere 3 HTML-Seiten)
app.use(express.static(path.join(__dirname, "public")));

// Routen (minimal)
app.get("/", (_req, res) => res.redirect("/login"));
app.get("/login", (_req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));
app.get("/admin", (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin") return res.redirect("/login");
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});
app.get("/student", (req, res) => {
  if (!req.session.user || req.session.user.role !== "student") return res.redirect("/login");
  res.sendFile(path.join(__dirname, "public", "student.html"));
});

// Login-API
app.post("/api/login", async (req, res) => {
  const { name, password } = req.body;
  if (!name || !password) return res.status(400).json({ error: "Name und Passwort nötig" });

  try {
    const { rows } = await pool.query("SELECT id, name, password, role FROM users WHERE name = $1", [name]);
    if (!rows[0]) return res.status(400).json({ error: "Benutzer nicht gefunden" });

    const ok = await bcrypt.compare(password, rows[0].password);
    if (!ok) return res.status(400).json({ error: "Falsches Passwort" });

    req.session.user = { id: rows[0].id, name: rows[0].name, role: rows[0].role };
    res.json({ success: true, role: rows[0].role });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Serverfehler beim Login" });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// DB-Initialisierung beim Start
async function ensureDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'student',
      xp INTEGER DEFAULT 0,
      highest_xp INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  // Admin anlegen, falls nicht vorhanden
  const adminName = "admin";
  const adminPass = "admin";
  const { rows } = await pool.query("SELECT id FROM users WHERE name = $1", [adminName]);
  if (!rows[0]) {
    const hash = await bcrypt.hash(adminPass, 10);
    await pool.query("INSERT INTO users (name, password, role) VALUES ($1, $2, 'admin')", [adminName, hash]);
    console.log("✅ Admin angelegt: admin / admin");
  }
}

// Start
ensureDatabase()
  .then(() => {
    app.listen(PORT, () => console.log(`✅ Temple of Logic läuft auf Port ${PORT}`));
  })
  .catch((err) => {
    console.error("❌ DB-Init fehlgeschlagen:", err);
    process.exit(1);
  });
