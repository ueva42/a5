import express from "express";
import session from "express-session";
import bcrypt from "bcrypt";
import pg from "pg";
import dotenv from "dotenv";
import multer from "multer";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3000;

// PostgreSQL Verbindung
const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("railway")
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

// Upload-Ordner einrichten
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadDir),
  filename: (_req, file, cb) => {
    const timestamp = Date.now();
    const sanitized = file.originalname.replace(/[^a-zA-Z0-9_.-]/g, "_");
    cb(null, `${timestamp}-${sanitized}`);
  },
});
const upload = multer({ storage });

// Statische Dateien (Frontend)
const publicDir = path.join(__dirname, "public");
app.use(express.static(publicDir));
app.use("/uploads", express.static(uploadDir));

// Auth-Middleware
const ensureAuthenticated = (req, res, next) => {
  if (!req.session.user)
    return res.status(401).json({ error: "Nicht angemeldet" });
  next();
};

const ensureRole = (role) => (req, res, next) => {
  if (!req.session.user || req.session.user.role !== role)
    return res.status(403).json({ error: "Keine Berechtigung" });
  next();
};

// --- Root & Login ---
app.get("/", (_req, res) => {
  res.redirect("/login.html");
});

app.get("/api/session", (req, res) => {
  if (!req.session.user) return res.json({ authenticated: false });
  res.json({ authenticated: true, user: req.session.user });
});

// ---------- LOGIN ----------
app.post("/api/login", async (req, res) => {
  const { name, password } = req.body;
  if (!name || !password)
    return res.status(400).json({ error: "Name und Passwort erforderlich" });

  try {
    const result = await pool.query("SELECT * FROM users WHERE name = $1", [
      name,
    ]);

    if (result.rows.length === 0)
      return res.status(400).json({ error: "Benutzer nicht gefunden" });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Falsches Passwort" });

    req.session.user = {
      id: user.id,
      name: user.name,
      role: user.role,
    };
    res.json({ success: true, role: user.role });
  } catch (err) {
    console.error("Login Fehler:", err);
    res.status(500).json({ error: "Serverfehler beim Login" });
  }
});

// ---------- LOGOUT ----------
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// ---------- KLASSEN ----------
app.get(
  "/api/admin/classes",
  ensureAuthenticated,
  ensureRole("admin"),
  async (_req, res) => {
    try {
      const { rows } = await pool.query(
        "SELECT id, name, is_active FROM classes ORDER BY name"
      );
      res.json(rows);
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Klassen konnten nicht geladen werden" });
    }
  }
);

app.post(
  "/api/admin/classes",
  ensureAuthenticated,
  ensureRole("admin"),
  async (req, res) => {
    const { name } = req.body;
    if (!name?.trim())
      return res.status(400).json({ error: "Klassenname erforderlich" });
    try {
      const { rows } = await pool.query(
        "INSERT INTO classes (name) VALUES ($1) RETURNING id, name, is_active",
        [name.trim()]
      );
      res.status(201).json(rows[0]);
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Klasse konnte nicht angelegt werden" });
    }
  }
);

app.patch(
  "/api/admin/classes/:id/activate",
  ensureAuthenticated,
  ensureRole("admin"),
  async (req, res) => {
    const { id } = req.params;
    try {
      await pool.query("UPDATE classes SET is_active = FALSE");
      const { rows } = await pool.query(
        "UPDATE classes SET is_active = TRUE WHERE id = $1 RETURNING id, name, is_active",
        [id]
      );
      if (!rows[0])
        return res.status(404).json({ error: "Klasse nicht gefunden" });
      res.json(rows[0]);
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Klasse konnte nicht aktiviert werden" });
    }
  }
);

app.delete(
  "/api/admin/classes/:id",
  ensureAuthenticated,
  ensureRole("admin"),
  async (req, res) => {
    const { id } = req.params;
    try {
      const result = await pool.query("DELETE FROM classes WHERE id = $1 RETURNING id", [id]);
      if (!result.rowCount)
        return res.status(404).json({ error: "Klasse nicht gefunden" });
      res.json({ success: true });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Klasse konnte nicht gelöscht werden" });
    }
  }
);

// ---------- INITIALISIERUNG ----------
async function ensureDatabase() {
  try {
    console.log("🔄 Überprüfe Datenbank...");
    await pool.query(`
      CREATE TABLE IF NOT EXISTS classes (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        is_active BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Admin-Account
    const adminCheck = await pool.query("SELECT * FROM users WHERE role = 'admin'");
    if (adminCheck.rows.length === 0) {
      const hash = await bcrypt.hash("admin", 10);
      await pool.query(
        "INSERT INTO users (name, password, role) VALUES ($1, $2, 'admin')",
        ["admin", hash]
      );
      console.log("✅ Admin-Account erstellt (admin / admin)");
    }

    console.log("✅ Datenbank bereit.");
  } catch (err) {
    console.error("❌ DB-Init fehlgeschlagen:", err);
  }
}

// ---------- SERVER START ----------
ensureDatabase().then(() => {
  app.listen(PORT, () => console.log(`🚀 Server läuft auf Port ${PORT}`));
});
