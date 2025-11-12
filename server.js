// server.js – Hauptserver für Temple of Logic

import express from "express";
import session from "express-session";
import bcrypt from "bcrypt";
import pg from "pg";
import multer from "multer";
import path from "path";
import fs from "fs";
import dotenv from "dotenv";
import { fileURLToPath } from "url";

dotenv.config();

// --- Basisvariablen ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3000;
const { Pool } = pg;

// --- DB-Verbindung ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.DATABASE_URL?.includes("railway") ||
    process.env.PGSSLMODE === "require"
      ? { rejectUnauthorized: false }
      : false,
});

// --- Uploadverzeichnis ---
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

// --- Multer-Konfiguration ---
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadDir),
  filename: (_req, file, cb) => {
    const timestamp = Date.now();
    const sanitized = file.originalname.replace(/[^a-zA-Z0-9_.-]/g, "_");
    cb(null, `${timestamp}-${sanitized}`);
  },
});
const upload = multer({ storage });

// --- Middleware ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(uploadDir));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "temple-secret",
    resave: false,
    saveUninitialized: false,
  })
);

// --- Authentifizierungs-Helpers ---
const ensureAuthenticated = (req, res, next) => {
  if (!req.session.user) return res.status(401).json({ error: "Nicht angemeldet" });
  next();
};
const ensureRole = (role) => (req, res, next) => {
  if (!req.session.user || req.session.user.role !== role)
    return res.status(403).json({ error: "Keine Berechtigung" });
  next();
};

// --- Failsafe-Datenbankprüfung ---
async function ensureDatabase() {
  console.log("🔍 Prüfe Datenbanktabellen...");
  const client = await pool.connect();
  try {
    const { rows } = await client.query(`
      SELECT table_name FROM information_schema.tables
      WHERE table_schema='public'
    `);
    const existing = rows.map(r => r.table_name);
    if (!existing.includes("users")) {
      console.log("⚙️ Tabellen fehlen – initialisiere...");
      await initDatabase();
    } else {
      console.log("✅ Tabellen vorhanden – alles gut.");
    }
  } finally {
    client.release();
  }
}

// --- Tabellen erstellen (wie init.js) ---
async function initDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS classes (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        is_active BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS missions (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        xp_value INTEGER NOT NULL,
        image_path TEXT,
        allow_upload BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        class_id INTEGER REFERENCES classes(id) ON DELETE SET NULL,
        xp INTEGER DEFAULT 0,
        highest_xp INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    const adminHash = await bcrypt.hash("admin", 10);
    await pool.query(
      `INSERT INTO users (name, password, role)
       VALUES ($1, $2, 'admin')
       ON CONFLICT (name) DO UPDATE SET role='admin'`,
      ["admin", adminHash]
    );
    console.log("✅ Tabellen erstellt & Admin vorhanden!");
  } catch (err) {
    console.error("❌ DB-Init fehlgeschlagen:", err);
  }
}

// --- Login & Logout ---
app.post("/api/login", async (req, res) => {
  const { name, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE name = $1", [name]);
    if (!result.rows.length) return res.status(400).json({ error: "Benutzer nicht gefunden" });
    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Falsches Passwort" });

    req.session.user = { id: user.id, name: user.name, role: user.role };
    res.json({ success: true, role: user.role });
  } catch (err) {
    res.status(500).json({ error: "Serverfehler beim Login" });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// --- Klassenverwaltung ---
app.get("/api/admin/classes", ensureAuthenticated, ensureRole("admin"), async (_req, res) => {
  const { rows } = await pool.query("SELECT * FROM classes ORDER BY id ASC");
  res.json(rows);
});

app.post("/api/admin/classes", ensureAuthenticated, ensureRole("admin"), async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: "Name erforderlich" });
  const { rows } = await pool.query(
    "INSERT INTO classes (name) VALUES ($1) RETURNING *",
    [name]
  );
  res.json(rows[0]);
});

app.delete("/api/admin/classes/:id", ensureAuthenticated, ensureRole("admin"), async (req, res) => {
  const { id } = req.params;
  await pool.query("DELETE FROM classes WHERE id = $1", [id]);
  res.json({ success: true });
});

// --- Missionsverwaltung ---
app.get("/api/admin/missions", ensureAuthenticated, ensureRole("admin"), async (_req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM missions ORDER BY id DESC");
    res.json(rows);
  } catch (err) {
    console.error("Fehler beim Laden der Missionen:", err);
    res.status(500).json({ error: "Missionen konnten nicht geladen werden" });
  }
});

app.post("/api/admin/missions", ensureAuthenticated, ensureRole("admin"), upload.single("image"), async (req, res) => {
  try {
    const { title, description, xp_value, allow_upload } = req.body;
    const imagePath = req.file ? `/uploads/${req.file.filename}` : null;
    const { rows } = await pool.query(
      `INSERT INTO missions (title, description, xp_value, image_path, allow_upload)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [title, description, xp_value, imagePath, allow_upload === "on"]
    );
    res.json(rows[0]);
  } catch (err) {
    console.error("Fehler beim Erstellen der Mission:", err);
    res.status(500).json({ error: "Mission konnte nicht erstellt werden" });
  }
});

app.delete("/api/admin/missions/:id", ensureAuthenticated, ensureRole("admin"), async (req, res) => {
  const { id } = req.params;
  await pool.query("DELETE FROM missions WHERE id = $1", [id]);
  res.json({ success: true });
});

// --- Basisrouten ---
app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get("/admin", ensureAuthenticated, ensureRole("admin"), (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

// --- Start ---
ensureDatabase().then(() => {
  app.listen(PORT, () => console.log(`✅ Server läuft auf Port ${PORT}`));
});
