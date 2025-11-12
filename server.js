// ====== IMPORTS ======
import express from "express";
import session from "express-session";
import bcrypt from "bcrypt";
import pg from "pg";
import multer from "multer";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

// ====== GRUNDKONFIGURATION ======
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// ====== DATENBANK ======
const { Pool } = pg;
const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  console.error("❌ Keine DATABASE_URL gefunden!");
  process.exit(1);
}

const pool = new Pool({
  connectionString,
  ssl: connectionString.includes("railway") ? { rejectUnauthorized: false } : false,
});

// ====== MIDDLEWARE ======
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "temple-secret",
    resave: false,
    saveUninitialized: false,
  })
);

const uploadDir = process.env.UPLOAD_DIR || path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
app.use("/uploads", express.static(uploadDir));
app.use(express.static(path.join(__dirname, "public")));

// ====== MULTER ======
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname.replace(/\s+/g, "_")),
});
const upload = multer({ storage });

// ====== AUTH-MIDDLEWARE ======
const ensureAuthenticated = (req, res, next) => {
  if (!req.session.user) return res.status(401).json({ error: "Nicht angemeldet" });
  next();
};

const ensureRole = (role) => (req, res, next) => {
  if (!req.session.user || req.session.user.role !== role)
    return res.status(403).json({ error: "Keine Berechtigung" });
  next();
};

// ====== INIT DATABASE ======
async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS classes (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      is_active BOOLEAN DEFAULT FALSE
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL
    )
  `);

  const adminHash = await bcrypt.hash("admin", 10);
  await pool.query(
    `INSERT INTO users (name, password, role)
     VALUES ('admin', $1, 'admin')
     ON CONFLICT (name) DO NOTHING`,
    [adminHash]
  );
  console.log("✅ Datenbank initialisiert, Admin erstellt (admin / admin)");
}

// ====== LOGIN ======
app.post("/api/login", async (req, res) => {
  const { name, password } = req.body;
  if (!name || !password) return res.status(400).json({ error: "Name und Passwort erforderlich" });

  try {
    const result = await pool.query("SELECT * FROM users WHERE name = $1", [name]);
    if (result.rows.length === 0) return res.status(400).json({ error: "Benutzer nicht gefunden" });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Falsches Passwort" });

    req.session.user = { id: user.id, name: user.name, role: user.role };
    res.json({ success: true, role: user.role });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login fehlgeschlagen" });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// ====== KLASSENVERWALTUNG ======
app.get("/api/admin/classes", ensureAuthenticated, ensureRole("admin"), async (_req, res) => {
  try {
    const { rows } = await pool.query("SELECT id, name, is_active FROM classes ORDER BY name");
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Klassen konnten nicht geladen werden" });
  }
});

app.post("/api/admin/classes", ensureAuthenticated, ensureRole("admin"), async (req, res) => {
  const { name } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: "Klassenname erforderlich" });
  try {
    const { rows } = await pool.query(
      "INSERT INTO classes (name) VALUES ($1) RETURNING id, name, is_active",
      [name.trim()]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Klasse konnte nicht angelegt werden" });
  }
});

app.patch("/api/admin/classes/:id/activate", ensureAuthenticated, ensureRole("admin"), async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query("UPDATE classes SET is_active = FALSE");
    const { rows } = await pool.query(
      "UPDATE classes SET is_active = TRUE WHERE id = $1 RETURNING id, name, is_active",
      [id]
    );
    if (!rows[0]) return res.status(404).json({ error: "Klasse nicht gefunden" });
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Klasse konnte nicht aktiviert werden" });
  }
});

// ====== START SERVER ======
initDatabase()
  .then(() => {
    app.listen(PORT, () => console.log(`🚀 Server läuft auf Port ${PORT}`));
  })
  .catch((err) => {
    console.error("❌ DB-Init fehlgeschlagen:", err);
    process.exit(1);
  });
