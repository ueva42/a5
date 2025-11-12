// ------------------------------
// Temple of Logic – server.js
// Express-App mit Login, Admin- und Studentbereich
// ------------------------------

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

// --- Grundvariablen ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3000;

// --- PostgreSQL-Verbindung ---
const { Pool } = pg;
const connectionString = process.env.DATABASE_URL;

const pool = new Pool({
  connectionString,
  ssl: connectionString.includes("railway")
    ? { rejectUnauthorized: false }
    : false,
});

// --- Middleware ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "temple-secret",
    resave: false,
    saveUninitialized: false,
  })
);

// --- Uploads ---
const uploadDir = process.env.UPLOAD_DIR || path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadDir),
  filename: (_req, file, cb) =>
    cb(null, Date.now() + "-" + file.originalname.replace(/\s+/g, "_")),
});
const upload = multer({ storage });

// --- Static Files ---
const publicDir = path.join(__dirname, "public");
app.use(express.static(publicDir));
app.use("/uploads", express.static(uploadDir));

// --- Helper ---
const ensureAuthenticated = (req, res, next) => {
  if (!req.session.user) return res.redirect("/login");
  next();
};
const ensureRole = (role) => (req, res, next) => {
  if (!req.session.user || req.session.user.role !== role)
    return res.status(403).send("Keine Berechtigung");
  next();
};

// --- ROUTES ---
// Startseite
app.get("/", (_req, res) => {
  res.redirect("/login");
});

// Loginseite
app.get("/login", (_req, res) => {
  res.sendFile(path.join(publicDir, "login.html"));
});

// Login-API
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

    req.session.user = { id: user.id, name: user.name, role: user.role };
    res.json({ success: true, role: user.role });
  } catch (err) {
    console.error("Login-Fehler:", err);
    res.status(500).json({ error: "Serverfehler" });
  }
});

// Logout
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// Adminbereich
app.get("/admin", ensureAuthenticated, ensureRole("admin"), (_req, res) => {
  res.sendFile(path.join(publicDir, "admin.html"));
});

// Schülerbereich
app.get("/student", ensureAuthenticated, ensureRole("student"), (_req, res) => {
  res.sendFile(path.join(publicDir, "student.html"));
});

// --- Beispiel-Endpunkt für Admin-Daten ---
app.get("/api/admin/students", ensureAuthenticated, ensureRole("admin"), async (_req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT id, name, xp, role FROM users WHERE role = 'student'"
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Fehler beim Laden der Schüler" });
  }
});

// --- Mission-Uploads Beispiel ---
app.post(
  "/api/student/upload",
  ensureAuthenticated,
  ensureRole("student"),
  upload.single("file"),
  async (req, res) => {
    res.json({ success: true, file: req.file.filename });
  }
);

// --- Server starten ---
app.listen(PORT, () => {
  console.log(`✅ Temple of Logic läuft auf Port ${PORT}`);
});
