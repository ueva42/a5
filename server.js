import express from "express";
import session from "express-session";
import multer from "multer";
import path from "path";
import fs from "fs";
import pkg from "pg";
import bcrypt from "bcrypt";
import dotenv from "dotenv";

dotenv.config();

const { Pool } = pkg;

// ---------- DB SETUP ----------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ---------- APP SETUP ----------
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ---------- SESSIONS ----------
app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: false,
  })
);

// ---------- STATIC FILES ----------
app.use(express.static("public"));

// ---------- UPLOADS ----------
const uploadDir = process.env.UPLOAD_DIR || "/app/uploads";

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, uploadDir),
  filename: (_, file, cb) => {
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, unique + path.extname(file.originalname));
  },
});

const upload = multer({ storage });

// ---------- AUTH MIDDLEWARE ----------
function ensureAuthenticated(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Nicht eingeloggt" });
  next();
}

function ensureRole(role) {
  return (req, res, next) => {
    if (!req.session.user || req.session.user.role !== role)
      return res.status(403).json({ error: "Keine Berechtigung" });
    next();
  };
}

// ---------- LOGIN ----------
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ error: "Benutzername & Passwort erforderlich" });

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );

    if (result.rows.length === 0)
      return res.status(400).json({ error: "User existiert nicht" });

    const user = result.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);

    if (!ok) return res.status(401).json({ error: "Passwort falsch" });

    req.session.user = {
      id: user.id,
      username: user.username,
      role: user.role,
    };

    res.json({ success: true, role: user.role });
  } catch (err) {
    console.error("LOGIN ERROR:", err);
    res.status(500).json({ error: "Serverfehler" });
  }
});

// ---------- LOGOUT ----------
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// *************************************************
// *************** KLASSEN CRUD *********************
// *************************************************
app.get("/api/admin/classes", ensureAuthenticated, ensureRole("admin"), async (_req, res) => {
  try {
    const r = await pool.query("SELECT * FROM classes ORDER BY id ASC");
    res.json(r.rows);
  } catch (err) {
    console.error("Load classes error:", err);
    res.status(500).json({ error: "Fehler beim Laden" });
  }
});

app.post("/api/admin/classes", ensureAuthenticated, ensureRole("admin"), async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: "Name fehlt" });

  try {
    await pool.query("INSERT INTO classes (class_name) VALUES ($1)", [name]);
    res.json({ success: true });
  } catch (err) {
    console.error("Create class error:", err);
    res.status(500).json({ error: "Fehler beim Erstellen" });
  }
});

app.delete("/api/admin/classes/:id", ensureAuthenticated, ensureRole("admin"), async (req, res) => {
  try {
    await pool.query("DELETE FROM classes WHERE id = $1", [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error("Delete class error:", err);
    res.status(500).json({ error: "Fehler beim Löschen" });
  }
});

// *************************************************
// *************** MISSIONEN CRUD *******************
// *************************************************
app.get("/api/admin/missions", ensureAuthenticated, ensureRole("admin"), async (_req, res) => {
  try {
    const r = await pool.query("SELECT * FROM missions ORDER BY id ASC");
    res.json(r.rows);
  } catch (err) {
    console.error("Load missions error:", err);
    res.status(500).json({ error: "Fehler beim Laden" });
  }
});

app.post(
  "/api/admin/missions",
  ensureAuthenticated,
  ensureRole("admin"),
  upload.single("image"),
  async (req, res) => {

    const { name, xp } = req.body;
    const imagePath = req.file ? req.file.filename : null;

    if (!name || !xp) return res.status(400).json({ error: "Name & XP erforderlich" });

    try {
      await pool.query(
        "INSERT INTO missions (name, xp, image_path) VALUES ($1, $2, $3)",
        [name, xp, imagePath]
      );
      res.json({ success: true });
    } catch (err) {
      console.error("Create mission error:", err);
      res.status(500).json({ error: "Fehler beim Erstellen" });
    }
  }
);

app.delete("/api/admin/missions/:id", ensureAuthenticated, ensureRole("admin"), async (req, res) => {
  try {
    await pool.query("DELETE FROM missions WHERE id = $1", [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error("Delete mission error:", err);
    res.status(500).json({ error: "Fehler beim Löschen" });
  }
});

// ---------- SERVER START ----------
app.listen(PORT, () => console.log("Server läuft auf Port", PORT));
