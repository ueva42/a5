// server.js
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

// ====== DB ======
const { Pool } = pg;
if (!process.env.DATABASE_URL) {
  console.warn("⚠️  DATABASE_URL fehlt. Setze sie in Railway → Variables.");
}
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.DATABASE_URL && process.env.DATABASE_URL.includes("railway")
      ? { rejectUnauthorized: false }
      : false,
});

// ====== Middleware ======
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.set("trust proxy", 1);
app.use(
  session({
    secret: process.env.SESSION_SECRET || "temple-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    },
  })
);

// ====== Static ======
const publicDir = path.join(__dirname, "public");
app.use(express.static(publicDir));

// ====== Uploads (mit Fallback) ======
let uploadDir = process.env.UPLOAD_DIR
  ? path.resolve(process.env.UPLOAD_DIR)
  : path.join(__dirname, "uploads");

try {
  if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
  console.log("📂 Upload-Verzeichnis:", uploadDir);
} catch (e) {
  console.error("⚠️ Upload-Verzeichnis nicht nutzbar, nutze MemoryStorage:", e.message);
  uploadDir = null;
}

let storage;
if (uploadDir) {
  storage = multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, uploadDir),
    filename: (_req, file, cb) => {
      const safe = file.originalname.replace(/[^a-zA-Z0-9_.-]/g, "_");
      cb(null, Date.now() + "_" + safe);
    },
  });
  app.use("/uploads", express.static(uploadDir));
} else {
  storage = multer.memoryStorage();
}
const upload = multer({ storage });

// ====== Helpers ======
const ensureAuthenticated = (req, res, next) => {
  if (!req.session.user) return res.status(401).json({ error: "Nicht angemeldet" });
  next();
};
const ensureRole = (role) => (req, res, next) => {
  if (!req.session.user || req.session.user.role !== role)
    return res.status(403).json({ error: "Keine Berechtigung" });
  next();
};
const toPublicPath = (filePath) =>
  filePath ? `/uploads/${path.basename(filePath)}` : null;
const parseBoolean = (v) => v === true || v === "true" || v === "on" || v === "1";

// ====== Routes (Basic) ======
app.get("/", (_req, res) => res.redirect("/login.html"));
app.get("/health", (_req, res) => res.json({ ok: true }));

// ====== Auth ======
app.post("/api/login", async (req, res) => {
  const { name, password } = req.body || {};
  if (!name || !password) return res.status(400).json({ error: "Name und Passwort erforderlich" });

  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE name = $1", [name]);
    if (!rows[0]) return res.status(400).json({ error: "Benutzer nicht gefunden" });

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: "Falsches Passwort" });

    req.session.user = { id: user.id, name: user.name, role: user.role };
    res.json({ success: true, role: user.role });
  } catch (err) {
    console.error("Login-Fehler:", err);
    res.status(500).json({ error: "Login fehlgeschlagen" });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.get("/api/session", (req, res) => {
  if (!req.session.user) return res.json({ authenticated: false });
  res.json({ authenticated: true, user: req.session.user });
});

// ====== Klassen ======
app.get(
  "/api/admin/classes",
  ensureAuthenticated,
  ensureRole("admin"),
  async (_req, res) => {
    try {
      const { rows } = await pool.query(
        "SELECT id, name, is_active FROM classes ORDER BY id"
      );
      res.json(rows);
    } catch (e) {
      console.error("Klassen laden:", e);
      res.status(500).json({ error: "Klassen konnten nicht geladen werden" });
    }
  }
);

app.post(
  "/api/admin/classes",
  ensureAuthenticated,
  ensureRole("admin"),
  async (req, res) => {
    const { name } = req.body || {};
    if (!name?.trim()) return res.status(400).json({ error: "Name erforderlich" });
    try {
      const { rows } = await pool.query(
        "INSERT INTO classes (name) VALUES ($1) RETURNING id, name, is_active",
        [name.trim()]
      );
      res.status(201).json(rows[0]);
    } catch (e) {
      console.error("Klasse anlegen:", e);
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
      if (!rows[0]) return res.status(404).json({ error: "Klasse nicht gefunden" });
      res.json(rows[0]);
    } catch (e) {
      console.error("Klasse aktivieren:", e);
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
      await pool.query("DELETE FROM classes WHERE id = $1", [id]);
      res.json({ success: true });
    } catch (e) {
      console.error("Klasse löschen:", e);
      res.status(500).json({ error: "Klasse konnte nicht gelöscht werden" });
    }
  }
);

// ====== Missionen ======
app.get(
  "/api/admin/missions",
  ensureAuthenticated,
  ensureRole("admin"),
  async (_req, res) => {
    try {
      const { rows } = await pool.query(
        "SELECT id, title, xp_value, image_path, allow_upload FROM missions ORDER BY id DESC"
      );
      res.json(
        rows.map((m) => ({
          ...m,
          xp_value: Number(m.xp_value) || 0,
          image_path: toPublicPath(m.image_path),
          allow_upload: !!m.allow_upload,
        }))
      );
    } catch (e) {
      console.error("Missionen laden:", e);
      res.status(500).json({ error: "Missionen konnten nicht geladen werden" });
    }
  }
);

app.post(
  "/api/admin/missions",
  ensureAuthenticated,
  ensureRole("admin"),
  upload.single("image"),
  async (req, res) => {
    try {
      const { title, xp_value, description, allow_upload } = req.body || {};
      if (!title?.trim() || xp_value === undefined)
        return res.status(400).json({ error: "Titel und XP erforderlich" });

      let imagePath = null;
      if (req.file && uploadDir) {
        imagePath = req.file.path;
      }

      const { rows } = await pool.query(
        `INSERT INTO missions (title, xp_value, image_path, allow_upload)
         VALUES ($1, $2, $3, $4)
         RETURNING id, title, xp_value, image_path, allow_upload`,
        [title.trim(), Number(xp_value), imagePath, parseBoolean(allow_upload)]
      );

      const m = rows[0];
      res.status(201).json({
        ...m,
        xp_value: Number(m.xp_value) || 0,
        image_path: toPublicPath(m.image_path),
        allow_upload: !!m.allow_upload,
      });
    } catch (e) {
      console.error("Mission anlegen:", e);
      res.status(500).json({ error: "Mission konnte nicht angelegt werden" });
    }
  }
);

// ====== DB-Setup ======
async function ensureDatabase() {
  // classes
  await pool.query(`
    CREATE TABLE IF NOT EXISTS classes (
      id SERIAL PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      is_active BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  // users
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  // missions
  await pool.query(`
    CREATE TABLE IF NOT EXISTS missions (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      xp_value INTEGER NOT NULL,
      image_path TEXT,
      allow_upload BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  // für bestehende DBs sicherstellen:
  await pool.query(`ALTER TABLE missions ADD COLUMN IF NOT EXISTS image_path TEXT`);
  await pool.query(`ALTER TABLE missions ADD COLUMN IF NOT EXISTS allow_upload BOOLEAN DEFAULT FALSE`);

  // Admin anlegen, falls fehlt
  const { rowCount } = await pool.query("SELECT 1 FROM users WHERE role = 'admin'");
  if (rowCount === 0) {
    const hash = await bcrypt.hash("admin", 10);
    await pool.query(
      "INSERT INTO users (name, password, role) VALUES ($1, $2, 'admin')",
      ["admin", hash]
    );
    console.log("✅ Admin erstellt (admin / admin)");
  }
}

// ====== Start ======
ensureDatabase()
  .then(() => {
    app.listen(PORT, () => console.log(`🚀 Server läuft auf Port ${PORT}`));
  })
  .catch((e) => {
    console.error("❌ DB-Init fehlgeschlagen:", e);
    process.exit(1);
  });
