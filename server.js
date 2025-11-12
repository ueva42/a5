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

// Upload Setup
const uploadDir = process.env.UPLOAD_DIR
  ? path.resolve(process.env.UPLOAD_DIR)
  : path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, uploadDir),
  filename: (_, file, cb) => {
    const safeName = file.originalname.replace(/[^a-zA-Z0-9_.-]/g, "_");
    cb(null, Date.now() + "_" + safeName);
  },
});
const upload = multer({ storage });

app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(uploadDir));

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

app.get("/", (_req, res) => res.redirect("/login.html"));

app.post("/api/login", async (req, res) => {
  const { name, password } = req.body;
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
    res.status(500).json({ error: "Login fehlgeschlagen" });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// === KLASSEN ===
app.get("/api/admin/classes", ensureAuthenticated, ensureRole("admin"), async (_req, res) => {
  const { rows } = await pool.query("SELECT id, name, is_active FROM classes ORDER BY id");
  res.json(rows);
});

app.post("/api/admin/classes", ensureAuthenticated, ensureRole("admin"), async (req, res) => {
  const { name } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: "Name erforderlich" });
  const { rows } = await pool.query(
    "INSERT INTO classes (name) VALUES ($1) RETURNING id, name, is_active",
    [name.trim()]
  );
  res.status(201).json(rows[0]);
});

app.patch("/api/admin/classes/:id/activate", ensureAuthenticated, ensureRole("admin"), async (req, res) => {
  const { id } = req.params;
  await pool.query("UPDATE classes SET is_active = FALSE");
  const { rows } = await pool.query(
    "UPDATE classes SET is_active = TRUE WHERE id=$1 RETURNING id,name,is_active",
    [id]
  );
  res.json(rows[0]);
});

app.delete("/api/admin/classes/:id", ensureAuthenticated, ensureRole("admin"), async (req, res) => {
  const { id } = req.params;
  await pool.query("DELETE FROM classes WHERE id=$1", [id]);
  res.json({ success: true });
});

// === MISSIONEN ===
app.get("/api/admin/missions", ensureAuthenticated, ensureRole("admin"), async (_req, res) => {
  const { rows } = await pool.query(
    "SELECT id,title,xp_value,image_path,allow_upload FROM missions ORDER BY id DESC"
  );
  res.json(rows.map(m => ({
    ...m,
    image_path: m.image_path ? `/uploads/${path.basename(m.image_path)}` : null
  })));
});

app.post("/api/admin/missions", ensureAuthenticated, ensureRole("admin"), upload.single("image"), async (req, res) => {
  const { title, xp_value, allow_upload } = req.body;
  if (!title?.trim() || !xp_value)
    return res.status(400).json({ error: "Titel und XP erforderlich" });

  const imagePath = req.file ? req.file.path : null;
  const { rows } = await pool.query(
    `INSERT INTO missions (title, xp_value, image_path, allow_upload)
     VALUES ($1,$2,$3,$4)
     RETURNING id,title,xp_value,image_path,allow_upload`,
    [title.trim(), Number(xp_value), imagePath, allow_upload === "true" || allow_upload === "on"]
  );
  res.status(201).json(rows[0]);
});

app.delete("/api/admin/missions/:id", ensureAuthenticated, ensureRole("admin"), async (req, res) => {
  const { id } = req.params;
  const { rows } = await pool.query("SELECT image_path FROM missions WHERE id=$1", [id]);
  if (rows[0]?.image_path && fs.existsSync(rows[0].image_path))
    fs.unlinkSync(rows[0].image_path);
  await pool.query("DELETE FROM missions WHERE id=$1", [id]);
  res.json({ success: true });
});

// === INIT DATABASE ===
async function ensureDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS classes (
      id SERIAL PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
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
  const adminExists = await pool.query("SELECT * FROM users WHERE role='admin'");
  if (adminExists.rowCount === 0) {
    const hash = await bcrypt.hash("admin", 10);
    await pool.query("INSERT INTO users (name,password,role) VALUES ($1,$2,'admin')", ["admin", hash]);
    console.log("✅ Admin erstellt (admin/admin)");
  }
}

ensureDatabase().then(() => {
  app.listen(PORT, () => console.log(`🚀 Server läuft auf Port ${PORT}`));
});
