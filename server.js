// server.js
import express from "express";
import session from "express-session";
import bcrypt from "bcrypt";
import dotenv from "dotenv";
import multer from "multer";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import pg from "pg";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// ---------------- DATABASE ----------------

const { Pool } = pg;
const connectionString = process.env.DATABASE_URL;
const ssl = { rejectUnauthorized: false };

const pool = new Pool({ connectionString, ssl });

// ---------------- UPLOADS ----------------

const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadDir),
  filename: (_req, file, cb) => {
    const clean = file.originalname.replace(/[^a-zA-Z0-9._-]/g, "_");
    cb(null, Date.now() + "-" + clean);
  },
});
const upload = multer({ storage });

const publicPath = (filePath) =>
  filePath ? "/uploads/" + path.basename(filePath) : null;

// ---------------- MIDDLEWARE ----------------

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "secret123",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(uploadDir));

// ---------------- HELPERS ----------------

function auth(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

function adminOnly(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin")
    return res.redirect("/login");
  next();
}

async function ensureAdmin() {
  const hash = await bcrypt.hash("admin", 10);
  await pool.query(
    `INSERT INTO users (username,password_hash,role)
     VALUES ('admin',$1,'admin')
     ON CONFLICT (username) DO NOTHING`,
    [hash]
  );
}

async function activeClass() {
  const r = await pool.query(
    "SELECT id FROM classes WHERE is_active = true LIMIT 1"
  );
  return r.rows[0]?.id || null;
}

// ---------------- ROUTES ----------------

// BASIC PAGES

app.get("/", (_req, res) => res.redirect("/login"));
app.get("/login", (_req, res) =>
  res.sendFile(path.join(__dirname, "public/login.html"))
);
app.get("/admin", adminOnly, (_req, res) =>
  res.sendFile(path.join(__dirname, "public/admin.html"))
);

// LOGIN

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  const r = await pool.query("SELECT * FROM users WHERE username=$1", [
    username,
  ]);
  if (!r.rows[0]) return res.status(400).json({ error: "Benutzer existiert nicht" });

  const user = r.rows[0];
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(400).json({ error: "Falsches Passwort" });

  req.session.user = { id: user.id, username, role: user.role };
  res.json({ ok: true });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// ---------------- ADMIN: KLASSEN ----------------

app.get("/api/admin/classes", adminOnly, async (_req, res) => {
  const r = await pool.query(
    "SELECT id,name,is_active FROM classes ORDER BY name"
  );
  res.json(r.rows);
});

app.post("/api/admin/classes", adminOnly, async (req, res) => {
  const { name } = req.body;
  const r = await pool.query(
    "INSERT INTO classes (name,is_active) VALUES ($1,false) RETURNING *",
    [name]
  );
  res.json(r.rows[0]);
});

app.patch("/api/admin/classes/:id", adminOnly, async (req, res) => {
  await pool.query("UPDATE classes SET is_active=false");
  const r = await pool.query(
    "UPDATE classes SET is_active=true WHERE id=$1 RETURNING *",
    [req.params.id]
  );
  res.json(r.rows[0]);
});

app.delete("/api/admin/classes/:id", adminOnly, async (req, res) => {
  await pool.query("DELETE FROM classes WHERE id=$1", [req.params.id]);
  res.json({ ok: true });
});

// ---------------- ADMIN: SCHÜLER ----------------

app.get("/api/admin/students", adminOnly, async (_req, res) => {
  const classId = await activeClass();
  if (!classId) return res.json([]);

  const r = await pool.query(
    `SELECT id,username,xp,highest_xp
     FROM users WHERE role='student' AND class_id=$1
     ORDER BY username`,
    [classId]
  );
  res.json(r.rows);
});

app.post("/api/admin/students", adminOnly, async (req, res) => {
  const { username, password } = req.body;
  const classId = await activeClass();
  if (!classId)
    return res.status(400).json({ error: "Keine aktive Klasse ausgewählt" });

  const hash = await bcrypt.hash(password, 10);
  const r = await pool.query(
    `INSERT INTO users (username,password_hash,role,class_id,xp,highest_xp)
     VALUES ($1,$2,'student',$3,0,0)
     RETURNING id,username,xp,highest_xp`,
    [username, hash, classId]
  );
  res.json(r.rows[0]);
});

app.delete("/api/admin/students/:id", adminOnly, async (req, res) => {
  await pool.query("DELETE FROM users WHERE id=$1 AND role='student'", [
    req.params.id,
  ]);
  res.json({ ok: true });
});

// ---------------- ADMIN: MISSIONEN ----------------

app.get("/api/admin/missions", adminOnly, async (_req, res) => {
  const r = await pool.query(
    `SELECT id,title,description,xp_value,image_path,allow_upload
     FROM missions ORDER BY created_at DESC`
  );

  res.json(
    r.rows.map((m) => ({
      ...m,
      image_url: publicPath(m.image_path),
    }))
  );
});

app.post(
  "/api/admin/missions",
  adminOnly,
  upload.single("image"),
  async (req, res) => {
    const { title, description, xp_value, allow_upload } = req.body;

    const r = await pool.query(
      `INSERT INTO missions (title,description,xp_value,image_path,allow_upload)
       VALUES ($1,$2,$3,$4,$5)
       RETURNING *`,
      [
        title,
        description,
        Number(xp_value),
        req.file ? req.file.path : null,
        allow_upload === "on" ? true : false,
      ]
    );

    const m = r.rows[0];
    m.image_url = publicPath(m.image_path);
    res.json(m);
  }
);

app.delete("/api/admin/missions/:id", adminOnly, async (req, res) => {
  const r = await pool.query(
    "SELECT file_path FROM student_mission_uploads WHERE mission_id=$1",
    [req.params.id]
  );
  for (const u of r.rows) {
    if (u.file_path && fs.existsSync(u.file_path)) fs.unlinkSync(u.file_path);
  }

  await pool.query("DELETE FROM missions WHERE id=$1", [req.params.id]);
  res.json({ ok: true });
});

// ---------------- ADMIN: XP VERGABE ----------------

app.post("/api/admin/xp", adminOnly, async (req, res) => {
  const { studentIds, xp, missionId, all } = req.body;

  let ids = studentIds;
  if (all) {
    const classId = await activeClass();
    const r = await pool.query(
      "SELECT id FROM users WHERE role='student' AND class_id=$1",
      [classId]
    );
    ids = r.rows.map((x) => x.id);
  }

  let addXp = Number(xp) || 0;

  if (missionId) {
    const m = await pool.query("SELECT xp_value FROM missions WHERE id=$1", [
      missionId,
    ]);
    addXp += Number(m.rows[0].xp_value);
  }

  for (const id of ids) {
    const u = await pool.query(
      "SELECT xp,highest_xp FROM users WHERE id=$1",
      [id]
    );
    const cur = Number(u.rows[0].xp);
    const high = Number(u.rows[0].highest_xp);
    const newXp = cur + addXp;
    const newHigh = Math.max(high, newXp);

    await pool.query(
      "UPDATE users SET xp=$1,highest_xp=$2 WHERE id=$3",
      [newXp, newHigh, id]
    );

    await pool.query(
      `INSERT INTO xp_transactions (student_id,amount,reason,mission_id,awarded_by)
       VALUES ($1,$2,$3,$4,$5)`,
      [
        id,
        addXp,
        missionId ? "Mission" : "Manuell",
        missionId || null,
        req.session.user.id,
      ]
    );
  }

  res.json({ ok: true });
});

// ========================= START =========================

ensureAdmin().then(() => {
  app.listen(PORT, () => console.log("Server läuft auf Port", PORT));
});
