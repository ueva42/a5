import express from "express";
import session from "express-session";
import bcrypt from "bcrypt";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";
import pkg from "pg";
const { Pool } = pkg;

// ---------------------------------------------------
// Grundkonfiguration
// ---------------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Static Files
app.use(express.static(path.join(__dirname, "public")));

// Session
app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev_secret",
    resave: false,
    saveUninitialized: false,
  })
);

// PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// ---------------------------------------------------
// Hilfsfunktionen
// ---------------------------------------------------

function ensureAuthenticated(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Nicht eingeloggt" });
  }
  next();
}

function ensureAdmin(req, res, next) {
  if (req.session.role !== "admin") {
    return res.status(403).json({ error: "Keine Adminrechte" });
  }
  next();
}

// ---------------------------------------------------
// FILE UPLOADS (Mission Images)
// ---------------------------------------------------

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, path.join(__dirname, "uploads")),
    filename: (req, file, cb) => {
      const unique = Date.now() + "-" + file.originalname;
      cb(null, unique);
    },
  }),
});

// Upload Ordner verfügbar machen
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// ---------------------------------------------------
// LOGIN
// ---------------------------------------------------

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const result = await pool.query("SELECT * FROM users WHERE username=$1", [
      username,
    ]);

    if (result.rowCount === 0) {
      return res.status(400).json({ error: "Ungültige Anmeldedaten" });
    }

    const user = result.rows[0];

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(400).json({ error: "Ungültige Anmeldedaten" });
    }

    req.session.userId = user.id;
    req.session.role = user.role;

    res.json({ success: true, role: user.role });
  } catch (err) {
    res.status(500).json({ error: "Serverfehler" });
  }
});

// LOGOUT
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// ---------------------------------------------------
// ADMIN – KLASSEN
// ---------------------------------------------------

app.get("/api/admin/classes", ensureAuthenticated, ensureAdmin, async (_req, res) => {
  const { rows } = await pool.query("SELECT * FROM classes ORDER BY id ASC");
  res.json(rows);
});

app.post("/api/admin/classes", ensureAuthenticated, ensureAdmin, async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: "Name fehlt" });

  await pool.query("INSERT INTO classes (name) VALUES ($1)", [name]);
  res.json({ success: true });
});

app.delete("/api/admin/classes/:id", ensureAuthenticated, ensureAdmin, async (req, res) => {
  await pool.query("DELETE FROM classes WHERE id=$1", [req.params.id]);
  res.json({ success: true });
});

// Aktive Klasse lesen
app.get("/api/admin/active-class", ensureAuthenticated, ensureAdmin, async (_req, res) => {
  const { rows } = await pool.query(
    "SELECT * FROM classes WHERE is_active = TRUE LIMIT 1"
  );
  res.json(rows[0] || null);
});

// Aktive Klasse setzen
app.post("/api/admin/active-class", ensureAuthenticated, ensureAdmin, async (req, res) => {
  const { class_id } = req.body;

  await pool.query("UPDATE classes SET is_active = FALSE WHERE is_active = TRUE");
  await pool.query("UPDATE classes SET is_active = TRUE WHERE id=$1", [class_id]);

  res.json({ success: true });
});

// ---------------------------------------------------
// ADMIN – SCHÜLER
// ---------------------------------------------------

app.get("/api/admin/students", ensureAuthenticated, ensureAdmin, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM users WHERE role='student' ORDER BY id ASC"
  );
  res.json(result.rows);
});

app.post("/api/admin/students", ensureAuthenticated, ensureAdmin, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: "Fehlerhafte Eingabe" });

  const hash = await bcrypt.hash(password, 10);

  await pool.query(
    "INSERT INTO users (username, password_hash, role, xp, highest_xp) VALUES ($1,$2,'student',0,0)",
    [username, hash]
  );

  res.json({ success: true });
});

app.delete("/api/admin/students/:id", ensureAuthenticated, ensureAdmin, async (req, res) => {
  await pool.query("DELETE FROM users WHERE id=$1", [req.params.id]);
  res.json({ success: true });
});

// ---------------------------------------------------
// ADMIN – MISSIONEN
// ---------------------------------------------------

app.get("/api/admin/missions", ensureAuthenticated, ensureAdmin, async (_req, res) => {
  const { rows } = await pool.query("SELECT * FROM missions ORDER BY id ASC");
  res.json(rows);
});

app.post(
  "/api/admin/missions",
  ensureAuthenticated,
  ensureAdmin,
  upload.single("image"),
  async (req, res) => {
    const { name, xp } = req.body;

    if (!name || !xp) return res.status(400).json({ error: "Fehlerhafte Eingabe" });

    const imagePath = req.file ? `/uploads/${req.file.filename}` : null;

    await pool.query(
      "INSERT INTO missions (name, xp, image_path) VALUES ($1,$2,$3)",
      [name, xp, imagePath]
    );

    res.json({ success: true });
  }
);

app.delete("/api/admin/missions/:id", ensureAuthenticated, ensureAdmin, async (req, res) => {
  await pool.query("DELETE FROM missions WHERE id=$1", [req.params.id]);
  res.json({ success: true });
});

// ---------------------------------------------------
// XP VERGABE
// ---------------------------------------------------

app.post("/api/admin/xp", ensureAuthenticated, ensureAdmin, async (req, res) => {
  const { student_id, xp } = req.body;

  await pool.query("UPDATE users SET xp = xp + $1 WHERE id=$2", [
    xp,
    student_id,
  ]);

  await pool.query(
    "INSERT INTO xp_transactions (student_id, xp, awarded_by) VALUES ($1,$2,$3)",
    [student_id, xp, req.session.userId]
  );

  res.json({ success: true });
});

app.post(
  "/api/admin/xp/mission",
  ensureAuthenticated,
  ensureAdmin,
  async (req, res) => {
    const { student_id, mission_id } = req.body;

    const mission = await pool.query("SELECT xp FROM missions WHERE id=$1", [
      mission_id,
    ]);

    if (mission.rowCount === 0)
      return res.status(400).json({ error: "Mission nicht gefunden" });

    const xp = mission.rows[0].xp;

    await pool.query("UPDATE users SET xp = xp + $1 WHERE id=$2", [
      xp,
      student_id,
    ]);

    await pool.query(
      "INSERT INTO xp_transactions (student_id, xp, awarded_by) VALUES ($1,$2,$3)",
      [student_id, xp, req.session.userId]
    );

    res.json({ success: true });
  }
);

// ---------------------------------------------------
// ADMIN PANEL ROUTE
// ---------------------------------------------------

app.get("/admin", ensureAuthenticated, ensureAdmin, (_req, res) => {
  res.sendFile(path.join(__dirname, "public/admin.html"));
});

// LOGIN PAGE
app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "public/login.html"));
});

// ---------------------------------------------------
// START
// ---------------------------------------------------

const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log("Server läuft auf Port", PORT)
);
