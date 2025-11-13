// ================================
// Server-Grundkonfiguration
// ================================
import express from "express";
import session from "express-session";
import multer from "multer";
import bcrypt from "bcrypt";
import pkg from "pg";
const { Pool } = pkg;
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";

// ================================
// Pfade & Upload-Verzeichnis
// ================================
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

const upload = multer({ dest: uploadDir });

// ================================
// Datenbankverbindung
// ================================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ================================
// Express App
// ================================
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Sessions
app.use(
  session({
    secret: process.env.SESSION_SECRET || "devsecret",
    resave: false,
    saveUninitialized: false,
  })
);

// Static files
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(uploadDir));

// ================================
// Middleware
// ================================
function ensureAuthenticated(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Nicht eingeloggt" });
  next();
}

function ensureAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).json({ error: "Keine Admin-Rechte" });
  }
  next();
}

// ================================
// LOGIN
// ================================

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const result = await pool.query(
      "SELECT * FROM users WHERE username=$1",
      [username]
    );

    if (result.rows.length === 0)
      return res.status(400).json({ error: "Benutzer existiert nicht" });

    const user = result.rows[0];

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(400).json({ error: "Falsches Passwort" });

    req.session.user = {
      id: user.id,
      username: user.username,
      role: user.role,
    };

    res.json({ success: true, role: user.role });

  } catch (err) {
    console.error("Login Fehler:", err);
    res.status(500).json({ error: "Login-Fehler" });
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login.html");
  });
});

// ================================
// ADMIN: Klassen
// ================================

app.get("/api/admin/classes", ensureAdmin, async (_req, res) => {
  const r = await pool.query("SELECT * FROM classes ORDER BY name");
  res.json(r.rows);
});

app.post("/api/admin/classes", ensureAdmin, async (req, res) => {
  const { name } = req.body;
  const r = await pool.query(
    "INSERT INTO classes (name) VALUES ($1) RETURNING *",
    [name]
  );
  res.json(r.rows[0]);
});

app.delete("/api/admin/classes/:id", ensureAdmin, async (req, res) => {
  await pool.query("DELETE FROM classes WHERE id=$1", [req.params.id]);
  res.json({ success: true });
});

// ================================
// ADMIN: Missionen
// ================================

app.get("/api/admin/missions", ensureAdmin, async (_req, res) => {
  const r = await pool.query("SELECT * FROM missions ORDER BY id DESC");
  res.json(r.rows);
});

app.post(
  "/api/admin/missions",
  ensureAdmin,
  upload.single("image"),
  async (req, res) => {
    try {
      const { title, xp } = req.body;
      const imagePath = req.file ? "/uploads/" + req.file.filename : null;

      const r = await pool.query(
        "INSERT INTO missions (title, xp, image_path) VALUES ($1,$2,$3) RETURNING *",
        [title, xp, imagePath]
      );

      res.json(r.rows[0]);
    } catch (err) {
      console.error("Mission Fehler:", err);
      res.status(500).json({ error: "Mission konnte nicht angelegt werden" });
    }
  }
);

app.delete("/api/admin/missions/:id", ensureAdmin, async (req, res) => {
  await pool.query("DELETE FROM missions WHERE id=$1", [req.params.id]);
  res.json({ success: true });
});

// ================================
// ADMIN: Schüler
// ================================

app.get("/api/admin/students/:classId", ensureAdmin, async (req, res) => {
  const r = await pool.query(
    "SELECT * FROM users WHERE role='student' AND class_id=$1 ORDER BY username",
    [req.params.classId]
  );
  res.json(r.rows);
});

app.post("/api/admin/students", ensureAdmin, async (req, res) => {
  try {
    const { username, password, class_id } = req.body;
    const hash = await bcrypt.hash(password, 10);

    const r = await pool.query(
      "INSERT INTO users (username, password_hash, role, class_id) VALUES ($1,$2,'student',$3) RETURNING *",
      [username, hash, class_id]
    );

    res.json(r.rows[0]);
  } catch (err) {
    console.error("Schüler anlegen Fehler:", err);
    res.status(500).json({ error: "Fehler beim Anlegen" });
  }
});

app.delete("/api/admin/students/:id", ensureAdmin, async (req, res) => {
  await pool.query("DELETE FROM users WHERE id=$1", [req.params.id]);
  res.json({ success: true });
});

// ================================
// XP Vergabe
// ================================
app.post("/api/admin/xp/give", ensureAdmin, async (req, res) => {
  try {
    const { studentIds, amount } = req.body;

    for (const id of studentIds) {
      await pool.query("UPDATE users SET xp=xp+$1 WHERE id=$2", [amount, id]);
    }
    res.json({ success: true });
  } catch (err) {
    console.error("XP Fehler:", err);
    res.status(500).json({ error: "XP konnte nicht vergeben werden" });
  }
});

// ================================
// Fallback: Admin-Seite
// ================================
app.get("/admin", ensureAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

// ================================
// Server Start
// ================================
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log("Server läuft auf Port " + PORT));
