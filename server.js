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

// ---------------------------------------------------------------------
// Pfade / Basis
// ---------------------------------------------------------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// ---------------------------------------------------------------------
// Datenbank-Verbindung
// ---------------------------------------------------------------------
const { Pool } = pg;

const connectionString =
  process.env.DATABASE_URL ||
  "postgresql://postgres:postgres@localhost:5432/temple_of_logic";

const pool = new Pool({
  connectionString,
  ssl:
    connectionString.includes("railway") ||
    process.env.PGSSLMODE === "require"
      ? { rejectUnauthorized: false }
      : false,
});

// kleine Hilfsfunktion für Queries mit Fehler-Log
async function dbQuery(text, params = []) {
  try {
    return await pool.query(text, params);
  } catch (err) {
    console.error("DB-Fehler:", err);
    throw err;
  }
}

// ---------------------------------------------------------------------
// Upload-Verzeichnis / Multer
// ---------------------------------------------------------------------
const uploadDir = process.env.UPLOAD_DIR
  ? path.resolve(process.env.UPLOAD_DIR)
  : path.join(__dirname, "uploads");

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadDir),
  filename: (_req, file, cb) => {
    const ts = Date.now();
    const sanitized = file.originalname.replace(/[^a-zA-Z0-9_.-]/g, "_");
    cb(null, `${ts}-${sanitized}`);
  },
});

const upload = multer({ storage });

function toPublicPath(filePath) {
  if (!filePath) return null;
  return `/uploads/${path.basename(filePath)}`;
}

// ---------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "temple-secret",
    resave: false,
    saveUninitialized: false,
  })
);

const publicDir = path.join(__dirname, "public");
app.use(express.static(publicDir));
app.use("/uploads", express.static(uploadDir));

// ---------------------------------------------------------------------
// Auth-Middleware
// ---------------------------------------------------------------------
function ensureAuthenticated(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: "Nicht angemeldet" });
  }
  next();
}

function ensureRole(role) {
  return function (req, res, next) {
    if (!req.session.user || req.session.user.role !== role) {
      return res.status(403).json({ error: "Keine Berechtigung" });
    }
    next();
  };
}

// ---------------------------------------------------------------------
// DB-Initialisierung (automatisch beim Start UND per init.js nutzbar)
// ---------------------------------------------------------------------
async function ensureDatabase() {
  console.log("🔧 Prüfe / initialisiere Datenbank …");

  // Klassen
  await dbQuery(`
    CREATE TABLE IF NOT EXISTS classes (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      is_active BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  // Users
  await dbQuery(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL,
      class_id INTEGER REFERENCES classes(id) ON DELETE SET NULL,
      xp INTEGER DEFAULT 0,
      highest_xp INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )
  `);

  // Missionen
  await dbQuery(`
    CREATE TABLE IF NOT EXISTS missions (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      xp_value INTEGER NOT NULL,
      image_path TEXT,
      allow_upload BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  // Schüler-Uploads zu Missionen
  await dbQuery(`
    CREATE TABLE IF NOT EXISTS student_mission_uploads (
      id SERIAL PRIMARY KEY,
      mission_id INTEGER REFERENCES missions(id) ON DELETE CASCADE,
      student_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      file_path TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  // XP-Buchungen
  await dbQuery(`
    CREATE TABLE IF NOT EXISTS xp_transactions (
      id SERIAL PRIMARY KEY,
      student_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      amount INTEGER NOT NULL,
      reason TEXT,
      mission_id INTEGER REFERENCES missions(id) ON DELETE SET NULL,
      awarded_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  // Admin-User sicherstellen
  const adminName = process.env.ADMIN_NAME || "admin";
  const adminPassword = process.env.ADMIN_PASSWORD || "admin";

  const result = await dbQuery("SELECT id FROM users WHERE name = $1", [
    adminName,
  ]);

  if (result.rows.length === 0) {
    const hash = await bcrypt.hash(adminPassword, 10);
    await dbQuery(
      `INSERT INTO users (name, password, role) VALUES ($1, $2, 'admin')`,
      [adminName, hash]
    );
    console.log(`✅ Admin angelegt: ${adminName}/${adminPassword}`);
  } else {
    console.log("✅ Admin existiert bereits");
  }

  console.log("✅ DB-Check fertig");
}

// ---------------------------------------------------------------------
// Routen: Basis / Auth
// ---------------------------------------------------------------------
app.get("/", (_req, res) => {
  return res.redirect("/login.html");
});

app.get("/login", (_req, res) => {
  return res.sendFile(path.join(publicDir, "login.html"));
});

app.get("/admin", (req, res) => {
  // Admin-Seite nur ausliefern, JS prüft Session
  return res.sendFile(path.join(publicDir, "admin.html"));
});

// Session-Status
app.get("/api/session", (req, res) => {
  if (!req.session.user) {
    return res.json({ authenticated: false });
  }
  res.json({ authenticated: true, user: req.session.user });
});

// Login
app.post("/api/login", async (req, res) => {
  const { name, password } = req.body;
  if (!name || !password) {
    return res.status(400).json({ error: "Name und Passwort erforderlich" });
  }

  try {
    const result = await dbQuery("SELECT * FROM users WHERE name = $1", [
      name.trim(),
    ]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: "Benutzer nicht gefunden" });
    }
    const user = result.rows[0];

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) {
      return res.status(400).json({ error: "Falsches Passwort" });
    }

    req.session.user = {
      id: user.id,
      name: user.name,
      role: user.role,
    };

    res.json({ success: true, role: user.role });
  } catch (err) {
    console.error("Login-Fehler:", err);
    res.status(500).json({ error: "Serverfehler beim Login" });
  }
});

// Logout
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// ---------------------------------------------------------------------
// Hilfsfunktionen
// ---------------------------------------------------------------------
async function getActiveClass() {
  const { rows } = await dbQuery(
    "SELECT * FROM classes WHERE is_active = TRUE LIMIT 1"
  );
  return rows[0] || null;
}

// ---------------------------------------------------------------------
// Klassen-API
// ---------------------------------------------------------------------
app.get(
  "/api/admin/classes",
  ensureAuthenticated,
  ensureRole("admin"),
  async (_req, res) => {
    try {
      const { rows } = await dbQuery(
        "SELECT id, name, is_active FROM classes ORDER BY name"
      );
      res.json(rows);
    } catch (err) {
      console.error(err);
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
    if (!name || !name.trim()) {
      return res.status(400).json({ error: "Klassenname ist erforderlich" });
    }
    try {
      const { rows } = await dbQuery(
        "INSERT INTO classes (name) VALUES ($1) RETURNING id, name, is_active",
        [name.trim()]
      );
      res.status(201).json(rows[0]);
    } catch (err) {
      console.error(err);
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
      await dbQuery("UPDATE classes SET is_active = FALSE");
      const { rows } = await dbQuery(
        "UPDATE classes SET is_active = TRUE WHERE id = $1 RETURNING id, name, is_active",
        [id]
      );
      if (!rows[0]) {
        return res.status(404).json({ error: "Klasse nicht gefunden" });
      }
      res.json(rows[0]);
    } catch (err) {
      console.error(err);
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
      const { rows } = await dbQuery(
        "DELETE FROM classes WHERE id = $1 RETURNING id",
        [id]
      );
      if (!rows[0]) {
        return res.status(404).json({ error: "Klasse nicht gefunden" });
      }
      res.json({ success: true });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Klasse konnte nicht gelöscht werden" });
    }
  }
);

// ---------------------------------------------------------------------
// Missionen-API
// ---------------------------------------------------------------------
app.get(
  "/api/admin/missions",
  ensureAuthenticated,
  ensureRole("admin"),
  async (_req, res) => {
    try {
      const { rows } = await dbQuery(
        "SELECT id, title, description, xp_value, image_path, allow_upload FROM missions ORDER BY created_at DESC"
      );
      const missions = rows.map((m) => ({
        id: m.id,
        title: m.title,
        description: m.description,
        xp_value: Number(m.xp_value) || 0,
        allow_upload: m.allow_upload,
        image_url: toPublicPath(m.image_path),
      }));
      res.json(missions);
    } catch (err) {
      console.error(err);
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
    const { title, description, xp_value, allow_upload } = req.body;
    if (!title || !title.trim() || !xp_value) {
      return res
        .status(400)
        .json({ error: "Titel und XP-Wert sind erforderlich" });
    }
    try {
      const xpVal = Number(xp_value);
      const imagePath = req.file ? req.file.path : null;
      const allow = !!(
        allow_upload === "on" ||
        allow_upload === "true" ||
        allow_upload === "1"
      );

      const { rows } = await dbQuery(
        `INSERT INTO missions (title, description, xp_value, image_path, allow_upload)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, title, description, xp_value, image_path, allow_upload`,
        [title.trim(), description || null, xpVal, imagePath, allow]
      );

      const m = rows[0];
      res.status(201).json({
        id: m.id,
        title: m.title,
        description: m.description,
        xp_value: Number(m.xp_value) || 0,
        allow_upload: m.allow_upload,
        image_url: toPublicPath(m.image_path),
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Mission konnte nicht angelegt werden" });
    }
  }
);

app.delete(
  "/api/admin/missions/:id",
  ensureAuthenticated,
  ensureRole("admin"),
  async (req, res) => {
    const { id } = req.params;
    try {
      // erst Bildpfad holen
      const { rows: missionRows } = await dbQuery(
        "SELECT image_path FROM missions WHERE id = $1",
        [id]
      );
      if (!missionRows[0]) {
        return res.status(404).json({ error: "Mission nicht gefunden" });
      }
      const imagePath = missionRows[0].image_path;

      // verknüpfte Uploads löschen (inkl. Dateien)
      const { rows: uploadRows } = await dbQuery(
        "SELECT file_path FROM student_mission_uploads WHERE mission_id = $1",
        [id]
      );
      for (const row of uploadRows) {
        if (row.file_path && fs.existsSync(row.file_path)) {
          fs.unlink(row.file_path, () => {});
        }
      }
      await dbQuery("DELETE FROM student_mission_uploads WHERE mission_id = $1", [
        id,
      ]);

      // Mission selbst löschen
      await dbQuery("DELETE FROM missions WHERE id = $1", [id]);

      if (imagePath && fs.existsSync(imagePath)) {
        fs.unlink(imagePath, () => {});
      }

      res.json({ success: true });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Mission konnte nicht gelöscht werden" });
    }
  }
);

// ---------------------------------------------------------------------
// Schüler-API
// ---------------------------------------------------------------------
app.get(
  "/api/admin/students",
  ensureAuthenticated,
  ensureRole("admin"),
  async (req, res) => {
    try {
      const classId = req.query.classId;
      let targetClassId = classId;
      if (!targetClassId) {
        const active = await getActiveClass();
        targetClassId = active ? active.id : null;
      }

      if (!targetClassId) {
        return res.json([]);
      }

      const { rows } = await dbQuery(
        `SELECT id, name, xp, highest_xp
         FROM users
         WHERE role = 'student' AND class_id = $1
         ORDER BY name`,
        [targetClassId]
      );

      const students = rows.map((s) => ({
        id: s.id,
        name: s.name,
        xp: Number(s.xp) || 0,
        highest_xp: Number(s.highest_xp) || 0,
      }));

      res.json(students);
    } catch (err) {
      console.error(err);
      res
        .status(500)
        .json({ error: "Schüler:innen konnten nicht geladen werden" });
    }
  }
);

app.post(
  "/api/admin/students",
  ensureAuthenticated,
  ensureRole("admin"),
  async (req, res) => {
    const { name, password, classId } = req.body;
    if (!name || !name.trim() || !password) {
      return res
        .status(400)
        .json({ error: "Name und Passwort sind erforderlich" });
    }

    try {
      let targetClassId = classId;
      if (!targetClassId) {
        const active = await getActiveClass();
        targetClassId = active ? active.id : null;
      }
      if (!targetClassId) {
        return res.status(400).json({ error: "Keine aktive Klasse gewählt" });
      }

      const hash = await bcrypt.hash(password, 10);
      const { rows } = await dbQuery(
        `INSERT INTO users (name, password, role, class_id)
         VALUES ($1, $2, 'student', $3)
         RETURNING id, name, xp, highest_xp`,
        [name.trim(), hash, targetClassId]
      );

      const s = rows[0];
      res.status(201).json({
        id: s.id,
        name: s.name,
        xp: Number(s.xp) || 0,
        highest_xp: Number(s.highest_xp) || 0,
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Schüler:in konnte nicht angelegt werden" });
    }
  }
);

// Hard Delete Schüler
app.delete(
  "/api/admin/students/:id",
  ensureAuthenticated,
  ensureRole("admin"),
  async (req, res) => {
    const { id } = req.params;
    try {
      // zugehörige Uploads-Dateien löschen
      const { rows: uploadRows } = await dbQuery(
        "SELECT file_path FROM student_mission_uploads WHERE student_id = $1",
        [id]
      );
      for (const row of uploadRows) {
        if (row.file_path && fs.existsSync(row.file_path)) {
          fs.unlink(row.file_path, () => {});
        }
      }

      // Child-Tabellen (zur Sicherheit)
      await dbQuery("DELETE FROM student_mission_uploads WHERE student_id = $1", [
        id,
      ]);
      await dbQuery("DELETE FROM xp_transactions WHERE student_id = $1", [id]);

      // User löschen
      const { rows } = await dbQuery(
        "DELETE FROM users WHERE id = $1 AND role = 'student' RETURNING id",
        [id]
      );
      if (!rows[0]) {
        return res.status(404).json({ error: "Schüler:in nicht gefunden" });
      }
      res.json({ success: true });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Schüler:in konnte nicht gelöscht werden" });
    }
  }
);

// ---------------------------------------------------------------------
// XP-Vergabe
// ---------------------------------------------------------------------
app.post(
  "/api/admin/xp-awards",
  ensureAuthenticated,
  ensureRole("admin"),
  async (req, res) => {
    let { studentIds = [], amount, missionId, reason, applyToAll } = req.body;

    try {
      // applyToAll: alle Schüler der aktiven Klasse
      if (applyToAll) {
        const active = await getActiveClass();
        if (!active) {
          return res
            .status(400)
            .json({ error: "Keine aktive Klasse ausgewählt" });
        }
        const { rows } = await dbQuery(
          "SELECT id FROM users WHERE role = 'student' AND class_id = $1",
          [active.id]
        );
        studentIds = rows.map((r) => r.id);
      }

      if (!Array.isArray(studentIds)) {
        // Single ID als string
        if (studentIds) studentIds = [studentIds];
        else studentIds = [];
      }

      if (!studentIds.length) {
        return res
          .status(400)
          .json({ error: "Keine Schüler:innen ausgewählt" });
      }

      let customAmount = Number(amount);
      if (Number.isNaN(customAmount)) customAmount = 0;

      let missionXp = 0;
      if (missionId) {
        const { rows } = await dbQuery(
          "SELECT xp_value FROM missions WHERE id = $1",
          [missionId]
        );
        if (!rows[0]) {
          return res.status(404).json({ error: "Mission nicht gefunden" });
        }
        missionXp = Number(rows[0].xp_value) || 0;
      }

      if (!customAmount && !missionXp) {
        return res
          .status(400)
          .json({ error: "XP-Betrag oder Mission erforderlich" });
      }

      const xpToAdd = customAmount + missionXp;
      const awarded = [];

      for (const sid of studentIds) {
        const { rows } = await dbQuery(
          "SELECT xp, highest_xp FROM users WHERE id = $1 AND role = 'student'",
          [sid]
        );
        if (!rows[0]) continue;
        const currentXp = Number(rows[0].xp) || 0;
        const highestXp = Number(rows[0].highest_xp) || 0;

        const newXp = currentXp + xpToAdd;
        const newHighest = Math.max(highestXp, newXp);

        await dbQuery(
          "UPDATE users SET xp = $1, highest_xp = $2, updated_at = NOW() WHERE id = $3",
          [newXp, newHighest, sid]
        );

        await dbQuery(
          `INSERT INTO xp_transactions (student_id, amount, reason, mission_id, awarded_by)
           VALUES ($1, $2, $3, $4, $5)`,
          [sid, xpToAdd, reason || null, missionId || null, req.session.user.id]
        );

        awarded.push({ studentId: sid, newXp, newHighest });
      }

      res.json({ success: true, awarded, xpAdded: xpToAdd });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "XP konnten nicht vergeben werden" });
    }
  }
);

// ---------------------------------------------------------------------
// Mission-Uploads – Schülerseite (für später) & Admin-Übersicht
// ---------------------------------------------------------------------

// Schüler-Upload für eine Mission
app.post(
  "/api/student/missions/:id/upload",
  ensureAuthenticated,
  ensureRole("student"),
  upload.single("image"),
  async (req, res) => {
    const { id } = req.params;
    try {
      const { rows } = await dbQuery(
        "SELECT allow_upload FROM missions WHERE id = $1",
        [id]
      );
      if (!rows[0] || !rows[0].allow_upload) {
        return res
          .status(400)
          .json({ error: "Für diese Mission sind keine Uploads möglich" });
      }
      if (!req.file) {
        return res.status(400).json({ error: "Bilddatei erforderlich" });
      }

      const { rows: ins } = await dbQuery(
        `INSERT INTO student_mission_uploads (mission_id, student_id, file_path)
         VALUES ($1, $2, $3)
         RETURNING id, file_path, created_at`,
        [id, req.session.user.id, req.file.path]
      );

      const up = ins[0];
      res.status(201).json({
        id: up.id,
        file_url: toPublicPath(up.file_path),
        created_at: up.created_at,
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Upload fehlgeschlagen" });
    }
  }
);

// Admin: alle Uploads ansehen
app.get(
  "/api/admin/mission-uploads",
  ensureAuthenticated,
  ensureRole("admin"),
  async (_req, res) => {
    try {
      const { rows } = await dbQuery(
        `SELECT u.id,
                u.file_path,
                u.created_at,
                m.title AS mission_title,
                s.name AS student_name
         FROM student_mission_uploads u
         JOIN missions m ON m.id = u.mission_id
         JOIN users s ON s.id = u.student_id
         ORDER BY u.created_at DESC`
      );

      const uploads = rows.map((r) => ({
        id: r.id,
        file_url: toPublicPath(r.file_path),
        created_at: r.created_at,
        mission_title: r.mission_title,
        student_name: r.student_name,
      }));

      res.json(uploads);
    } catch (err) {
      console.error(err);
      res
        .status(500)
        .json({ error: "Mission-Uploads konnten nicht geladen werden" });
    }
  }
);

// Admin: Upload löschen
app.delete(
  "/api/admin/mission-uploads/:id",
  ensureAuthenticated,
  ensureRole("admin"),
  async (req, res) => {
    const { id } = req.params;
    try {
      const { rows } = await dbQuery(
        "DELETE FROM student_mission_uploads WHERE id = $1 RETURNING file_path",
        [id]
      );
      if (!rows[0]) {
        return res.status(404).json({ error: "Upload nicht gefunden" });
      }
      const filePath = rows[0].file_path;
      if (filePath && fs.existsSync(filePath)) {
        fs.unlink(filePath, () => {});
      }
      res.json({ success: true });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Upload konnte nicht gelöscht werden" });
    }
  }
);

// ---------------------------------------------------------------------
// Serverstart
// ---------------------------------------------------------------------
ensureDatabase()
  .then(() => {
    app.listen(PORT, () =>
      console.log(`🚀 Server läuft auf Port ${PORT}`)
    );
  })
  .catch((err) => {
    console.error("❌ Fehler bei DB-Initialisierung:", err);
    process.exit(1);
  });
