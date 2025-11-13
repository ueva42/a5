// =========================
// Temple of Logic - Server
// =========================

import express from "express";
import session from "express-session";
import pg from "pg";
import bcrypt from "bcrypt";
import path from "path";
import dotenv from "dotenv";
import multer from "multer";

dotenv.config();

const app = express();
const __dirname = process.cwd();

// ---------- MIDDLEWARE ----------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

// ---------- SESSION ----------
app.use(
  session({
    secret: process.env.SESSION_SECRET || "supersecret123",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 24 }, // 1 Tag
  })
);

// ---------- DATABASE ----------
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
});

// ---------- AUTH HELPERS ----------
function ensureAuthenticated(req, res, next) {
  if (req.session.userId) return next();
  return res.status(401).json({ error: "Nicht eingeloggt" });
}

function ensureRole(role) {
  return (req, res, next) => {
    if (req.session.role === role) return next();
    return res.status(403).json({ error: "Keine Berechtigung" });
  };
}

// ---------- UPLOADS (Schüler Avatar / Mission Bild später) ----------
const uploadFolder = path.join(__dirname, "uploads");
import fs from "fs";

if (!fs.existsSync(uploadFolder)) fs.mkdirSync(uploadFolder);

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, uploadFolder),
  filename: (_, file, cb) =>
    cb(null, Date.now() + "-" + file.originalname.replace(/\s+/g, "")),
});

const upload = multer({ storage });

// ==============================
//           ROUTES
// ==============================

// ---------- LOGIN ----------
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE username = $1 LIMIT 1",
      [username]
    );

    if (result.rows.length === 0)
      return res.status(400).json({ error: "Nutzer nicht gefunden" });

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch)
      return res.status(400).json({ error: "Passwort falsch" });

    req.session.userId = user.id;
    req.session.role = user.role;

    return res.json({ success: true, role: user.role });
  } catch (err) {
    console.error("Login-Fehler:", err);
    res.status(500).json({ error: "Serverfehler" });
  }
});

// ---------- LOGOUT ----------
app.get("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// ---------- FRONTEND ROUTES ----------
app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get(
  "/admin",
  ensureAuthenticated,
  ensureRole("admin"),
  (_req, res) => {
    res.sendFile(path.join(__dirname, "public", "admin.html"));
  }
);

// ---------- TEST ENDPOINT (optional) ----------
app.get("/api/ping", (_req, res) => {
  res.json({ pong: true });
});

// ==============================
//           SERVER START
// ==============================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("🚀 Server läuft auf Port:", PORT);
});
