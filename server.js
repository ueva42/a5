import express from "express";
import session from "express-session";
import bcrypt from "bcrypt";
import pg from "pg";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 8080;

// PostgreSQL
const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
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

app.use(express.static(path.join(__dirname, "public")));

// =============== LOGIN ================
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password)
      return res.status(400).json({ error: "Username & Passwort erforderlich" });

    const result = await pool.query(
      "SELECT id, username, password_hash, role FROM users WHERE username=$1",
      [username]
    );

    if (result.rows.length === 0)
      return res.status(400).json({ error: "Benutzer existiert nicht" });

    const user = result.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);

    if (!ok) return res.status(400).json({ error: "Falsches Passwort" });

    req.session.user = {
      id: user.id,
      username: user.username,
      role: user.role,
    };

    res.json({ success: true, role: user.role });
  } catch (err) {
    console.error("Login-Fehler:", err);
    res.status(500).json({ error: "Serverfehler" });
  }
});

// =============== ADMIN PAGE =============
app.get("/admin", (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.redirect("/login.html");
  }

  res.send(`<h1>Adminbereich</h1><p>Login erfolgreich.</p>`);
});

// =============== ROOT ================
app.get("/", (req, res) => {
  res.redirect("/login.html");
});

// Start
app.listen(PORT, () => {
  console.log("Server läuft auf Port " + PORT);
});
