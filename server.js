import express from "express";
import session from "express-session";
import multer from "multer";
import pg from "pg";
import bcrypt from "bcrypt";
import path from "path";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 8080;

// ------------------ DATABASE ------------------
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Test DB
pool.query("SELECT NOW()").catch((e) => console.error("DB ERROR:", e));

// ------------------ MIDDLEWARE ------------------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "secret123",
    resave: false,
    saveUninitialized: false,
  })
);

// Static files
app.use(express.static("public"));
app.use("/uploads", express.static("uploads"));

// File upload (avatars + mission images)
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads"),
  filename: (req, file, cb) =>
    cb(null, Date.now() + "-" + Math.random() + path.extname(file.originalname)),
});
const upload = multer({ storage });

// ------------------ AUTH HELPERS ------------------
function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Not logged in" });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin")
    return res.status(403).json({ error: "Admin only" });
  next();
}

// ------------------ LOGIN ------------------
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  const result = await pool.query("SELECT * FROM users WHERE username = $1", [
    username,
  ]);

  const user = result.rows[0];
  if (!user) return res.status(400).json({ error: "Unknown user" });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(400).json({ error: "Wrong password" });

  req.session.user = {
    id: user.id,
    username: user.username,
    role: user.role,
    class_id: user.class_id,
  };

  res.json({ success: true });
});

// ------------------ LOGOUT ------------------
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// ------------------ CLASSES ------------------

// Get all classes
app.get("/api/admin/classes", requireAdmin, async (_req, res) => {
  const r = await pool.query("SELECT * FROM classes ORDER BY id ASC");
  res.json(r.rows);
});

// Create class
app.post("/api/admin/classes", requireAdmin, async (req, res) => {
  const { name } = req.body;
  const r = await pool.query(
    "INSERT INTO classes (name) VALUES ($1) RETURNING *",
    [name]
  );
  res.json(r.rows[0]);
});

// Delete class
app.delete("/api/admin/classes/:id", requireAdmin, async (req, res) => {
  await pool.query("DELETE FROM classes WHERE id = $1", [req.params.id]);
  res.json({ success: true });
});

// ------------------ STUDENTS ------------------

// Get all students from active class
app.get("/api/admin/students", requireAdmin, async (req, res) => {
  const result = await pool.query(
    `SELECT id, username, xp, highest_xp, avatar_path, class_id
     FROM users
     WHERE role = 'student'
     ORDER BY id ASC`
  );
  res.json(result.rows);
});

// Create student
app.post("/api/admin/students", requireAdmin, async (req, res) => {
  const { username, password, class_id } = req.body;

  const ph = await bcrypt.hash(password, 10);

  const result = await pool.query(
    `INSERT INTO users (username, password_hash, role, class_id)
     VALUES ($1, $2, 'student', $3)
     RETURNING id, username, class_id`,
    [username, ph, class_id]
  );

  res.json(result.rows[0]);
});

// Delete student
app.delete("/api/admin/students/:id", requireAdmin, async (req, res) => {
  await pool.query("DELETE FROM users WHERE id=$1", [req.params.id]);
  res.json({ success: true });
});

// Upload student avatar
app.post(
  "/api/admin/students/:id/avatar",
  requireAdmin,
  upload.single("avatar"),
  async (req, res) => {
    await pool.query(
      "UPDATE users SET avatar_path=$1 WHERE id=$2",
      [req.file.path, req.params.id]
    );
    res.json({ success: true, avatar: req.file.path });
  }
);

// ------------------ MISSIONS ------------------

// Get missions
app.get("/api/admin/missions", requireAdmin, async (_req, res) => {
  const r = await pool.query("SELECT * FROM missions ORDER BY id ASC");
  res.json(r.rows);
});

// Create mission (+optional image)
app.post(
  "/api/admin/missions",
  requireAdmin,
  upload.single("image"),
  async (req, res) => {
    const { title, xp } = req.body;
    const imagePath = req.file ? req.file.path : null;

    const r = await pool.query(
      "INSERT INTO missions (title, xp, image_path) VALUES ($1, $2, $3) RETURNING *",
      [title, xp, imagePath]
    );
    res.json(r.rows[0]);
  }
);

// Delete mission
app.delete("/api/admin/missions/:id", requireAdmin, async (req, res) => {
  await pool.query("DELETE FROM missions WHERE id=$1", [req.params.id]);
  res.json({ success: true });
});

// ------------------ XP VERGABE ------------------
app.post("/api/admin/xp", requireAdmin, async (req, res) => {
  const { student_ids, xp } = req.body;

  for (const id of student_ids) {
    await pool.query(
      `UPDATE users 
       SET xp = xp + $1,
           highest_xp = GREATEST(highest_xp, xp + $1)
       WHERE id=$2`,
      [xp, id]
    );
  }

  res.json({ success: true });
});

// ------------------ START SERVER ------------------
app.listen(PORT, () => console.log("Server running on PORT", PORT));
