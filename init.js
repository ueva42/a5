// -------------------------------
// Temple of Logic – init.js
// Erstellt Tabellen und legt Admin-Account an
// -------------------------------

import pg from "pg";
import bcrypt from "bcrypt";
import dotenv from "dotenv";

dotenv.config();

const { Pool } = pg;

// ---- Verbindung zur Datenbank ----
const connectionString =
  process.env.DATABASE_URL ||
  "postgresql://postgres:aNSttxYnkdYPWBokKWaSfWZmSUamsZqY@shuttle.proxy.rlwy.net:42998/railway";

const pool = new Pool({
  connectionString,
  ssl: connectionString.includes("railway")
    ? { rejectUnauthorized: false }
    : false,
});

// ---- Tabellen erstellen + Admin anlegen ----
async function run() {
  console.log("🚀 Initialisiere Datenbank...");

  try {
    // Klassen
    await pool.query(`
      CREATE TABLE IF NOT EXISTS classes (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        is_active BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Benutzer
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        class_id INTEGER REFERENCES classes(id) ON DELETE SET NULL,
        xp INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Missionen
    await pool.query(`
      CREATE TABLE IF NOT EXISTS missions (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        xp_value INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Bonuskarten
    await pool.query(`
      CREATE TABLE IF NOT EXISTS bonus_cards (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        xp_cost INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Level
    await pool.query(`
      CREATE TABLE IF NOT EXISTS levels (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        xp_threshold INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Admin anlegen
    const adminHash = await bcrypt.hash("admin", 10);
    await pool.query(
      `INSERT INTO users (name, password, role)
       VALUES ($1, $2, 'admin')
       ON CONFLICT (name) DO NOTHING`,
      ["admin", adminHash]
    );

    console.log("✅ Tabellen erstellt & Admin-Account angelegt!");
  } catch (err) {
    console.error("❌ Fehler beim Initialisieren:", err);
  } finally {
    await pool.end();
    console.log("🏁 Fertig!");
  }
}

// ---- Start ----
run();
