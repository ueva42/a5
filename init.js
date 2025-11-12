// init.js – Erstellt die komplette Datenbankstruktur und Admin-Account

import pg from "pg";
import bcrypt from "bcrypt";
import dotenv from "dotenv";

dotenv.config();
const { Pool } = pg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.DATABASE_URL?.includes("railway") ||
    process.env.PGSSLMODE === "require"
      ? { rejectUnauthorized: false }
      : false,
});

async function run() {
  console.log("🚀 Initialisiere Datenbank...");

  try {
    // Tabellen anlegen
    await pool.query(`
      CREATE TABLE IF NOT EXISTS classes (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        is_active BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS missions (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        xp_value INTEGER NOT NULL,
        image_path TEXT,
        allow_upload BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS characters (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        image_path TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        class_id INTEGER REFERENCES classes(id) ON DELETE SET NULL,
        character_id INTEGER REFERENCES characters(id) ON DELETE SET NULL,
        xp INTEGER DEFAULT 0,
        highest_xp INTEGER DEFAULT 0,
        traits JSONB DEFAULT '[]'::jsonb,
        equipment JSONB DEFAULT '[]'::jsonb,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS xp_transactions (
        id SERIAL PRIMARY KEY,
        student_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        amount INTEGER NOT NULL,
        reason TEXT,
        mission_id INTEGER REFERENCES missions(id) ON DELETE SET NULL,
        awarded_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS bonus_cards (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        xp_cost INTEGER NOT NULL,
        image_path TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS bonus_redemptions (
        id SERIAL PRIMARY KEY,
        bonus_card_id INTEGER REFERENCES bonus_cards(id) ON DELETE CASCADE,
        student_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS student_mission_uploads (
        id SERIAL PRIMARY KEY,
        mission_id INTEGER REFERENCES missions(id) ON DELETE CASCADE,
        student_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        file_path TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS levels (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        xp_threshold INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Admin anlegen (Standard)
    const adminHash = await bcrypt.hash("admin", 10);
    await pool.query(
      `INSERT INTO users (name, password, role)
       VALUES ($1, $2, 'admin')
       ON CONFLICT (name) DO UPDATE SET role = 'admin';`,
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

run();
