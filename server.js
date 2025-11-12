// ----- Klassenverwaltung -----
app.get("/api/admin/classes", ensureAuthenticated, ensureRole("admin"), async (_req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT id, name, is_active FROM classes ORDER BY name"
    );
    res.json(rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Klassen konnten nicht geladen werden" });
  }
});

app.post("/api/admin/classes", ensureAuthenticated, ensureRole("admin"), async (req, res) => {
  const { name } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: "Klassenname erforderlich" });

  try {
    const { rows } = await pool.query(
      "INSERT INTO classes (name) VALUES ($1) RETURNING id, name, is_active",
      [name.trim()]
    );
    res.status(201).json(rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Klasse konnte nicht angelegt werden" });
  }
});

app.patch("/api/admin/classes/:id/activate", ensureAuthenticated, ensureRole("admin"), async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query("UPDATE classes SET is_active = FALSE");
    const { rows } = await pool.query(
      "UPDATE classes SET is_active = TRUE WHERE id = $1 RETURNING id, name, is_active",
      [id]
    );
    if (!rows[0]) return res.status(404).json({ error: "Klasse nicht gefunden" });
    res.json(rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Klasse konnte nicht aktiviert werden" });
  }
});
