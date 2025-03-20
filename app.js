const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");
const bcrypt = require("bcryptjs");
const bodyParser = require("body-parser");

const app = express();

app.use(cors({ origin: "*", methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"] }));
const db = new sqlite3.Database(":memory:");

app.use(bodyParser.json());


db.serialize(() => {
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      role TEXT CHECK(role IN ('admin', 'user')) NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `);
});


app.get("/users", (req, res) => {
  db.all("SELECT id, name, role, email FROM users", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post("/users", async (req, res) => {
  const { name, role, email, password } = req.body;
  if (!name || !role || !email || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const stmt = db.prepare("INSERT INTO users (name, role, email, password) VALUES (?, ?, ?, ?)");

  stmt.run(name, role, email, hashedPassword, function (err) {
    if (err) return res.status(400).json({ error: err.message });
    res.json({ id: this.lastID, name, role, email });
  });

  stmt.finalize();
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email and password required" });

  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (err || !user) return res.status(401).json({ error: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Invalid credentials" });

    res.json({ message: "Login successful", user: { id: user.id, name: user.name, role: user.role, email: user.email } });
  });
});


app.delete("/users/:id", (req, res) => {
  const { id } = req.params;

  db.run("DELETE FROM users WHERE id = ?", [id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: "User not found" });

    res.json({ message: "User deleted successfully" });
  });
});


app.listen(3000, () => console.log("Server running on http://localhost:3000"));
