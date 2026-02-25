import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import Database from "better-sqlite3";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const db = new Database("conduct.db");
const JWT_SECRET = process.env.JWT_SECRET || "super-secret-key";

// Initialize Database
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    name TEXT,
    role TEXT CHECK(role IN ('admin', 'teacher'))
  );

  CREATE TABLE IF NOT EXISTS students (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id TEXT UNIQUE,
    name TEXT,
    grade TEXT,
    score INTEGER DEFAULT 100
  );

  CREATE TABLE IF NOT EXISTS score_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id TEXT,
    score_change INTEGER,
    reason TEXT,
    teacher_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(student_id) REFERENCES students(student_id),
    FOREIGN KEY(teacher_id) REFERENCES users(id)
  );
`);

// Seed Admin if not exists
const adminExists = db.prepare("SELECT * FROM users WHERE username = ?").get("admin");
if (!adminExists) {
  const hashedPassword = bcrypt.hashSync("admin123", 10);
  db.prepare("INSERT INTO users (username, password, name, role) VALUES (?, ?, ?, ?)").run(
    "admin",
    hashedPassword,
    "ผู้ดูแลระบบ",
    "admin"
  );
}

async function startServer() {
  const app = express();
  app.use(express.json());

  // Auth Middleware
  const authenticateToken = (req: any, res: any, next: any) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) return res.status(401).json({ error: "Access denied" });

    jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
      if (err) return res.status(403).json({ error: "Invalid token" });
      req.user = user;
      next();
    });
  };

  // --- API Routes ---

  // Auth
  app.post("/api/auth/register", (req, res) => {
    const { username, password, name, role } = req.body;
    try {
      const hashedPassword = bcrypt.hashSync(password, 10);
      db.prepare("INSERT INTO users (username, password, name, role) VALUES (?, ?, ?, ?)").run(
        username,
        hashedPassword,
        name,
        role || "teacher"
      );
      res.json({ success: true });
    } catch (e) {
      res.status(400).json({ error: "Username already exists" });
    }
  });

  app.post("/api/auth/login", (req, res) => {
    const { username, password } = req.body;
    const user: any = db.prepare("SELECT * FROM users WHERE username = ?").get(username);

    if (user && bcrypt.compareSync(password, user.password)) {
      const token = jwt.sign({ id: user.id, username: user.username, role: user.role, name: user.name }, JWT_SECRET);
      res.json({ token, user: { id: user.id, username: user.username, role: user.role, name: user.name } });
    } else {
      res.status(401).json({ error: "Invalid credentials" });
    }
  });

  // Students
  app.get("/api/students", authenticateToken, (req, res) => {
    const students = db.prepare("SELECT * FROM students ORDER BY student_id ASC").all();
    res.json(students);
  });

  app.post("/api/students", authenticateToken, (req, res) => {
    if ((req as any).user.role !== "admin") return res.status(403).json({ error: "Admin only" });
    const { student_id, name, grade } = req.body;
    try {
      db.prepare("INSERT INTO students (student_id, name, grade) VALUES (?, ?, ?)").run(student_id, name, grade);
      res.json({ success: true });
    } catch (e) {
      res.status(400).json({ error: "Student ID already exists" });
    }
  });

  app.put("/api/students/:id", authenticateToken, (req, res) => {
    if ((req as any).user.role !== "admin") return res.status(403).json({ error: "Admin only" });
    const { student_id, name, grade } = req.body;
    try {
      db.prepare("UPDATE students SET student_id = ?, name = ?, grade = ? WHERE id = ?").run(
        student_id,
        name,
        grade,
        req.params.id
      );
      res.json({ success: true });
    } catch (e) {
      res.status(400).json({ error: "Failed to update student" });
    }
  });

  app.delete("/api/students/:id", authenticateToken, (req, res) => {
    if ((req as any).user.role !== "admin") return res.status(403).json({ error: "Admin only" });
    try {
      const student = db.prepare("SELECT student_id FROM students WHERE id = ?").get(req.params.id) as any;
      if (student) {
        db.transaction(() => {
          db.prepare("DELETE FROM score_history WHERE student_id = ?").run(student.student_id);
          db.prepare("DELETE FROM students WHERE id = ?").run(req.params.id);
        })();
      }
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: "Failed to delete student" });
    }
  });

  // Teachers list for filters
  app.get("/api/teachers", authenticateToken, (req, res) => {
    const teachers = db.prepare("SELECT id, name FROM users ORDER BY name ASC").all();
    res.json(teachers);
  });

  // Score Management
  app.post("/api/scores/update", authenticateToken, (req, res) => {
    const { student_id, score_change, reason } = req.body;
    const teacher_id = (req as any).user.id;

    const updateScore = db.transaction(() => {
      db.prepare("UPDATE students SET score = score + ? WHERE student_id = ?").run(score_change, student_id);
      db.prepare("INSERT INTO score_history (student_id, score_change, reason, teacher_id) VALUES (?, ?, ?, ?)").run(
        student_id,
        score_change,
        reason,
        teacher_id
      );
    });

    try {
      updateScore();
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: "Failed to update score" });
    }
  });

  app.get("/api/scores/history", authenticateToken, (req, res) => {
    const { student_id, teacher_id, type, start_date, end_date } = req.query;
    let query = `
      SELECT h.*, u.name as teacher_name, s.name as student_name, s.grade as student_grade
      FROM score_history h 
      JOIN users u ON h.teacher_id = u.id 
      JOIN students s ON h.student_id = s.student_id
      WHERE 1=1
    `;
    const params: any[] = [];

    if (student_id) {
      query += " AND h.student_id = ?";
      params.push(student_id);
    }
    if (teacher_id) {
      query += " AND h.teacher_id = ?";
      params.push(teacher_id);
    }
    if (type === "positive") {
      query += " AND h.score_change > 0";
    } else if (type === "negative") {
      query += " AND h.score_change < 0";
    }
    if (start_date) {
      query += " AND h.created_at >= ?";
      params.push(start_date);
    }
    if (end_date) {
      query += " AND h.created_at <= ?";
      params.push(`${end_date} 23:59:59`);
    }

    query += " ORDER BY h.created_at DESC";
    const history = db.prepare(query).all(...params);
    res.json(history);
  });

  app.get("/api/scores/history/:student_id", authenticateToken, (req, res) => {
    const history = db.prepare(`
      SELECT h.*, u.name as teacher_name 
      FROM score_history h 
      JOIN users u ON h.teacher_id = u.id 
      WHERE h.student_id = ? 
      ORDER BY h.created_at DESC
    `).all(req.params.student_id);
    res.json(history);
  });

  // Dashboard Stats
  app.get("/api/dashboard/stats", authenticateToken, (req, res) => {
    const totalStudents = db.prepare("SELECT COUNT(*) as count FROM students").get() as any;
    const avgScore = db.prepare("SELECT AVG(score) as avg FROM students").get() as any;
    const lowScores = db.prepare("SELECT COUNT(*) as count FROM students WHERE score < 60").get() as any;
    
    const scoreDistribution = db.prepare(`
      SELECT 
        CASE 
          WHEN score >= 80 THEN '80-100'
          WHEN score >= 60 THEN '60-79'
          WHEN score >= 40 THEN '40-59'
          ELSE '0-39'
        END as range,
        COUNT(*) as count
      FROM students
      GROUP BY range
    `).all();

    res.json({
      totalStudents: totalStudents.count,
      avgScore: Math.round(avgScore.avg || 0),
      lowScores: lowScores.count,
      scoreDistribution
    });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, "dist")));
    app.get("*", (req, res) => {
      res.sendFile(path.join(__dirname, "dist", "index.html"));
    });
  }

  const PORT = 3000;
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
