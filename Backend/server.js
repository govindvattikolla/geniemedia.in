require("dotenv").config();

const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const multer = require("multer");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const PORT = process.env.PORT || 5000;
const app = express();

// ================= CORS =================
const allowedOrigins = [
  "http://localhost:5173",
  "https://geniemedia.in",
];

app.use(
  cors({
    origin: function (origin, callback) {
      // Allow requests with no origin (Postman, mobile apps, curl)
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error("Not allowed by CORS"));
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

// Handle preflight requests for ALL routes
app.use(express.json());

// ================= DB CONNECTION =================
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

db.query("SELECT 1", (err) => {
  if (err) {
    console.log("❌ DB ERROR:", err);
  } else {
    console.log("✅ DB Connected Stable");
  }
});

// ================= MULTER =================
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
});

// ================= JWT MIDDLEWARE =================
const verifyToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];

  if (!authHeader) {
    return res.status(403).json({ success: false, message: "No token provided" });
  }

  // Support both "Bearer <token>" and raw token
  const token = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7)
    : authHeader;

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ success: false, message: "Invalid or expired token" });
    }
    req.user = decoded;
    next();
  });
};

// ================= ROOT ROUTE =================
app.get("/", (req, res) => {
  res.send("🚀 GenieStudio Backend is Working!");
});

// ================= LOGIN =================
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: "Email and password required" });
  }

  db.query("SELECT * FROM admins WHERE email = ?", [email], async (err, result) => {
    if (err) {
      console.error("DB error on login:", err);
      return res.status(500).json({ success: false, message: "Database error" });
    }

    if (result.length === 0) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    const user = result[0];

    // ✅ FIXED: Check if password is bcrypt hash or plain text
    const isHashed = user.password.startsWith("$2b$") || user.password.startsWith("$2a$");

    let passwordMatch = false;

    if (isHashed) {
      // bcrypt hashed password
      passwordMatch = await bcrypt.compare(password, user.password);
    } else {
      // plain text password (direct compare)
      passwordMatch = password === user.password;
    }

    if (!passwordMatch) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({ success: true, token });
  });
});

// ================= CREATE BLOG =================
app.post("/api/blogs", verifyToken, upload.single("image"), (req, res) => {
  const { title, permalink, metaDescription, description, category, keywords, status } = req.body;

  if (!title || !permalink) {
    return res.status(400).json({ success: false, message: "Title and permalink are required" });
  }

  const image = req.file ? req.file.buffer : null;
  const imageType = req.file ? req.file.mimetype : null;

  const sql = `
    INSERT INTO blogs 
    (title, permalink, metaDescription, description, category, image, imageType, keywords, status, createdAt, updatedAt)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.query(
    sql,
    [title, permalink, metaDescription, description, category, image, imageType, keywords, status, Date.now(), Date.now()],
    (err) => {
      if (err) {
        console.error("DB error creating blog:", err);
        return res.status(500).json({ success: false, message: "Failed to create blog" });
      }
      res.json({ success: true, message: "Blog created" });
    }
  );
});

// ================= GET PUBLIC BLOGS =================
app.get("/api/blogs", (req, res) => {
  db.query("SELECT * FROM blogs WHERE status = 'published' ORDER BY createdAt DESC", (err, results) => {
    if (err) {
      console.error("DB error fetching blogs:", err);
      return res.status(500).json({ success: false, message: "Failed to fetch blogs" });
    }

    const blogs = results.map((blog) => {
      if (blog.image) {
        blog.image = `data:${blog.imageType};base64,${blog.image.toString("base64")}`;
      }
      return blog;
    });

    res.json(blogs);
  });
});

// ================= GET ALL BLOGS (ADMIN) =================
app.get("/api/admin/blogs", verifyToken, (req, res) => {
  db.query("SELECT * FROM blogs ORDER BY createdAt DESC", (err, results) => {
    if (err) {
      console.error("DB error fetching admin blogs:", err);
      return res.status(500).json({ success: false, message: "Failed to fetch blogs" });
    }

    const blogs = results.map((blog) => {
      if (blog.image) {
        blog.image = `data:${blog.imageType};base64,${blog.image.toString("base64")}`;
      }
      return blog;
    });

    res.json(blogs);
  });
});

// ================= GET SINGLE BLOG BY SLUG =================
// ⚠️  NOTE: This uses app.use() which catches ALL methods — kept as-is to preserve existing behavior
app.use("/api/blog", (req, res) => {
  const slug = req.path.replace(/^\//, "");

  if (!slug) {
    return res.status(404).json({ success: false, message: "No slug provided" });
  }

  db.query("SELECT * FROM blogs WHERE permalink = ?", [slug], (err, result) => {
    if (err) {
      console.error("DB error fetching blog by slug:", err);
      return res.status(500).json({ success: false, message: "Database error" });
    }
    if (result.length === 0) {
      return res.status(404).json({ success: false, message: "Blog not found" });
    }

    let blog = result[0];
    if (blog.image) {
      blog.image = `data:${blog.imageType};base64,${blog.image.toString("base64")}`;
    }
    res.json(blog);
  });
});

// ================= UPDATE BLOG =================
app.put("/api/blogs/:id", verifyToken, upload.single("image"), (req, res) => {
  const { id } = req.params;
  const { title, permalink, metaDescription, description, category, keywords, status } = req.body;

  const image = req.file ? req.file.buffer : null;
  const imageType = req.file ? req.file.mimetype : null;

  let sql = `
    UPDATE blogs SET 
    title = ?, permalink = ?, metaDescription = ?, description = ?, 
    category = ?, keywords = ?, status = ?, updatedAt = ?
  `;

  let values = [title, permalink, metaDescription, description, category, keywords, status, Date.now()];

  if (image) {
    sql += ", image = ?, imageType = ?";
    values.push(image, imageType);
  }

  sql += " WHERE id = ?";
  values.push(id);

  db.query(sql, values, (err) => {
    if (err) {
      console.error("DB error updating blog:", err);
      return res.status(500).json({ success: false, message: "Failed to update blog" });
    }
    res.json({ success: true, message: "Blog updated" });
  });
});

// ================= DELETE BLOG =================
app.delete("/api/blogs/:id", verifyToken, (req, res) => {
  db.query("DELETE FROM blogs WHERE id = ?", [req.params.id], (err) => {
    if (err) {
      console.error("DB error deleting blog:", err);
      return res.status(500).json({ success: false, message: "Failed to delete blog" });
    }
    res.json({ success: true, message: "Blog deleted" });
  });
});

// ================= START =================
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`👉 Open: http://localhost:${PORT}`);
});