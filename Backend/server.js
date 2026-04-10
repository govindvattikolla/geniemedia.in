require("dotenv").config();

const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const multer = require("multer");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const path = require("path");
const fs = require("fs");

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
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      return callback(new Error("Not allowed by CORS"));
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

app.use(express.json());

// ================= STATIC FILES =================
app.use("/uploads", express.static(path.join(__dirname, "public/uploads")));
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
  if (err) console.log("❌ DB ERROR:", err);
  else console.log("✅ DB Connected Stable");
});

// ================= MULTER =================
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, "public/uploads");
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const unique = `${Date.now()}-${Math.round(Math.random() * 1e9)}${ext}`;
    cb(null, unique);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ["image/jpeg", "image/png", "image/webp"];
    if (allowed.includes(file.mimetype)) cb(null, true);
    else cb(new Error("Only images are allowed"));
  },
});
// ================= HELPER: Build full image URL =================
const BASE_URL = process.env.BASE_URL || "https://geniestudio.in";
// WITH THIS:
const getImageUrl = (imagePath) => {
  if (!imagePath) return null;
  return String(imagePath);
};
// ================= JWT MIDDLEWARE =================
const verifyToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader)
    return res.status(403).json({ success: false, message: "No token provided" });

  const token = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7)
    : authHeader;

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err)
      return res.status(401).json({ success: false, message: "Invalid or expired token" });
    req.user = decoded;
    next();
  });
};
app.use((req, res, next) => {
  if (
    process.env.NODE_ENV === "production" &&
    req.headers["x-forwarded-proto"] &&
    req.headers["x-forwarded-proto"] !== "https"
  ) {
    return res.redirect("https://" + req.headers.host + req.url);
  }
  next();
});
// ================= ROOT =================
app.get("/", (req, res) => {
  res.send("🚀 GenieStudio Backend is Working!");
});

// ================= LOGIN =================
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ success: false, message: "Email and password required" });

  db.query("SELECT * FROM admins WHERE email = ?", [email], async (err, result) => {
    if (err) return res.status(500).json({ success: false, message: "Database error" });
    if (result.length === 0)
      return res.status(401).json({ success: false, message: "Invalid credentials" });

    const user = result[0];
    const isHashed = user.password.startsWith("$2b$") || user.password.startsWith("$2a$");
    const passwordMatch = isHashed
      ? await bcrypt.compare(password, user.password)
      : password === user.password;

    if (!passwordMatch)
      return res.status(401).json({ success: false, message: "Invalid credentials" });

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );
    res.json({ success: true, token });
  });
});

// ================= CREATE BLOG =================
// app.post("/api/blogs", verifyToken, upload.single("image"), (req, res) => {
//   const { title, permalink, metaDescription, description, category, keywords, status } = req.body;

//   if (!title || !permalink)
//     return res.status(400).json({ success: false, message: "Title and permalink are required" });

//   // ✅ Store file path, not buffer
//   const image = req.file ? `/uploads/${req.file.filename}` : null;
//   const sql = `
//     INSERT INTO blogs 
//     (title, permalink, metaDescription, description, category, image, keywords, status, createdAt, updatedAt)
//     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
//   `;

//   db.query(
//     sql,
//     [title, permalink, metaDescription, description, category, image, keywords, status, Date.now(), Date.now()],
//     (err) => {
//       if (err) {
//         console.error("DB error creating blog:", err);
//         return res.status(500).json({ success: false, message: "Failed to create blog" });
//       }
//       res.json({ success: true, message: "Blog created" });
//     }
//   );
// });
const axios = require("axios");
const FormData = require("form-data");

app.post("/api/blogs", verifyToken, upload.single("image"), async (req, res) => {
  try {
    let imageUrl = null;

    if (req.file) {
      const formData = new FormData();
      formData.append("file", fs.createReadStream(req.file.path));

      const response = await axios.post(
        "https://geniestudio.in/upload.php", // 👈 Hostinger API
        formData,
        { headers: formData.getHeaders() }
      );

      imageUrl = response.data.url; // full HTTPS URL
    }

    const sql = `
      INSERT INTO blogs 
      (title, permalink, metaDescription, description, category, image, keywords, status, createdAt, updatedAt)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    db.query(
      sql,
      [req.body.title, req.body.permalink, req.body.metaDescription, req.body.description, req.body.category, imageUrl, req.body.keywords, req.body.status, Date.now(), Date.now()],
      (err) => {
        if (err) return res.status(500).json({ success: false });
        res.json({ success: true });
      }
    );

  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false });
  }
});
// ================= GET PUBLIC BLOGS =================
app.get("/api/blogs", (req, res) => {
  db.query("SELECT * FROM blogs WHERE status = 'published' ORDER BY createdAt DESC", (err, results) => {
    if (err) return res.status(500).json({ success: false, message: "Failed to fetch blogs" });

    // ✅ Return full HTTPS URL, no base64
    const blogs = results.map((blog) => ({
      ...blog,
      image: getImageUrl(blog.image),
    }));

    res.json(blogs);
  });
});

// ================= GET ALL BLOGS (ADMIN) =================
app.get("/api/admin/blogs", verifyToken, (req, res) => {
  db.query("SELECT * FROM blogs ORDER BY createdAt DESC", (err, results) => {
    if (err) return res.status(500).json({ success: false, message: "Failed to fetch blogs" });

    const blogs = results.map((blog) => ({
      ...blog,
      image: getImageUrl(blog.image),
    }));

    res.json(blogs);
  });
});

// ================= GET SINGLE BLOG BY SLUG =================
app.use("/api/blog", (req, res) => {
  const slug = req.path.replace(/^\//, "");
  if (!slug)
    return res.status(404).json({ success: false, message: "No slug provided" });

  db.query("SELECT * FROM blogs WHERE permalink = ?", [slug], (err, result) => {
    if (err) return res.status(500).json({ success: false, message: "Database error" });
    if (result.length === 0)
      return res.status(404).json({ success: false, message: "Blog not found" });

    const blog = { ...result[0], image: getImageUrl(result[0].image) };
    res.json(blog);
  });
});

// ================= UPDATE BLOG =================
app.put("/api/blogs/:id", verifyToken, upload.single("image"), (req, res) => {
  const { id } = req.params;
  const { title, permalink, metaDescription, description, category, keywords, status } = req.body;

  let sql = `
    UPDATE blogs SET 
    title = ?, permalink = ?, metaDescription = ?, description = ?, 
    category = ?, keywords = ?, status = ?, updatedAt = ?
  `;
  let values = [title, permalink, metaDescription, description, category, keywords, status, Date.now()];

  // ✅ Only update image column if a new file was uploaded
  if (req.file) {
    sql += ", image = ?";
    values.push(`/uploads/${req.file.filename}`);
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
  // ✅ Also delete the image file from disk when blog is deleted
  db.query("SELECT image FROM blogs WHERE id = ?", [req.params.id], (err, result) => {
    if (!err && result.length > 0 && result[0].image) {
      const filePath = path.join(__dirname, "public", result[0].image);
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    }

    db.query("DELETE FROM blogs WHERE id = ?", [req.params.id], (err2) => {
      if (err2) return res.status(500).json({ success: false, message: "Failed to delete blog" });
      res.json({ success: true, message: "Blog deleted" });
    });
  });
});

// ================= START =================
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`👉 Open: http://localhost:${PORT}`);
});