require("dotenv").config();

const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const multer = require("multer");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const path = require("path");
const fs = require("fs");
const axios = require("axios");
const FormData = require("form-data");

const PORT = process.env.PORT || 5000;
const app = express();

// ================= CORS =================
const allowedOrigins = [
  "http://localhost:5173",
  "http://127.0.0.1:5173", // ✅ add this
  "https://geniemedia.in",
  "https://www.geniemedia.in/"
];

app.options("*", cors());

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);

      // ✅ FIX: flexible matching instead of strict includes
      const isAllowed = allowedOrigins.some((allowed) =>
        origin.startsWith(allowed)
      );

      if (isAllowed) return callback(null, true);

      console.log("❌ Blocked by CORS:", origin); // 👈 debug
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
// Multer is only used as a temp buffer before uploading to Hostinger
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

// ================= HELPER: Upload file to Hostinger =================
// Uploads temp file to upload.php, returns full HTTPS URL, cleans up temp file
const uploadToHostinger = async (tempFilePath) => {
  try {
    const formData = new FormData();
    formData.append("file", fs.createReadStream(tempFilePath));

    const response = await axios.post(
      "https://geniemedia.in/upload.php",
      formData,
      { headers: formData.getHeaders() }
    );

    return response.data.url; // full HTTPS URL from Hostinger
  } finally {
    // Always clean up the temp file, whether upload succeeded or failed
    try {
      if (fs.existsSync(tempFilePath)) fs.unlinkSync(tempFilePath);
    } catch (_) {}
  }
};

// ================= HELPER: Normalize image URL =================
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
  res.send("🚀 geniemedia Backend is Working!");
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
app.post("/api/blogs", verifyToken, upload.single("image"), async (req, res) => {
  try {
    let imageUrl = null;

    if (req.file) {
      // Upload temp file to Hostinger, get back full HTTPS URL
      imageUrl = await uploadToHostinger(req.file.path);
    }

    const sql = `
      INSERT INTO blogs 
      (title, permalink, metaDescription, description, category, image, keywords, status, createdAt, updatedAt)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    db.query(
      sql,
      [
        req.body.title,
        req.body.permalink,
        req.body.metaDescription,
        req.body.description,
        req.body.category,
        imageUrl,
        req.body.keywords,
        req.body.status,
        Date.now(),
        Date.now(),
      ],
      (err) => {
        if (err) {
          console.error("DB error creating blog:", err);
          return res.status(500).json({ success: false, message: "Failed to create blog" });
        }
        res.json({ success: true, message: "Blog created" });
      }
    );
  } catch (err) {
    console.error("Error creating blog:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ================= GET PUBLIC BLOGS =================
app.get("/api/blogs", (req, res) => {
  db.query("SELECT * FROM blogs WHERE status = 'published' ORDER BY createdAt DESC", (err, results) => {
    if (err) return res.status(500).json({ success: false, message: "Failed to fetch blogs" });

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
app.put("/api/blogs/:id", verifyToken, upload.single("image"), async (req, res) => {
  const { id } = req.params;
  const {
    title,
    permalink,
    metaDescription,
    description,
    category,
    keywords,
    status,
    existingImage, // ✅ sent by frontend when no new file is chosen — preserve current image
  } = req.body;

  try {
    let imageUrl;

    if (req.file) {
      // ✅ FIX: New file uploaded → send it to Hostinger upload.php, get full HTTPS URL
      // Previously this was storing a local /uploads/ path which broke on Hostinger
      imageUrl = await uploadToHostinger(req.file.path);
    } else if (existingImage && existingImage.trim() !== "") {
      // ✅ No new file, but frontend passed the current image URL → keep it
      imageUrl = existingImage.trim();
    } else {
      // No file, no existingImage → user intentionally removed the image
      imageUrl = null;
    }

    const sql = `
      UPDATE blogs SET
        title = ?,
        permalink = ?,
        metaDescription = ?,
        description = ?,
        category = ?,
        keywords = ?,
        status = ?,
        image = ?,
        updatedAt = ?
      WHERE id = ?
    `;

    const values = [
      title,
      permalink,
      metaDescription,
      description,
      category,
      keywords,
      status,
      imageUrl,   // ✅ always explicitly set — no conditional column building
      Date.now(),
      id,
    ];

    db.query(sql, values, (err) => {
      if (err) {
        console.error("DB error updating blog:", err);
        return res.status(500).json({ success: false, message: "Failed to update blog" });
      }
      res.json({ success: true, message: "Blog updated" });
    });
  } catch (err) {
    console.error("Error updating blog:", err);
    res.status(500).json({ success: false, message: "Server error uploading image" });
  }
});

// ================= DELETE BLOG =================
app.delete("/api/blogs/:id", verifyToken, (req, res) => {
  db.query("SELECT image FROM blogs WHERE id = ?", [req.params.id], (err, result) => {
    // Note: images are stored on Hostinger, not locally, so local file deletion is skipped
    // If you want to also delete from Hostinger you'd need a delete endpoint on upload.php

    db.query("DELETE FROM blogs WHERE id = ?", [req.params.id], (err2) => {
      if (err2) return res.status(500).json({ success: false, message: "Failed to delete blog" });
      res.json({ success: true, message: "Blog deleted" });
    });
  });
});

// ================= OG SHARE PREVIEW =================
// When a blog link is shared on WhatsApp / Twitter / LinkedIn / Telegram etc.,
// social crawlers hit this URL, read the OG meta tags, and render the preview card.
// Regular human visitors are instantly JS-redirected to the actual React blog page.
//
// Share URL format:  https://<your-backend-domain>/share/<permalink>
// Example:           https://api.geniemedia.in/share/services/my-blog-post
//
// In AdminBlogs.jsx the "Copy Share Link" button copies exactly this URL.

const escapeHtml = (str) =>
  String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
// ================= OG SHARE PREVIEW =================
app.use("/share/", (req, res) => {
  const permalink = req.path.replace(/^\//, "");
  if (!permalink) return res.redirect("https://geniemedia.in");

  db.query(
    "SELECT title, metaDescription, image, permalink FROM blogs WHERE permalink = ?",
    [permalink],
    (err, result) => {
      if (err || result.length === 0) {
        return res.redirect("https://geniemedia.in/blog");
      }
      const blog        = result[0];
      const title       = escapeHtml(blog.title || "geniemedia Blog");
      const description = escapeHtml(blog.metaDescription || "Read this article on geniemedia");
      const image       = escapeHtml(blog.image || "https://geniemedia.in/og-default.jpg");
      const pageUrl     = `https://geniemedia.in/blog/${blog.permalink}`;

      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>${title}</title>
  <meta name="description" content="${description}" />
  <meta property="og:type"        content="article" />
  <meta property="og:title"       content="${title}" />
  <meta property="og:description" content="${description}" />
  <meta property="og:image"       content="${image}" />
  <meta property="og:image:width"  content="1200" />
  <meta property="og:image:height" content="630" />
  <meta property="og:url"         content="${pageUrl}" />
  <meta property="og:site_name"   content="geniemedia" />
  <meta name="twitter:card"        content="summary_large_image" />
  <meta name="twitter:title"       content="${title}" />
  <meta name="twitter:description" content="${description}" />
  <meta name="twitter:image"       content="${image}" />
  <meta http-equiv="refresh" content="0;url=${pageUrl}" />
</head>
<body style="margin:0;background:#1a1a1a;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center;">
  <div>
    <p style="font-size:14px;color:#aaa;margin-bottom:12px;">Redirecting you to the article…</p>
    <a href="${pageUrl}" style="color:#D4B49A;font-size:16px;font-weight:bold;">${title}</a>
  </div>
  <script>window.location.replace("${pageUrl}");</script>
</body>
</html>`);
    }
  );
});

// ================= START =================
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`👉 Open: http://localhost:${PORT}`);
});