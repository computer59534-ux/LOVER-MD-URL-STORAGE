
require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const multer = require("multer");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();

const PORT = Number(process.env.PORT || 3000);
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/+$/, "");

const API_KEY = process.env.API_KEY || "";
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";

const MAX_FILE_MB = Number(process.env.MAX_FILE_MB || 10);
const STORAGE_DIR = path.resolve(
  process.env.STORAGE_DIR || path.join(__dirname, "uploads")
);

if (API_KEY.length < 24) {
  throw new Error("API_KEY must be at least 24 characters long.");
}

if (ADMIN_PASSWORD.length < 12) {
  throw new Error("ADMIN_PASSWORD must be at least 12 characters long.");
}

fs.mkdirSync(STORAGE_DIR, { recursive: true });

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

app.use("/uploads", express.static(STORAGE_DIR));

const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 60,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 60,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

function safeEqual(a, b) {
  const first = Buffer.from(String(a));
  const second = Buffer.from(String(b));

  if (first.length !== second.length) return false;

  return crypto.timingSafeEqual(first, second);
}

function requireApiKey(req, res, next) {
  const key = req.headers["x-api-key"];

  if (!key || !safeEqual(key, API_KEY)) {
    return res.status(401).json({
      success: false,
      error: "Invalid API key"
    });
  }

  next();
}

function requireAdmin(req, res, next) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Basic ")) {
    res.set("WWW-Authenticate", 'Basic realm="Image Storage Admin"');
    return res.status(401).send("Authentication required");
  }

  let decoded;

  try {
    decoded = Buffer.from(header.slice(6), "base64").toString("utf8");
  } catch {
    res.set("WWW-Authenticate", 'Basic realm="Image Storage Admin"');
    return res.status(401).send("Invalid credentials");
  }

  const separator = decoded.indexOf(":");

  if (separator < 0) {
    return res.status(401).send("Invalid credentials");
  }

  const username = decoded.slice(0, separator);
  const password = decoded.slice(separator + 1);

  if (
    !safeEqual(username, ADMIN_USER) ||
    !safeEqual(password, ADMIN_PASSWORD)
  ) {
    res.set("WWW-Authenticate", 'Basic realm="Image Storage Admin"');
    return res.status(401).send("Invalid username or password");
  }

  next();
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, STORAGE_DIR);
  },

  filename: (req, file, cb) => {
    const extension = path.extname(file.originalname).toLowerCase();
    const randomName = crypto.randomBytes(16).toString("hex");

    cb(null, `${Date.now()}-${randomName}${extension}`);
  }
});

const allowedTypes = [
  "image/jpeg",
  "image/png",
  "image/webp",
  "image/gif"
];

const upload = multer({
  storage,

  limits: {
    fileSize: MAX_FILE_MB * 1024 * 1024,
    files: 1
  },

  fileFilter: (req, file, cb) => {
    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error("Only JPG, PNG, WEBP and GIF images are allowed."));
    }

    cb(null, true);
  }
});

// Home
app.get("/", (req, res) => {
  res.send("Image URL Storage Server is running.");
});

// Health check
app.get("/health", (req, res) => {
  res.json({
    success: true,
    status: "online"
  });
});

// Public upload API - API KEY required
app.post(
  "/api/upload",
  uploadLimiter,
  requireApiKey,
  upload.single("image"),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: "No image file received"
      });
    }

    res.json({
      success: true,
      message: "Image uploaded successfully",
      filename: req.file.filename,
      url: `${BASE_URL}/uploads/${encodeURIComponent(req.file.filename)}`,
      size: req.file.size
    });
  }
);

// Public image list API - API KEY required
app.get("/api/images", requireApiKey, (req, res) => {
  try {
    const images = fs.readdirSync(STORAGE_DIR)
      .filter(name => fs.statSync(path.join(STORAGE_DIR, name)).isFile())
      .map(name => {
        const fullPath = path.join(STORAGE_DIR, name);
        const stats = fs.statSync(fullPath);

        return {
          filename: name,
          url: `${BASE_URL}/uploads/${encodeURIComponent(name)}`,
          size: stats.size,
          uploadedAt: stats.mtime
        };
      })
      .sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));

    res.json({
      success: true,
      count: images.length,
      images
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      error: "Could not read image directory"
    });
  }
});

// Public delete API - API KEY required
app.delete("/api/images/:filename", requireApiKey, (req, res) => {
  const filename = path.basename(req.params.filename);
  const filePath = path.join(STORAGE_DIR, filename);

  if (!fs.existsSync(filePath)) {
    return res.status(404).json({
      success: false,
      error: "Image not found"
    });
  }

  try {
    fs.unlinkSync(filePath);

    res.json({
      success: true,
      message: "Image deleted successfully"
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      error: "Could not delete image"
    });
  }
});

// Admin upload API - uses admin authentication, not API KEY
app.post(
  "/admin/api/upload",
  adminLimiter,
  requireAdmin,
  upload.single("image"),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: "No image file received"
      });
    }

    res.json({
      success: true,
      message: "Image uploaded successfully",
      filename: req.file.filename,
      url: `${BASE_URL}/uploads/${encodeURIComponent(req.file.filename)}`,
      size: req.file.size
    });
  }
);

// Admin image list API
app.get("/admin/api/images", adminLimiter, requireAdmin, (req, res) => {
  try {
    const images = fs.readdirSync(STORAGE_DIR)
      .filter(name => fs.statSync(path.join(STORAGE_DIR, name)).isFile())
      .map(name => {
        const fullPath = path.join(STORAGE_DIR, name);
        const stats = fs.statSync(fullPath);

        return {
          filename: name,
          url: `${BASE_URL}/uploads/${encodeURIComponent(name)}`,
          size: stats.size,
          uploadedAt: stats.mtime
        };
      })
      .sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));

    res.json({
      success: true,
      count: images.length,
      images
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      error: "Could not load images"
    });
  }
});

// Admin delete API
app.delete(
  "/admin/api/images/:filename",
  adminLimiter,
  requireAdmin,
  (req, res) => {
    const filename = path.basename(req.params.filename);
    const filePath = path.join(STORAGE_DIR, filename);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({
        success: false,
        error: "Image not found"
      });
    }

    try {
      fs.unlinkSync(filePath);

      res.json({
        success: true,
        message: "Image deleted successfully"
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        error: "Could not delete image"
      });
    }
  }
);

// Admin panel
app.get("/admin", adminLimiter, requireAdmin, (req, res) => {
  res.set("Cache-Control", "no-store");

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Image Storage Admin</title>

<style>
*{box-sizing:border-box}

body{
  margin:0;
  padding:20px;
  background:#101827;
  color:#fff;
  font-family:Arial,sans-serif
}

.container{
  max-width:750px;
  margin:30px auto;
  background:#1c293b;
  padding:24px;
  border-radius:14px
}

h2{margin-top:0}

input,button{
  width:100%;
  padding:13px;
  margin-top:12px;
  border-radius:8px;
  border:0;
  font-size:15px
}

input{
  background:#fff;
  color:#111
}

button{
  background:#16a36a;
  color:white;
  font-weight:bold;
  cursor:pointer
}

button:disabled{opacity:.6}

.item{
  background:#27364a;
  padding:12px;
  margin-top:12px;
  border-radius:9px;
  overflow-wrap:anywhere
}

.item img{
  max-width:100%;
  max-height:180px;
  display:block;
  margin-bottom:10px;
  border-radius:7px
}

.delete{background:#d94343}

#status{
  margin-top:15px;
  overflow-wrap:anywhere
}

a{color:#8bc7ff}
</style>
</head>

<body>
<div class="container">

<h2>Image Storage Admin</h2>

<form id="uploadForm">
  <input
    type="file"
    id="imageFile"
    accept="image/jpeg,image/png,image/webp,image/gif"
    required
  >

  <button type="submit" id="uploadButton">
    Upload Image
  </button>
</form>

<div id="status"></div>

<hr style="margin:25px 0;border-color:#45546a">

<h3>Uploaded Images</h3>
<div id="imageList">Loading...</div>

</div>

<script>
const form = document.getElementById("uploadForm");
const fileInput = document.getElementById("imageFile");
const uploadButton = document.getElementById("uploadButton");
const statusBox = document.getElementById("status");
const imageList = document.getElementById("imageList");

// Upload image
form.addEventListener("submit", async function(event) {
  event.preventDefault();

  const selectedFile = fileInput.files[0];

  if (!selectedFile) {
    statusBox.textContent = "Please select an image first.";
    return;
  }

  const data = new FormData();
  data.append("image", selectedFile, selectedFile.name);

  uploadButton.disabled = true;
  statusBox.textContent = "Uploading...";

  try {
    const response = await fetch("/admin/api/upload", {
      method: "POST",
      body: data,
      credentials: "same-origin"
    });

    const result = await response.json();

    if (!response.ok || !result.success) {
      throw new Error(result.error || "Upload failed");
    }

    statusBox.textContent = "";

    const message = document.createElement("p");
    message.textContent = "Upload successful!";
    statusBox.appendChild(message);

    const link = document.createElement("a");
    link.href = result.url;
    link.textContent = result.url;
    link.target = "_blank";
    link.rel = "noopener";
    statusBox.appendChild(link);

    fileInput.value = "";
    await loadImages();

  } catch (error) {
    statusBox.textContent = "Error: " + error.message;
  } finally {
    uploadButton.disabled = false;
  }
});

// Load images
async function loadImages() {
  imageList.textContent = "Loading...";

  try {
    const response = await fetch("/admin/api/images", {
      credentials: "same-origin"
    });

    const result = await response.json();

    if (!response.ok || !result.success) {
      throw new Error(result.error || "Could not load images");
    }

    imageList.innerHTML = "";

    if (!result.images || result.images.length === 0) {
      imageList.textContent = "No images uploaded yet.";
      return;
    }

    result.images.forEach(item => {
      const box = document.createElement("div");
      box.className = "item";

      const img = document.createElement("img");
      img.src = item.url;
      img.alt = item.filename;

      const name = document.createElement("p");
      name.textContent = item.filename;

      const link = document.createElement("a");
      link.href = item.url;
      link.target = "_blank";
      link.rel = "noopener";
      link.textContent = "Open Image";

      const del = document.createElement("button");
      del.className = "delete";
      del.textContent = "Delete";

      del.addEventListener("click", async () => {
        if (!confirm("Delete this image?")) return;

        try {
          const response = await fetch(
            "/admin/api/images/" + encodeURIComponent(item.filename),
            {
              method: "DELETE",
              credentials: "same-origin"
            }
          );

          const result = await response.json();

          if (!response.ok || !result.success) {
            throw new Error(result.error || "Delete failed");
          }

          await loadImages();

        } catch (error) {
          alert(error.message);
        }
      });

      box.appendChild(img);
      box.appendChild(name);
      box.appendChild(link);
      box.appendChild(del);

      imageList.appendChild(box);
    });

  } catch (error) {
    imageList.textContent = "Could not load images: " + error.message;
  }
}

loadImages();
</script>

</body>
</html>`);
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: "Route not found"
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error("Request error:", err);

  if (err instanceof multer.MulterError) {
    return res.status(400).json({
      success: false,
      error: err.code === "LIMIT_FILE_SIZE"
        ? `File is too large. Maximum size is ${MAX_FILE_MB} MB.`
        : err.message
    });
  }

  res.status(400).json({
    success: false,
    error: err.message || "Something went wrong"
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Image Storage Server running on port ${PORT}`);
});
        
