const express = require("express");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const multer = require("multer");
const AdmZip = require("adm-zip");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const https = require("https");

const app = express();

const PORT = process.env.PORT || 10000;

if (!process.env.DATABASE_URL) {
  console.error("ERROR: DATABASE_URL is missing.");
  process.exit(1);
}

if (!process.env.GOOGLE_CLIENT_ID) {
  console.error("ERROR: GOOGLE_CLIENT_ID is missing.");
  process.exit(1);
}

if (!process.env.GOOGLE_CLIENT_SECRET) {
  console.error("ERROR: GOOGLE_CLIENT_SECRET is missing.");
  process.exit(1);
}

if (!process.env.SESSION_SECRET) {
  console.error("ERROR: SESSION_SECRET is missing.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

app.set("trust proxy", 1);

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));

app.use(
  session({
    store: new pgSession({
      pool,
      tableName: "user_sessions",
      createTableIfMissing: true
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000
    }
  })
);

app.use(express.static(path.join(__dirname, "public")));

// ----------------------------------------------------
// Database
// ----------------------------------------------------

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      google_id TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      name TEXT,
      picture TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS websites (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      type TEXT NOT NULL CHECK (type IN ('html', 'zip')),
      html_content TEXT,
      zip_data BYTEA,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  console.log("Database initialized.");
}

// ----------------------------------------------------
// Google OAuth helpers
// ----------------------------------------------------

function googleRequest(options, postData = null) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let data = "";

      res.on("data", (chunk) => {
        data += chunk;
      });

      res.on("end", () => {
        try {
          const parsed = JSON.parse(data);

          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(parsed);
          } else {
            reject(
              new Error(
                parsed.error_description ||
                parsed.error ||
                `Google API error: ${res.statusCode}`
              )
            );
          }
        } catch (err) {
          reject(err);
        }
      });
    });

    req.on("error", reject);

    if (postData) {
      req.write(postData);
    }

    req.end();
  });
}

function base64UrlDecode(str) {
  return Buffer.from(
    str.replace(/-/g, "+").replace(/_/g, "/"),
    "base64"
  ).toString("utf8");
}

// ----------------------------------------------------
// Auth middleware
// ----------------------------------------------------

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      error: "You must login first."
    });
  }

  next();
}

// ----------------------------------------------------
// Google Login
// ----------------------------------------------------

app.get("/api/auth/google", (req, res) => {
  const state = crypto.randomBytes(32).toString("hex");

  req.session.oauthState = state;

  const params = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: getRedirectUri(req),
    response_type: "code",
    scope: "openid email profile",
    state,
    access_type: "online",
    prompt: "select_account"
  });

  const googleUrl =
    "https://accounts.google.com/o/oauth2/v2/auth?" +
    params.toString();

  res.redirect(googleUrl);
});

app.get("/api/auth/google/callback", async (req, res) => {
  try {
    const { code, state } = req.query;

    if (!code) {
      return res.status(400).send("Google authorization code missing.");
    }

    if (!state || state !== req.session.oauthState) {
      return res.status(400).send("Invalid OAuth state.");
    }

    delete req.session.oauthState;

    const redirectUri = getRedirectUri(req);

    // Exchange authorization code for access token
    const tokenParams = new URLSearchParams({
      code,
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      redirect_uri: redirectUri,
      grant_type: "authorization_code"
    });

    const tokenResponse = await googleRequest(
      {
        hostname: "oauth2.googleapis.com",
        path: "/token",
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Content-Length": Buffer.byteLength(tokenParams.toString())
        }
      },
      tokenParams.toString()
    );

    if (!tokenResponse.access_token) {
      throw new Error("Google access token not received.");
    }

    // Get Google user information
    const userInfo = await googleRequest({
      hostname: "openidconnect.googleapis.com",
      path: "/v1/userinfo",
      method: "GET",
      headers: {
        Authorization: `Bearer ${tokenResponse.access_token}`
      }
    });

    if (!userInfo.sub || !userInfo.email) {
      throw new Error("Google account information incomplete.");
    }

    if (userInfo.email_verified !== true) {
      throw new Error("Google email is not verified.");
    }

    // Create/update user
    const result = await pool.query(
      `
      INSERT INTO users
        (google_id, email, name, picture)
      VALUES
        ($1, $2, $3, $4)
      ON CONFLICT (google_id)
      DO UPDATE SET
        email = EXCLUDED.email,
        name = EXCLUDED.name,
        picture = EXCLUDED.picture
      RETURNING id, email, name, picture
      `,
      [
        userInfo.sub,
        userInfo.email.toLowerCase(),
        userInfo.name || "",
        userInfo.picture || ""
      ]
    );

    const user = result.rows[0];

    req.session.userId = user.id;
    req.session.userEmail = user.email;

    req.session.save((err) => {
      if (err) {
        console.error(err);
        return res.status(500).send("Could not create session.");
      }

      res.redirect("/dashboard.html");
    });

  } catch (error) {
    console.error("Google login error:", error);
    res.status(500).send(
      "Google login failed. Please try again."
    );
  }
});

function getRedirectUri(req) {
  if (process.env.GOOGLE_REDIRECT_URI) {
    return process.env.GOOGLE_REDIRECT_URI;
  }

  const protocol =
    process.env.NODE_ENV === "production"
      ? "https"
      : req.protocol;

  return `${protocol}://${req.get("host")}/api/auth/google/callback`;
}

// ----------------------------------------------------
// Logout
// ----------------------------------------------------

app.post("/api/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({
      success: true
    });
  });
});

// ----------------------------------------------------
// Current user
// ----------------------------------------------------

app.get("/api/me", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT id, email, name, picture, created_at
      FROM users
      WHERE id = $1
      `,
      [req.session.userId]
    );

    if (result.rows.length === 0) {
      req.session.destroy(() => {});
      return res.status(401).json({
        error: "User not found."
      });
    }

    res.json(result.rows[0]);

  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: "Server error."
    });
  }
});

// ----------------------------------------------------
// Generate unique slug
// ----------------------------------------------------

async function generateSlug(name) {
  let base = String(name)
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .substring(0, 35);

  if (!base) {
    base = "website";
  }

  let slug = base;

  for (let i = 0; i < 20; i++) {
    const result = await pool.query(
      "SELECT id FROM websites WHERE slug = $1",
      [slug]
    );

    if (result.rows.length === 0) {
      return slug;
    }

    slug =
      base +
      "-" +
      crypto.randomBytes(3).toString("hex");
  }

  throw new Error("Could not generate unique website URL.");
}

// ----------------------------------------------------
// List user's websites
// ----------------------------------------------------

app.get("/api/websites", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        id,
        name,
        slug,
        type,
        created_at,
        updated_at
      FROM websites
      WHERE user_id = $1
      ORDER BY created_at DESC
      `,
      [req.session.userId]
    );

    res.json(result.rows);

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Could not load websites."
    });
  }
});

// ----------------------------------------------------
// Create HTML website
// ----------------------------------------------------

app.post("/api/websites/html", requireLogin, async (req, res) => {
  try {
    const { name, html } = req.body;

    if (!name || !html) {
      return res.status(400).json({
        error: "Website name and HTML are required."
      });
    }

    if (Buffer.byteLength(html, "utf8") > 1024 * 1024 * 2) {
      return res.status(400).json({
        error: "HTML file is too large. Maximum 2MB."
      });
    }

    const slug = await generateSlug(name);

    const result = await pool.query(
      `
      INSERT INTO websites
        (user_id, name, slug, type, html_content)
      VALUES
        ($1, $2, $3, 'html', $4)
      RETURNING id, name, slug, type
      `,
      [
        req.session.userId,
        name.trim(),
        slug,
        html
      ]
    );

    res.json({
      success: true,
      website: result.rows[0],
      url: `/site/${slug}`
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Could not create website."
    });
  }
});

// ----------------------------------------------------
// ZIP upload
// ----------------------------------------------------

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024
  },
  fileFilter: (req, file, cb) => {
    const allowed = [
      "application/zip",
      "application/x-zip-compressed",
      "application/octet-stream"
    ];

    if (
      allowed.includes(file.mimetype) ||
      file.originalname.toLowerCase().endsWith(".zip")
    ) {
      cb(null, true);
    } else {
      cb(new Error("Only ZIP files are allowed."));
    }
  }
});

app.post(
  "/api/websites/zip",
  requireLogin,
  upload.single("website"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          error: "ZIP file is required."
        });
      }

      const { name } = req.body;

      if (!name) {
        return res.status(400).json({
          error: "Website name is required."
        });
      }

      // Validate ZIP
      const zip = new AdmZip(req.file.buffer);
      const entries = zip.getEntries();

      if (entries.length === 0) {
        return res.status(400).json({
          error: "ZIP file is empty."
        });
      }

      if (entries.length > 1000) {
        return res.status(400).json({
          error: "ZIP contains too many files."
        });
      }

      let totalUncompressed = 0;
      let hasIndex = false;

      for (const entry of entries) {
        const entryName = entry.entryName.replace(/\\/g, "/");

        // Prevent path traversal
        if (
          entryName.startsWith("/") ||
          entryName.includes("../") ||
          entryName.includes("..\\")
        ) {
          return res.status(400).json({
            error: "Unsafe ZIP file path detected."
          });
        }

        if (!entry.isDirectory) {
          totalUncompressed += entry.header.size;

          if (
            entryName === "index.html" ||
            entryName === "index.htm"
          ) {
            hasIndex = true;
          }
        }
      }

      // Protect against huge extracted ZIPs
      if (totalUncompressed > 50 * 1024 * 1024) {
        return res.status(400).json({
          error: "ZIP extracted size cannot exceed 50MB."
        });
      }

      if (!hasIndex) {
        return res.status(400).json({
          error: "ZIP must contain index.html."
        });
      }

      const slug = await generateSlug(name);

      const result = await pool.query(
        `
        INSERT INTO websites
          (user_id, name, slug, type, zip_data)
        VALUES
          ($1, $2, $3, 'zip', $4)
        RETURNING id, name, slug, type
        `,
        [
          req.session.userId,
          name.trim(),
          slug,
          req.file.buffer
        ]
      );

      res.json({
        success: true,
        website: result.rows[0],
        url: `/site/${slug}`
      });

    } catch (error) {
      console.error(error);

      res.status(400).json({
        error:
          error.message ||
          "Could not process ZIP file."
      });
    }
  }
);

// ----------------------------------------------------
// Delete website
// ----------------------------------------------------

app.delete(
  "/api/websites/:id",
  requireLogin,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        DELETE FROM websites
        WHERE id = $1
        AND user_id = $2
        RETURNING id
        `,
        [
          req.params.id,
          req.session.userId
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: "Website not found or not owned by you."
        });
      }

      res.json({
        success: true
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Could not delete website."
      });
    }
  }
);

// ----------------------------------------------------
// Get website details for owner
// ----------------------------------------------------

app.get(
  "/api/websites/:id",
  requireLogin,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          id,
          name,
          slug,
          type,
          html_content,
          created_at,
          updated_at
        FROM websites
        WHERE id = $1
        AND user_id = $2
        `,
        [
          req.params.id,
          req.session.userId
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: "Website not found."
        });
      }

      res.json(result.rows[0]);

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Could not load website."
      });
    }
  }
);

// ----------------------------------------------------
// Update HTML website
// ----------------------------------------------------

app.put(
  "/api/websites/:id/html",
  requireLogin,
  async (req, res) => {
    try {
      const { name, html } = req.body;

      if (!name || !html) {
        return res.status(400).json({
          error: "Website name and HTML are required."
        });
      }

      if (Buffer.byteLength(html, "utf8") > 1024 * 1024 * 2) {
        return res.status(400).json({
          error: "HTML cannot exceed 2MB."
        });
      }

      const result = await pool.query(
        `
        UPDATE websites
        SET
          name = $1,
          html_content = $2,
          updated_at = NOW()
        WHERE id = $3
        AND user_id = $4
        AND type = 'html'
        RETURNING id, name, slug, type
        `,
        [
          name.trim(),
          html,
          req.params.id,
          req.session.userId
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: "Website not found."
        });
      }

      res.json({
        success: true,
        website: result.rows[0]
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Could not update website."
      });
    }
  }
);

// ----------------------------------------------------
// Public website
// ----------------------------------------------------

app.get("/site/:slug", async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT *
      FROM websites
      WHERE slug = $1
      `,
      [req.params.slug]
    );

    if (result.rows.length === 0) {
      return res.status(404).send("Website not found.");
    }

    const site = result.rows[0];

    if (site.type === "html") {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res.send(site.html_content || "");
    }

    if (site.type === "zip") {
      return serveZipWebsite(site, req, res);
    }

    res.status(500).send("Unknown website type.");

  } catch (error) {
    console.error(error);

    res.status(500).send(
      "Could not load website."
    );
  }
});

// ----------------------------------------------------
// ZIP website file serving
// ----------------------------------------------------

function serveZipWebsite(site, req, res) {
  try {
    const zip = new AdmZip(site.zip_data);

    let requestedPath = req.path;

    // req.path for /site/slug is "/"
    // For nested files Express route is handled separately below.
    if (
      !requestedPath ||
      requestedPath === "/" ||
      requestedPath === ""
    ) {
      requestedPath = "/index.html";
    }

    requestedPath = decodeURIComponent(requestedPath)
      .replace(/^\/+/, "")
      .replace(/\\/g, "/");

    if (
      requestedPath.includes("../") ||
      requestedPath.includes("..\\") ||
      requestedPath.startsWith("..")
    ) {
      return res.status(400).send("Invalid path.");
    }

    const entry = zip.getEntry(requestedPath);

    if (!entry || entry.isDirectory) {
      return res.status(404).send("File not found.");
    }

    const data = entry.getData();

    const mime = getMimeType(requestedPath);

    res.setHeader("Content-Type", mime);
    res.setHeader("Cache-Control", "public, max-age=300");

    return res.send(data);

  } catch (error) {
    console.error(error);

    return res.status(500).send(
      "Could not load website file."
    );
  }
}

// ----------------------------------------------------
// ZIP nested file route
// ----------------------------------------------------

app.get("/site/:slug/*splat", async (req, res) => {
  try {
    const slug = req.params.slug;

    const result = await pool.query(
      `
      SELECT *
      FROM websites
      WHERE slug = $1
      `,
      [slug]
    );

    if (result.rows.length === 0) {
      return res.status(404).send("Website not found.");
    }

    const site = result.rows[0];

    if (site.type !== "zip") {
      return res.status(404).send("File not found.");
    }

    let splat = req.params.splat;

    if (Array.isArray(splat)) {
      splat = splat.join("/");
    }

    splat = "/" + (splat || "");

    // Re-use ZIP serving logic
    req.path = splat;

    return serveZipWebsite(site, req, res);

  } catch (error) {
    console.error(error);

    res.status(500).send(
      "Could not load website file."
    );
  }
});

// ----------------------------------------------------
// MIME types
// ----------------------------------------------------

function getMimeType(filename) {
  const ext = path.extname(filename).toLowerCase();

  const mimeTypes = {
    ".html": "text/html; charset=utf-8",
    ".htm": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".mjs": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".xml": "application/xml; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".ico": "image/x-icon",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".ttf": "font/ttf",
    ".mp3": "audio/mpeg",
    ".mp4": "video/mp4",
    ".webm": "video/webm"
  };

  return mimeTypes[ext] || "application/octet-stream";
}

// ----------------------------------------------------
// Error handler
// ----------------------------------------------------

app.use((err, req, res, next) => {
  console.error(err);

  if (err instanceof multer.MulterError) {
    return res.status(400).json({
      error: `Upload error: ${err.message}`
    });
  }

  res.status(500).json({
    error: err.message || "Internal server error."
  });
});

// ----------------------------------------------------
// Start server
// ----------------------------------------------------

initDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(
        `TM Web Hosting running on port ${PORT}`
      );
    });
  })
  .catch((error) => {
    console.error(
      "Database initialization failed:",
      error
    );

    process.exit(1);
  });
