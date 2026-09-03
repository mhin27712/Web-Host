const express = require("express");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const multer = require("multer");
const fs = require("fs-extra");
const path = require("path");
const AdmZip = require("adm-zip");
const crypto = require("crypto");
const http = require("http");
const https = require("https");

const app = express();

const PORT = process.env.PORT || 3000;

const DATA_DIR =
  process.env.DATA_DIR || path.join(__dirname, "data");

const sitesDir = path.join(DATA_DIR, "sites");
const tempDir = path.join(DATA_DIR, "temp");

fs.ensureDirSync(sitesDir);
fs.ensureDirSync(tempDir);

// ======================================================
// REQUIRED ENVIRONMENT VARIABLES
// ======================================================

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

// ======================================================
// DATABASE
// ======================================================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false
});

app.set("trust proxy", 1);

// ======================================================
// EXPRESS
// ======================================================

app.use(
  express.urlencoded({
    extended: true,
    limit: "50mb"
  })
);

app.use(
  express.json({
    limit: "50mb"
  })
);

// ======================================================
// SESSION
// ======================================================

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

// ======================================================
// DATABASE INITIALIZATION
// ======================================================

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
      user_id INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      name TEXT NOT NULL,

      slug TEXT UNIQUE NOT NULL,

      type TEXT NOT NULL
        CHECK (type IN ('html', 'zip')),

      html_content TEXT,

      zip_data BYTEA,

      folder_name TEXT,

      title TEXT,

      description TEXT,

      keywords TEXT,

      author TEXT,

      previous_slugs TEXT[] DEFAULT '{}',

      created_at TIMESTAMPTZ DEFAULT NOW(),

      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // ----------------------------------------------------
  // Migration support for older websites table
  // ----------------------------------------------------

  const columns = [
    ["folder_name", "TEXT"],
    ["title", "TEXT"],
    ["description", "TEXT"],
    ["keywords", "TEXT"],
    ["author", "TEXT"],
    ["previous_slugs", "TEXT[] DEFAULT '{}'"]
  ];

  for (const [column, definition] of columns) {
    try {
      await pool.query(
        `ALTER TABLE websites ADD COLUMN IF NOT EXISTS ${column} ${definition}`
      );
    } catch (error) {
      console.error(
        `Could not add column ${column}:`,
        error.message
      );
    }
  }

  await pool.query(`
    CREATE INDEX IF NOT EXISTS websites_user_id_idx
    ON websites(user_id);
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS websites_slug_idx
    ON websites(slug);
  `);

  console.log("Database initialized.");
}

// ======================================================
// GOOGLE OAUTH
// ======================================================

function googleRequest(options, postData = null) {
  return new Promise((resolve, reject) => {
    const request = https.request(
      options,
      (response) => {
        let data = "";

        response.on("data", (chunk) => {
          data += chunk;
        });

        response.on("end", () => {
          try {
            const parsed = JSON.parse(data);

            if (
              response.statusCode >= 200 &&
              response.statusCode < 300
            ) {
              resolve(parsed);
            } else {
              reject(
                new Error(
                  parsed.error_description ||
                    parsed.error ||
                    `Google API error: ${response.statusCode}`
                )
              );
            }
          } catch (error) {
            reject(error);
          }
        });
      }
    );

    request.on("error", reject);

    if (postData) {
      request.write(postData);
    }

    request.end();
  });
}

function getRedirectUri(req) {
  if (process.env.GOOGLE_REDIRECT_URI) {
    return process.env.GOOGLE_REDIRECT_URI;
  }

  const protocol =
    process.env.NODE_ENV === "production"
      ? "https"
      : req.protocol;

  return `${protocol}://${req.get(
    "host"
  )}/api/auth/google/callback`;
}

// ======================================================
// AUTH HELPERS
// ======================================================

function isLoggedIn(req) {
  return Boolean(req.session && req.session.userId);
}

function requireLogin(req, res, next) {
  if (!isLoggedIn(req)) {
    if (
      req.path.startsWith("/api/")
    ) {
      return res.status(401).json({
        error: "You must login first."
      });
    }

    return res.redirect("/login");
  }

  next();
}

// ======================================================
// LOGIN PAGE
// ======================================================

app.get("/login", (req, res) => {
  if (isLoggedIn(req)) {
    return res.redirect("/");
  }

  res.send(`
<!DOCTYPE html>
<html lang="bn">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="theme-color" content="#020617">
<title>Login - Personal Website Hosting</title>

<style>
:root{
  --c1:#00d9ff;
  --c2:#0066ff;
  --c3:#8b5cf6;
  --bg1:#020617;
  --bg2:#07132f;
  --text:#f8fafc;
  --muted:#94a3b8;
}

*{
  box-sizing:border-box;
}

body{
  margin:0;
  min-height:100vh;
  display:flex;
  justify-content:center;
  align-items:center;
  font-family:Arial,"Segoe UI",sans-serif;
  color:var(--text);

  background:
    radial-gradient(
      circle at 15% 10%,
      var(--c3),
      transparent 30%
    ),
    radial-gradient(
      circle at 85% 80%,
      var(--c2),
      transparent 30%
    ),
    linear-gradient(
      135deg,
      var(--bg1),
      var(--bg2)
    );

  background-size:200% 200%;
  animation:liveBackgroundShift 12s ease infinite;
}

@keyframes liveBackgroundShift{
  0%{
    background-position:0% 50%;
  }

  50%{
    background-position:100% 50%;
  }

  100%{
    background-position:0% 50%;
  }
}

.login-card{
  width:min(450px,92%);
  position:relative;
  background:rgba(8,15,35,.95);
  border-radius:22px;
  padding:35px 25px;
  text-align:center;
  box-shadow:
    0 20px 60px rgba(0,0,0,.5);
}

.login-card::before{
  content:"";
  position:absolute;
  inset:-2px;
  border-radius:24px;

  background:
    linear-gradient(
      90deg,
      #00d9ff,
      #0066ff,
      #8b5cf6,
      #ff007f,
      #00d9ff
    );

  background-size:400% 100%;
  animation:rgbMove 6s linear infinite;

  z-index:-2;
  filter:blur(5px);
}

.login-card::after{
  content:"";
  position:absolute;
  inset:0;
  border-radius:22px;
  background:rgba(8,15,35,.98);
  z-index:-1;
}

@keyframes rgbMove{
  0%{
    background-position:0% 50%;
  }

  100%{
    background-position:400% 50%;
  }
}

.logo{
  font-size:28px;
  font-weight:900;
  margin-bottom:8px;

  background:
    linear-gradient(
      90deg,
      var(--c1),
      var(--c2),
      var(--c3),
      #ff007f
    );

  -webkit-background-clip:text;
  background-clip:text;
  color:transparent;

  background-size:300% auto;
  animation:titleGradient 5s linear infinite;
}

@keyframes titleGradient{
  0%{
    background-position:0% center;
  }

  100%{
    background-position:300% center;
  }
}

.subtitle{
  color:var(--muted);
  font-size:14px;
  margin-bottom:28px;
}

.google-btn{
  display:block;
  width:100%;
  padding:15px;
  border-radius:12px;
  text-decoration:none;
  color:white;
  font-weight:900;
  font-size:16px;

  background:
    linear-gradient(
      90deg,
      #0066ff,
      #8b5cf6,
      #ff007f,
      #0066ff
    );

  background-size:300% auto;
  animation:buttonGradient 4s linear infinite;

  box-shadow:
    0 0 20px rgba(0,217,255,.35);

  transition:.2s;
}

.google-btn:hover{
  transform:translateY(-2px);
  box-shadow:
    0 0 30px rgba(139,92,246,.55);
}

@keyframes buttonGradient{
  to{
    background-position:300% center;
  }
}

.small{
  color:#64748b;
  font-size:12px;
  margin-top:20px;
}
</style>
</head>

<body>

<div class="login-card">

  <div class="logo">
    Personal Website Hosting
  </div>

  <div class="subtitle">
    Developed BY TâMïM Khan
  </div>

  <p style="color:#cbd5e1;margin-bottom:25px;">
    আপনার website hosting dashboard ব্যবহার করতে
    Google account দিয়ে login করুন।
  </p>

  <a
    class="google-btn"
    href="/api/auth/google"
  >
    🔐 Continue with Google
  </a>

  <div class="small">
    Secure Google OAuth Login
  </div>

</div>

</body>
</html>
`);
});

// ======================================================
// GOOGLE LOGIN
// ======================================================

app.get("/api/auth/google", (req, res) => {
  const state =
    crypto.randomBytes(32).toString("hex");

  req.session.oauthState = state;

  const params = new URLSearchParams({
    client_id:
      process.env.GOOGLE_CLIENT_ID,

    redirect_uri:
      getRedirectUri(req),

    response_type: "code",

    scope:
      "openid email profile",

    state,

    access_type: "online",

    prompt: "select_account"
  });

  const googleUrl =
    "https://accounts.google.com/o/oauth2/v2/auth?" +
    params.toString();

  res.redirect(googleUrl);
});

// ======================================================
// GOOGLE CALLBACK
// ======================================================

app.get(
  "/api/auth/google/callback",
  async (req, res) => {
    try {
      const { code, state } = req.query;

      if (!code) {
        return res
          .status(400)
          .send(
            "Google authorization code missing."
          );
      }

      if (
        !state ||
        state !== req.session.oauthState
      ) {
        return res
          .status(400)
          .send(
            "Invalid OAuth state."
          );
      }

      delete req.session.oauthState;

      const redirectUri =
        getRedirectUri(req);

      // --------------------------------------------------
      // Exchange code
      // --------------------------------------------------

      const tokenParams =
        new URLSearchParams({
          code,

          client_id:
            process.env.GOOGLE_CLIENT_ID,

          client_secret:
            process.env.GOOGLE_CLIENT_SECRET,

          redirect_uri:
            redirectUri,

          grant_type:
            "authorization_code"
        });

      const tokenResponse =
        await googleRequest(
          {
            hostname:
              "oauth2.googleapis.com",

            path:
              "/token",

            method:
              "POST",

            headers:{
              "Content-Type":
                "application/x-www-form-urlencoded",

              "Content-Length":
                Buffer.byteLength(
                  tokenParams.toString()
                )
            }
          },

          tokenParams.toString()
        );

      if (
        !tokenResponse.access_token
      ) {
        throw new Error(
          "Google access token not received."
        );
      }

      // --------------------------------------------------
      // Get user
      // --------------------------------------------------

      const userInfo =
        await googleRequest({
          hostname:
            "openidconnect.googleapis.com",

          path:
            "/v1/userinfo",

          method:
            "GET",

          headers:{
            Authorization:
              `Bearer ${tokenResponse.access_token}`
          }
        });

      if (
        !userInfo.sub ||
        !userInfo.email
      ) {
        throw new Error(
          "Google account information incomplete."
        );
      }

      if (
        userInfo.email_verified !== true
      ) {
        throw new Error(
          "Google email is not verified."
        );
      }

      // --------------------------------------------------
      // Create/update user
      // --------------------------------------------------

      const result =
        await pool.query(
          `
          INSERT INTO users
            (
              google_id,
              email,
              name,
              picture
            )
          VALUES
            ($1,$2,$3,$4)

          ON CONFLICT (google_id)
          DO UPDATE SET
            email = EXCLUDED.email,
            name = EXCLUDED.name,
            picture = EXCLUDED.picture

          RETURNING
            id,
            email,
            name,
            picture
          `,
          [
            userInfo.sub,

            userInfo.email
              .toLowerCase(),

            userInfo.name || "",

            userInfo.picture || ""
          ]
        );

      const user =
        result.rows[0];

      // --------------------------------------------------
      // Regenerate session
      // --------------------------------------------------

      req.session.regenerate(
        (sessionError) => {
          if (sessionError) {
            console.error(
              sessionError
            );

            return res
              .status(500)
              .send(
                "Could not create session."
              );
          }

          req.session.userId =
            user.id;

          req.session.userEmail =
            user.email;

          req.session.userName =
            user.name;

          req.session.save(
            (saveError) => {
              if (saveError) {
                console.error(
                  saveError
                );

                return res
                  .status(500)
                  .send(
                    "Could not save session."
                  );
              }

              res.redirect("/");
            }
          );
        }
      );

    } catch (error) {
      console.error(
        "Google login error:",
        error
      );

      res
        .status(500)
        .send(
          "Google login failed. Please try again."
        );
    }
  }
);

// ======================================================
// LOGOUT
// ======================================================

app.post(
  "/api/auth/logout",
  (req, res) => {
    req.session.destroy(
      (error) => {
        if (error) {
          console.error(error);

          return res.status(500).json({
            error:
              "Could not logout."
          });
        }

        res.clearCookie(
          "connect.sid"
        );

        res.json({
          success:true
        });
      }
    );
  }
);

// ======================================================
// CURRENT USER
// ======================================================

app.get(
  "/api/me",
  requireLogin,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            id,
            email,
            name,
            picture,
            created_at
          FROM users
          WHERE id = $1
          `,
          [req.session.userId]
        );

      if (!result.rows.length) {
        req.session.destroy(
          () => {}
        );

        return res
          .status(401)
          .json({
            error:
              "User not found."
          });
      }

      res.json(
        result.rows[0]
      );

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "Server error."
      });
    }
  }
);

// ======================================================
// HELPERS
// ======================================================

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function escapeAttribute(value) {
  return escapeHtml(value);
}

function sanitizeSiteName(name) {
  return String(name || "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9-_]/g, "")
    .replace(/^-+|-+$/g, "")
    .slice(0, 50);
}

function sanitizeFileName(name) {
  return path
    .basename(name)
    .replace(
      /[<>:"|?*\x00-\x1F]/g,
      "_"
    );
}

function safeJoin(base, target) {
  const resolvedBase =
    path.resolve(base);

  const resolvedTarget =
    path.resolve(base, target);

  if (
    resolvedTarget !== resolvedBase &&
    !resolvedTarget.startsWith(
      resolvedBase + path.sep
    )
  ) {
    throw new Error(
      "Unsafe path detected"
    );
  }

  return resolvedTarget;
}

function getProjectUrl(
  req,
  siteName
) {
  return (
    `${req.protocol}://` +
    `${req.get("host")}` +
    `/site/` +
    `${encodeURIComponent(siteName)}/`
  );
}

// ======================================================
// ZIP SECURITY
// ======================================================

function validateZipBuffer(buffer) {
  const zip =
    new AdmZip(buffer);

  const entries =
    zip.getEntries();

  if (!entries.length) {
    throw new Error(
      "ZIP file is empty."
    );
  }

  if (entries.length > 1000) {
    throw new Error(
      "ZIP contains too many files."
    );
  }

  let totalUncompressed = 0;

  let hasIndex = false;

  for (const entry of entries) {
    const entryName =
      entry.entryName
        .replace(/\\/g, "/");

    // Absolute paths
    if (
      entryName.startsWith("/")
    ) {
      throw new Error(
        "Unsafe ZIP file path detected."
      );
    }

    // Windows drive paths
    if (
      /^[a-zA-Z]:/.test(
        entryName
      )
    ) {
      throw new Error(
        "Unsafe ZIP file path detected."
      );
    }

    // Path traversal
    const parts =
      entryName.split("/");

    if (
      parts.includes("..")
    ) {
      throw new Error(
        "Unsafe ZIP file path detected."
      );
    }

    if (
      entryName.includes("\0")
    ) {
      throw new Error(
        "Invalid ZIP file path."
      );
    }

    if (!entry.isDirectory) {
      totalUncompressed +=
        Number(
          entry.header.size || 0
        );

      const lower =
        entryName.toLowerCase();

      if (
        lower === "index.html" ||
        lower === "index.htm"
      ) {
        hasIndex = true;
      }
    }
  }

  if (
    totalUncompressed >
    50 * 1024 * 1024
  ) {
    throw new Error(
      "ZIP extracted size cannot exceed 50MB."
    );
  }

  if (!hasIndex) {
    throw new Error(
      "ZIP must contain index.html or index.htm."
    );
  }

  return zip;
}

// ======================================================
// HTML FINDER
// ======================================================

function findHtmlFiles(dir) {
  let results = [];

  if (!fs.existsSync(dir)) {
    return results;
  }

  const items =
    fs.readdirSync(
      dir,
      {
        withFileTypes:true
      }
    );

  for (const item of items) {
    const fullPath =
      path.join(
        dir,
        item.name
      );

    if (item.isDirectory()) {
      results =
        results.concat(
          findHtmlFiles(fullPath)
        );
    } else {
      const ext =
        path.extname(
          item.name
        ).toLowerCase();

      if (
        ext === ".html" ||
        ext === ".htm"
      ) {
        results.push(
          fullPath
        );
      }
    }
  }

  return results;
}

function findBestHtml(dir) {
  const htmlFiles =
    findHtmlFiles(dir);

  if (!htmlFiles.length) {
    return null;
  }

  for (
    const name of [
      "index.html",
      "index.htm",
      "home.html",
      "main.html",
      "default.html"
    ]
  ) {
    const found =
      htmlFiles.find(
        file =>
          path
            .basename(file)
            .toLowerCase() ===
          name
      );

    if (found) {
      return found;
    }
  }

  return htmlFiles[0];
}

async function ensureIndexHtml(
  projectDir
) {
  const existing =
    path.join(
      projectDir,
      "index.html"
    );

  if (
    fs.existsSync(existing)
  ) {
    return existing;
  }

  const htmlFile =
    findBestHtml(
      projectDir
    );

  if (!htmlFile) {
    return null;
  }

  await fs.copy(
    htmlFile,
    existing,
    {
      overwrite:false
    }
  );

  return existing;
}

// ======================================================
// FLATTEN SINGLE ZIP FOLDER
// ======================================================

async function flattenSingleFolder(
  projectDir
) {
  if (
    !fs.existsSync(projectDir)
  ) {
    return;
  }

  const items =
    fs.readdirSync(
      projectDir,
      {
        withFileTypes:true
      }
    );

  const visibleItems =
    items.filter(
      item =>
        item.name !==
          "__MACOSX" &&
        item.name !==
          ".DS_Store"
    );

  if (
    visibleItems.length === 1 &&
    visibleItems[0].isDirectory()
  ) {
    const folderName =
      visibleItems[0].name;

    const folderPath =
      safeJoin(
        projectDir,
        folderName
      );

    const htmlFiles =
      findHtmlFiles(
        folderPath
      );

    if (!htmlFiles.length) {
      return;
    }

    const tempFlatten =
      path.join(
        DATA_DIR,
        `flatten-${Date.now()}-${Math.random()
          .toString(36)
          .slice(2)}`
      );

    await fs.ensureDir(
      tempFlatten
    );

    const innerItems =
      await fs.readdir(
        folderPath
      );

    for (
      const item of innerItems
    ) {
      await fs.move(
        safeJoin(
          folderPath,
          item
        ),
        safeJoin(
          tempFlatten,
          item
        ),
        {
          overwrite:true
        }
      );
    }

    await fs.remove(
      folderPath
    );

    const flattenedItems =
      await fs.readdir(
        tempFlatten
      );

    for (
      const item of
        flattenedItems
    ) {
      await fs.move(
        safeJoin(
          tempFlatten,
          item
        ),
        safeJoin(
          projectDir,
          item
        ),
        {
          overwrite:true
        }
      );
    }

    await fs.remove(
      tempFlatten
    );
  }
}

// ======================================================
// USER PROJECT DIRECTORY
// ======================================================

function getUserDir(userId) {
  return safeJoin(
    sitesDir,
    String(userId)
  );
}

function getProjectDir(
  userId,
  folderName
) {
  return safeJoin(
    getUserDir(userId),
    folderName
  );
}

// ======================================================
// UNIQUE FOLDER
// ======================================================

function makeFolderName(
  siteName
) {
  return (
    siteName +
    "-" +
    crypto
      .randomBytes(4)
      .toString("hex")
  );
}

// ======================================================
// UNIQUE SLUG
// ======================================================

async function generateSlug(
  name
) {
  let base =
    String(name)
      .toLowerCase()
      .trim()
      .replace(
        /[^a-z0-9]+/g,
        "-"
      )
      .replace(
        /^-+|-+$/g,
        ""
      )
      .substring(0, 35);

  if (!base) {
    base = "website";
  }

  let slug = base;

  for (
    let i = 0;
    i < 30;
    i++
  ) {
    const result =
      await pool.query(
        `
        SELECT id
        FROM websites
        WHERE slug = $1
        `,
        [slug]
      );

    if (
      result.rows.length === 0
    ) {
      return slug;
    }

    slug =
      base +
      "-" +
      crypto
        .randomBytes(3)
        .toString("hex");
  }

  throw new Error(
    "Could not generate unique website URL."
  );
}

// ======================================================
// PROJECT LOOKUP
// ======================================================

async function findProjectBySlug(
  slug
) {
  const result =
    await pool.query(
      `
      SELECT *
      FROM websites
      WHERE
        slug = $1
        OR $1 = ANY(previous_slugs)
      ORDER BY id DESC
      LIMIT 1
      `,
      [slug]
    );

  if (
    !result.rows.length
  ) {
    return null;
  }

  return result.rows[0];
}

async function findUserProject(
  userId,
  folderName
) {
  const result =
    await pool.query(
      `
      SELECT *
      FROM websites
      WHERE
        user_id = $1
        AND folder_name = $2
      LIMIT 1
      `,
      [
        userId,
        folderName
      ]
    );

  return result.rows[0] || null;
}

// ======================================================
// SEO
// ======================================================

function injectSEO(
  html,
  meta,
  liveUrl
) {
  const title =
    escapeHtml(
      meta.title ||
        "Website"
    );

  const description =
    escapeAttribute(
      meta.description || ""
    );

  const keywords =
    escapeAttribute(
      meta.keywords || ""
    );

  const author =
    escapeAttribute(
      meta.author ||
        "Website Owner"
    );

  const canonical =
    escapeAttribute(
      liveUrl
    );

  const seoTags = `
<meta name="description" content="${description}">
<meta name="keywords" content="${keywords}">
<meta name="author" content="${author}">
<meta name="robots" content="index, follow">
<link rel="canonical" href="${canonical}">
<meta property="og:type" content="website">
<meta property="og:title" content="${title}">
<meta property="og:description" content="${description}">
<meta property="og:url" content="${canonical}">
`;

  let output = html;

  if (
    /<head[^>]*>/i.test(
      output
    )
  ) {
    output =
      output.replace(
        /<head[^>]*>/i,
        match =>
          `${match}${seoTags}<title>${title}</title>`
      );
  } else {
    output = `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
${seoTags}
</head>
<body>
${output}
</body>
</html>
`;
  }

  return output;
}

// ======================================================
// MIME
// ======================================================

function getMimeType(
  filename
) {
  const ext =
    path
      .extname(filename)
      .toLowerCase();

  const mimeTypes = {
    ".html":
      "text/html; charset=utf-8",

    ".htm":
      "text/html; charset=utf-8",

    ".css":
      "text/css; charset=utf-8",

    ".js":
      "application/javascript; charset=utf-8",

    ".mjs":
      "application/javascript; charset=utf-8",

    ".json":
      "application/json; charset=utf-8",

    ".xml":
      "application/xml; charset=utf-8",

    ".txt":
      "text/plain; charset=utf-8",

    ".svg":
      "image/svg+xml",

    ".png":
      "image/png",

    ".jpg":
      "image/jpeg",

    ".jpeg":
      "image/jpeg",

    ".gif":
      "image/gif",

    ".webp":
      "image/webp",

    ".ico":
      "image/x-icon",

    ".woff":
      "font/woff",

    ".woff2":
      "font/woff2",

    ".ttf":
      "font/ttf",

    ".mp3":
      "audio/mpeg",

    ".mp4":
      "video/mp4",

    ".webm":
      "video/webm"
  };

  return (
    mimeTypes[ext] ||
    "application/octet-stream"
  );
}

// ======================================================
// MULTER
// ======================================================

const upload =
  multer({
    dest: tempDir,

    limits:{
      fileSize:
        100 * 1024 * 1024,

      files:50
    },

    fileFilter:
      (req, file, cb) => {
        const name =
          file.originalname
            .toLowerCase();

        const allowed =
          [
            ".html",
            ".htm",
            ".css",
            ".js",
            ".json",
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".svg",
            ".webp",
            ".ico",
            ".txt",
            ".zip",
            ".woff",
            ".woff2",
            ".ttf",
            ".mp3",
            ".mp4",
            ".webm"
          ];

        if (
          allowed.some(
            ext =>
              name.endsWith(ext)
          )
        ) {
          cb(null, true);
        } else {
          cb(
            new Error(
              "Unsupported file type."
            )
          );
        }
      }
  });

// ======================================================
// DASHBOARD
// ======================================================

app.get(
  "/",
  requireLogin,
  async (req, res) => {
    let projectsCount = 0;

    let totalSize = 0;

    try {
      const result =
        await pool.query(
          `
          SELECT
            id,
            folder_name
          FROM websites
          WHERE user_id = $1
          `,
          [req.session.userId]
        );

      projectsCount =
        result.rows.length;

      for (
        const project
          of result.rows
      ) {
        if (
          !project.folder_name
        ) {
          continue;
        }

        const projectPath =
          getProjectDir(
            req.session.userId,
            project.folder_name
          );

        if (
          !fs.existsSync(
            projectPath
          )
        ) {
          continue;
        }

        try {
          const files =
            fs.readdirSync(
              projectPath,
              {
                recursive:true
              }
            );

          for (
            const file
              of files
          ) {
            try {
              const full =
                path.join(
                  projectPath,
                  file
                );

              const stat =
                fs.statSync(
                  full
                );

              if (
                stat.isFile()
              ) {
                totalSize +=
                  stat.size;
              }
            } catch {}
          }
        } catch {}
      }
    } catch (error) {
      console.error(error);
    }

    let userName =
      req.session.userName ||
      req.session.userEmail ||
      "User";

    userName =
      escapeHtml(userName);

    res.send(`
<!DOCTYPE html>
<html lang="bn">
<head>

<meta charset="UTF-8">

<meta
  name="viewport"
  content="width=device-width, initial-scale=1.0"
>

<meta
  name="theme-color"
  content="#020617"
>

<title>
Personal Website Hosting & Developed BY Tâmïm Khan
</title>

<style>

:root {
  --c1:#00d9ff;
  --c2:#0066ff;
  --c3:#8b5cf6;
  --bg1:#020617;
  --bg2:#07132f;
  --text:#f8fafc;
  --muted:#94a3b8;
  --border:rgba(255,255,255,.14);
}

*{
  box-sizing:border-box;
}

html{
  scroll-behavior:smooth;
}

body{
  margin:0;
  min-height:100vh;

  font-family:
    Arial,
    "Segoe UI",
    sans-serif;

  color:var(--text);

  background:
    radial-gradient(
      circle at 15% 10%,
      var(--c3),
      transparent 30%
    ),
    radial-gradient(
      circle at 85% 80%,
      var(--c2),
      transparent 30%
    ),
    linear-gradient(
      135deg,
      var(--bg1),
      var(--bg2)
    );

  background-size:
    200% 200%;

  animation:
    liveBackgroundShift
    12s ease infinite;

  overflow-x:hidden;
}

@keyframes liveBackgroundShift {

  0% {
    background-position:
      0% 50%;
  }

  50% {
    background-position:
      100% 50%;
  }

  100% {
    background-position:
      0% 50%;
  }

}

.container{
  position:relative;
  z-index:2;

  width:min(
    900px,
    94%
  );

  margin:auto;

  padding:
    30px 0 60px;
}

.header{
  text-align:center;
  margin-bottom:20px;
}

.logo{
  min-height:90px;

  display:flex;
  flex-direction:column;

  justify-content:center;
  align-items:center;

  gap:6px;

  font-size:
    clamp(
      18px,
      3.5vw,
      26px
    );

  font-weight:900;

  text-align:center;
}

.logo-line1{

  background:
    linear-gradient(
      90deg,
      var(--c1),
      var(--c2),
      var(--c3)
    );

  -webkit-background-clip:text;
  background-clip:text;

  color:transparent;

  animation:
    titleGradient
    5s linear infinite;

  background-size:
    300% auto;
}

.logo-line2{

  font-size:
    clamp(
      14px,
      2.8vw,
      19px
    );

  background:
    linear-gradient(
      90deg,
      var(--c3),
      #ff007f,
      var(--c1)
    );

  -webkit-background-clip:text;
  background-clip:text;

  color:transparent;

  animation:
    titleGradient
    5s linear infinite;

  background-size:
    300% auto;
}

@keyframes titleGradient{

  0%{
    background-position:
      0% center;
  }

  100%{
    background-position:
      300% center;
  }

}

.subtitle{
  color:var(--muted);
  font-size:14px;
  margin-top:5px;
}

.stats-container{

  display:flex;

  justify-content:space-around;
  align-items:center;

  background:
    rgba(
      8,
      15,
      35,
      .85
    );

  border:
    1px solid
    rgba(
      255,
      255,
      255,
      .12
    );

  border-radius:14px;

  padding:
    12px 15px;

  margin-bottom:20px;

  backdrop-filter:
    blur(10px);

  position:relative;

  box-shadow:
    0 0 15px
      rgba(
        0,
        217,
        255,
        .2
      ),

    inset 0 0 10px
      rgba(
        139,
        92,
        246,
        .15
      );

  animation:
    statsGlow
    4s ease-in-out
    infinite alternate;
}

@keyframes statsGlow {

  0% {

    box-shadow:
      0 0 10px
        rgba(
          0,
          217,
          255,
          .2
        ),

      0 0 20px
        rgba(
          0,
          102,
          255,
          .1
        );
  }

  100% {

    box-shadow:
      0 0 20px
        rgba(
          139,
          92,
          246,
          .4
        ),

      0 0 35px
        rgba(
          0,
          217,
          255,
          .3
        );
  }

}

.stat-item{

  text-align:center;

  flex:1;

  border-right:
    1px solid
    rgba(
      255,
      255,
      255,
      .08
    );
}

.stat-item:last-child{
  border-right:none;
}

.stat-number{
  font-size:18px;
  font-weight:900;
  margin-top:2px;
}

.stat-label{
  font-size:10px;
  color:var(--muted);
  margin-top:1px;
  text-transform:uppercase;
}

.rgb-card{
  position:relative;
}

.rgb-card::before{

  content:"";

  position:absolute;

  inset:-2px;

  border-radius:20px;

  background:
    linear-gradient(
      90deg,
      #00d9ff,
      #0066ff,
      #8b5cf6,
      #ff007f,
      #00d9ff
    );

  background-size:
    400% 100%;

  animation:
    rgbMove
    6s linear infinite;

  z-index:-2;

  filter:
    blur(4px);

  opacity:.85;
}

.rgb-card::after{

  content:"";

  position:absolute;

  inset:1px;

  border-radius:18px;

  background:
    rgba(
      8,
      15,
      35,
      .96
    );

  z-index:-1;
}

@keyframes rgbMove{

  0%{
    background-position:
      0% 50%;
  }

  100%{
    background-position:
      400% 50%;
  }

}

.card{

  position:relative;

  background:
    rgba(
      8,
      15,
      35,
      .88
    );

  border:
    1px solid
    var(--border);

  border-radius:18px;

  padding:22px;

  margin-bottom:20px;
}

.card h2{

  margin-top:0;

  font-size:22px;

  background:
    linear-gradient(
      90deg,
      var(--c1),
      var(--c3)
    );

  -webkit-background-clip:text;
  background-clip:text;

  color:transparent;
}

label{

  display:block;

  font-weight:bold;

  margin:
    14px 0 6px;

  font-size:15px;

  color:#dbeafe;
}

.input-wrap{

  position:relative;

  padding:2px;

  border-radius:11px;

  overflow:hidden;

  margin-bottom:15px;
}

.input-wrap::before{

  content:"";

  position:absolute;

  inset:-100%;

  background:
    conic-gradient(
      from 0deg,
      #00d9ff,
      #0066ff,
      #8b5cf6,
      #ff007f,
      #00d9ff
    );

  animation:
    rotateRGB
    4s linear infinite;
}

.input-wrap input{

  position:relative;

  z-index:2;
}

@keyframes rotateRGB{

  to{
    transform:
      rotate(360deg);
  }

}

input[type=text],
input[type=file],
textarea{

  width:100%;

  padding:12px;

  border:0;

  outline:none;

  border-radius:10px;

  background:#020617;

  color:white;

  font-size:15px;
}

input[type=file]{

  border:
    1px solid
    rgba(
      255,
      255,
      255,
      .08
    );
}

textarea{

  min-height:160px;

  font-family:monospace;

  resize:vertical;

  border:
    1px solid
    rgba(
      255,
      255,
      255,
      .1
    );
}

.drop{

  position:relative;

  border:
    2px dashed
    var(--c1);

  padding:20px;

  text-align:center;

  border-radius:14px;

  margin-bottom:18px;

  background:
    rgba(
      2,
      6,
      23,
      .65
    );
}

.deploy-btn{

  width:100%;

  border:0;

  padding:15px;

  border-radius:11px;

  color:white;

  font-size:16px;

  font-weight:900;

  cursor:pointer;

  background:
    linear-gradient(
      90deg,
      #0066ff,
      #8b5cf6,
      #ff007f,
      #0066ff
    );

  background-size:300% auto;

  animation:
    buttonGradient
    4s linear infinite;

  box-shadow:
    0 0 15px
    rgba(
      0,
      217,
      255,
      .4
    );
}

@keyframes buttonGradient{

  to{
    background-position:
      300% center;
  }

}

.menu-btn{

  display:block;

  width:100%;

  text-align:center;

  padding:15px;

  background:
    linear-gradient(
      135deg,
      #2563eb,
      #7c3aed,
      #db2777
    );

  background-size:
    200% 200%;

  animation:
    liveBtnGlow
    5s ease infinite;

  color:white;

  text-decoration:none;

  border-radius:12px;

  font-weight:bold;

  font-size:16px;

  margin-top:15px;

  box-shadow:
    0 4px 20px
    rgba(
      37,
      99,
      235,
      .4
    );

  transition:
    transform .2s;
}

@keyframes liveBtnGlow{

  0%{
    background-position:
      0% 50%;
  }

  50%{
    background-position:
      100% 50%;
  }

  100%{
    background-position:
      0% 50%;
  }

}

.menu-btn:hover{
  transform:
    translateY(-2px);
}

.note{

  color:#718096;

  font-size:12px;

  margin-bottom:12px;
}

.deploy-tabs{

  display:flex;

  gap:10px;

  margin-bottom:15px;
}

.tab-btn{

  flex:1;

  padding:10px;

  border-radius:8px;

  border:
    1px solid
    var(--border);

  background:
    rgba(
      2,
      6,
      23,
      .8
    );

  color:var(--muted);

  font-weight:bold;

  cursor:pointer;

  transition:
    all .2s;
}

.tab-btn.active{

  background:
    linear-gradient(
      90deg,
      var(--c2),
      var(--c3)
    );

  color:white;

  border-color:
    transparent;
}

.tab-content{
  display:none;
}

.tab-content.active{
  display:block;
}

.account-bar{

  display:flex;

  align-items:center;

  justify-content:space-between;

  gap:10px;

  margin-bottom:15px;

  padding:10px 12px;

  background:
    rgba(
      2,
      6,
      23,
      .75
    );

  border:
    1px solid
    rgba(
      255,
      255,
      255,
      .1
    );

  border-radius:12px;
}

.account-user{

  display:flex;

  align-items:center;

  gap:10px;

  min-width:0;
}

.account-user img{

  width:38px;

  height:38px;

  border-radius:50%;

  border:
    2px solid
    var(--c1);
}

.account-email{

  font-size:12px;

  color:var(--muted);

  overflow:hidden;

  text-overflow:ellipsis;

  white-space:nowrap;
}

.logout-btn{

  border:0;

  background:
    linear-gradient(
      135deg,
      #dc2626,
      #ef4444
    );

  color:white;

  border-radius:8px;

  padding:8px 12px;

  cursor:pointer;

  font-weight:bold;
}

</style>
</head>

<body>

<div class="container">

<div class="account-bar">

  <div class="account-user">

    ${
      req.session.userPicture
        ? `
        <img
          src="${escapeAttribute(
            req.session.userPicture
          )}"
          alt="Profile"
        >
        `
        : ""
    }

    <div>

      <div style="font-weight:800;">
        👋 ${userName}
      </div>

      <div class="account-email">
        ${escapeHtml(
          req.session.userEmail ||
            ""
        )}
      </div>

    </div>

  </div>

  <button
    class="logout-btn"
    onclick="logoutUser()"
  >
    🚪 Logout
  </button>

</div>

<div class="header">

  <div
    class="card rgb-card"
    style="
      padding:15px;
      margin-bottom:15px;
    "
  >

    <div class="logo">

      <div class="logo-line1">
        Personal Website Hosting
      </div>

      <div class="logo-line2">
        Developed BY TâMïM Khan
      </div>

    </div>

  </div>

  <div class="subtitle">
    Upload / Paste → Deploy → Manage → Update → Live
  </div>

</div>

<div class="stats-container">

  <div class="stat-item">

    <div style="font-size:16px;">
      🌐
    </div>

    <div class="stat-number">
      ${projectsCount}
    </div>

    <div class="stat-label">
      Total Projects
    </div>

  </div>

  <div class="stat-item">

    <div style="font-size:16px;">
      🟢
    </div>

    <div class="stat-number">
      ${projectsCount}
    </div>

    <div class="stat-label">
      Live Websites
    </div>

  </div>

  <div class="stat-item">

    <div style="font-size:16px;">
      💾
    </div>

    <div class="stat-number">
      ${(totalSize / 1024).toFixed(1)}
      KB
    </div>

    <div class="stat-label">
      Total Storage
    </div>

  </div>

</div>

<div class="card rgb-card">

  <h2>
    🚀 নতুন প্রজেক্ট Deploy করুন
  </h2>

  <div class="deploy-tabs">

    <button
      type="button"
      class="tab-btn active"
      onclick="switchTab('file')"
    >
      📁 File / ZIP Upload
    </button>

    <button
      type="button"
      class="tab-btn"
      onclick="switchTab('code')"
    >
      💻 Code Paste (HTML)
    </button>

  </div>

  <form
    id="deployForm"
    action="/deploy"
    method="POST"
    enctype="multipart/form-data"
  >

    <input
      type="hidden"
      name="deployMode"
      id="deployMode"
      value="file"
    >

    <label>
      Project Name
    </label>

    <div class="input-wrap">

      <input
        type="text"
        name="sitename"
        required
        placeholder="my-project"
        pattern="[A-Za-z0-9_-]+"
        maxlength="50"
      >

    </div>

    <div class="note">
      শুধু English letters, numbers,
      - এবং _ ব্যবহার করুন।
    </div>

    <div
      id="fileTabContent"
      class="tab-content active"
    >

      <label>
        Website Files
      </label>

      <div
        id="dropBox"
        class="drop"
      >

        <div
          style="
            font-size:32px;
            margin-bottom:6px
          "
        >
          📦
        </div>

        <div
          style="
            font-size:15px;
            font-weight:bold
          "
        >
          HTML / CSS / JS অথবা ZIP
          ফাইল নির্বাচন করুন
        </div>

        <div
          style="
            margin:6px 0 10px;
            color:#64748b;
            font-size:12px
          "
        >
          Drag & Drop করেও file
          দেওয়া যাবে
        </div>

        <input
          type="file"
          id="fileInput"
          name="projectfiles"
          multiple
          accept=".html,.htm,.css,.js,.json,.png,.jpg,.jpeg,.gif,.svg,.webp,.ico,.txt,.zip,.woff,.woff2,.ttf,.mp3,.mp4,.webm"
        >

        <div
          id="fileStatus"
          style="
            margin-top:8px;
            color:#64748b;
            font-size:12px
          "
        >
          কোনো file নির্বাচন করা হয়নি
        </div>

      </div>

    </div>

    <div
      id="codeTabContent"
      class="tab-content"
    >

      <label>
        Direct HTML Code
        (কপি-পেস্ট)
      </label>

      <textarea
        name="htmlcode"
        placeholder="<!DOCTYPE html>
<html>
<head>
<title>My Site</title>
</head>
<body>
  <h1>Hello World</h1>
</body>
</html>"
      ></textarea>

      <div
        class="note"
        style="margin-top:6px;"
      >
        এখানে ডিরেক্ট HTML কোড
        পেস্ট করে সরাসরি লাইভ করতে
        পারবেন।
      </div>

    </div>

    <button
      id="deployBtn"
      class="deploy-btn"
      type="submit"
    >
      🚀 DEPLOY WEBSITE
    </button>

  </form>

</div>

<div
  class="card rgb-card"
  style="
    text-align:center;
    padding:20px;
  "
>

  <h2
    style="margin-bottom:8px;"
  >
    📂 My Projects
  </h2>

  <p
    style="
      color:var(--muted);
      font-size:13px;
      margin-bottom:15px;
    "
  >
    আপনার সকল প্রজেক্ট দেখতে এবং
    ম্যানেজ করতে নিচের বাটনে
    ক্লিক করুন।
  </p>

  <a
    href="/projects"
    class="menu-btn"
  >
    📂 View All Projects
  </a>

</div>

</div>

<script>

function switchTab(mode){

  document.getElementById(
    "deployMode"
  ).value = mode;

  const buttons =
    document.querySelectorAll(
      ".tab-btn"
    );

  buttons.forEach(
    b =>
      b.classList.remove(
        "active"
      )
  );

  if(mode === "file"){

    buttons[0]
      .classList.add(
        "active"
      );

    document
      .getElementById(
        "fileTabContent"
      )
      .classList.add(
        "active"
      );

    document
      .getElementById(
        "codeTabContent"
      )
      .classList.remove(
        "active"
      );

    document
      .getElementById(
        "fileInput"
      )
      .required = true;

  }else{

    buttons[1]
      .classList.add(
        "active"
      );

    document
      .getElementById(
        "fileTabContent"
      )
      .classList.remove(
        "active"
      );

    document
      .getElementById(
        "codeTabContent"
      )
      .classList.add(
        "active"
      );

    document
      .getElementById(
        "fileInput"
      )
      .required = false;
  }
}

const fileInput =
  document.getElementById(
    "fileInput"
  );

const fileStatus =
  document.getElementById(
    "fileStatus"
  );

if(fileInput){

  fileInput.addEventListener(
    "change",
    ()=>{

      if(
        fileInput.files.length
      ){

        fileStatus.textContent =
          "✅ " +
          fileInput.files.length +
          "টি file selected";

      }else{

        fileStatus.textContent =
          "কোনো file নির্বাচন করা হয়নি";
      }

    }
  );
}

const deployForm =
  document.getElementById(
    "deployForm"
  );

const deployBtn =
  document.getElementById(
    "deployBtn"
  );

if(deployForm){

  deployForm.addEventListener(
    "submit",
    ()=>{

      deployBtn.innerHTML =
        "⏳ UPLOADING & DEPLOYING...";

      deployBtn.style.pointerEvents =
        "none";

      deployBtn.disabled =
        true;

    }
  );
}

async function logoutUser(){

  try{

    await fetch(
      "/api/auth/logout",
      {
        method:"POST"
      }
    );

  }catch{}

  window.location.href =
    "/login";
}

</script>

</body>
</html>
`);
  }
);

// ======================================================
// PROJECTS PAGE
// ======================================================

app.get(
  "/projects",
  requireLogin,
  async (req, res) => {
    let projects = [];

    try {
      const result =
        await pool.query(
          `
          SELECT
            id,
            name,
            slug,
            type,
            folder_name,
            title,
            description,
            keywords,
            author,
            created_at,
            updated_at
          FROM websites
          WHERE user_id = $1
          ORDER BY created_at DESC
          `,
          [req.session.userId]
        );

      projects =
        result.rows.map(
          project => {

            let size = 0;

            if (
              project.folder_name
            ) {
              const projectPath =
                getProjectDir(
                  req.session.userId,
                  project.folder_name
                );

              if (
                fs.existsSync(
                  projectPath
                )
              ) {
                try {
                  const files =
                    fs.readdirSync(
                      projectPath,
                      {
                        recursive:true
                      }
                    );

                  for (
                    const file
                      of files
                  ) {
                    try {
                      const full =
                        path.join(
                          projectPath,
                          file
                        );

                      const stat =
                        fs.statSync(
                          full
                        );

                      if (
                        stat.isFile()
                      ) {
                        size +=
                          stat.size;
                      }
                    } catch {}
                  }
                } catch {}
              }
            }

            return {
              ...project,

              title:
                project.title ||
                project.name,

              description:
                project.description ||
                "",

              keywords:
                project.keywords ||
                "",

              size:
                (
                  size / 1024
                ).toFixed(1)
            };
          }
        );

    } catch (error) {
      console.error(error);
    }

    const projectHTML =
      projects.length
        ? projects
            .map(
              project => `
      <div
        class="project-card-wrap"
        data-search="${escapeAttribute(
          `${project.title}
           ${project.name}
           ${project.slug}
           ${project.description}
           ${project.keywords}`
        )}"
      >

        <div class="project">

          <div class="project-header">

            <div class="project-left">

              <div class="project-icon">
                🌐
              </div>

              <div>

                <div class="project-name">
                  ${escapeHtml(
                    project.title
                  )}
                </div>

                <div class="project-id">
                  ID:
                  ${escapeHtml(
                    project.name
                  )}
                </div>

              </div>

            </div>

            <div class="project-meta-badge">

              <span>
                💾
                ${escapeHtml(
                  project.size
                )}
                KB
              </span>

              <span
                class="live-dot-badge"
              >
                ● Live
              </span>

            </div>

          </div>

          <div class="project-url-container">

            <span class="url-text">
              /site/${escapeHtml(
                project.slug
              )}/
            </span>

            <button
              class="copy-url-btn"
              type="button"
              data-url="/site/${encodeURIComponent(
                project.slug
              )}/"
            >
              📋 Copy Link
            </button>

          </div>

          <div class="project-actions">

            <a
              class="action-btn live-btn"
              href="/site/${encodeURIComponent(
                project.slug
              )}/"
              target="_blank"
              rel="noopener"
            >
              🌐 Live View
            </a>

            <a
              class="action-btn edit-btn"
              href="/edit/${encodeURIComponent(
                project.folder_name
              )}"
            >
              ✏️ Edit
            </a>

            <form
              action="/delete/${encodeURIComponent(
                project.folder_name
              )}"
              method="POST"
              onsubmit="return confirm('এই প্রজেক্টটি কি সত্যি ডিলিট করতে চান?')"
              style="
                margin:0;
                flex:1;
                display:flex;
              "
            >

              <button
                class="action-btn delete-btn"
                type="submit"
              >
                🗑 Delete
              </button>

            </form>

          </div>

        </div>

      </div>
    `
            )
            .join("")
        : `
      <div class="empty">

        <div
          class="empty-icon"
          style="
            font-size:36px;
            margin-bottom:10px;
          "
        >
          📂
        </div>

        <b>
          এখনো কোনো প্রজেক্ট
          ডিপ্লয় করা হয়নি।
        </b>

      </div>
    `;

    res.send(`
<!DOCTYPE html>
<html lang="bn">

<head>

<meta charset="UTF-8">

<meta
  name="viewport"
  content="width=device-width, initial-scale=1.0"
>

<title>
My Projects - Personal Website Hosting
</title>

<style>

:root{
  --c1:#00d9ff;
  --c2:#0066ff;
  --c3:#8b5cf6;
  --bg1:#020617;
  --bg2:#07132f;
  --text:#f8fafc;
  --muted:#94a3b8;
  --border:rgba(255,255,255,.14);
}

*{
  box-sizing:border-box;
}

body{

  margin:0;

  min-height:100vh;

  font-family:
    Arial,
    sans-serif;

  color:var(--text);

  background:
    radial-gradient(
      circle at 10% 20%,
      rgba(
        139,
        92,
        246,
        .25
      ),
      transparent 40%
    ),

    radial-gradient(
      circle at 90% 80%,
      rgba(
        0,
        102,
        255,
        .25
      ),
      transparent 40%
    ),

    linear-gradient(
      135deg,
      var(--bg1),
      var(--bg2)
    );

  background-size:
    200% 200%;

  animation:
    liveBackgroundShift
    12s ease infinite;

  padding:
    20px 0 50px;
}

@keyframes liveBackgroundShift{

  0%{
    background-position:
      0% 50%;
  }

  50%{
    background-position:
      100% 50%;
  }

  100%{
    background-position:
      0% 50%;
  }

}

.container{
  width:min(
    900px,
    94%
  );

  margin:auto;
}

.account-bar{

  display:flex;

  justify-content:space-between;

  align-items:center;

  gap:10px;

  margin-bottom:15px;

  padding:10px 12px;

  border-radius:12px;

  background:
    rgba(
      8,
      15,
      35,
      .9
    );

  border:
    1px solid
    rgba(
      255,
      255,
      255,
      .1
    );
}

.account-user{

  display:flex;

  align-items:center;

  gap:10px;
}

.account-user img{

  width:36px;

  height:36px;

  border-radius:50%;

  border:
    2px solid
    var(--c1);
}

.account-email{

  font-size:11px;

  color:var(--muted);
}

.logout-btn{

  border:0;

  padding:8px 12px;

  border-radius:8px;

  color:white;

  background:
    linear-gradient(
      135deg,
      #dc2626,
      #ef4444
    );

  font-weight:bold;

  cursor:pointer;
}

.main-card{

  position:relative;

  background:
    rgba(
      8,
      15,
      35,
      .9
    );

  border-radius:20px;

  padding:24px;

  margin-bottom:20px;

  box-shadow:
    0 10px 30px
    rgba(
      0,
      0,
      0,
      .5
    );
}

.main-card::before{

  content:"";

  position:absolute;

  inset:-2px;

  border-radius:22px;

  background:
    linear-gradient(
      90deg,
      #00d9ff,
      #0066ff,
      #8b5cf6,
      #ff007f,
      #00d9ff
    );

  background-size:
    400% 100%;

  animation:
    rgbMove
    6s linear infinite;

  z-index:-2;

  filter:blur(5px);

  opacity:.9;
}

.main-card::after{

  content:"";

  position:absolute;

  inset:0;

  border-radius:20px;

  background:
    rgba(
      8,
      15,
      35,
      .95
    );

  z-index:-1;
}

@keyframes rgbMove{

  0%{
    background-position:
      0% 50%;
  }

  100%{
    background-position:
      400% 50%;
  }

}

.section-head{

  display:flex;

  justify-content:space-between;

  align-items:center;

  gap:15px;

  margin-bottom:20px;

  flex-wrap:wrap;
}

.section-head h2{

  margin:0;

  font-size:22px;

  background:
    linear-gradient(
      90deg,
      var(--c1),
      var(--c3)
    );

  -webkit-background-clip:text;

  -webkit-text-fill-color:transparent;
}

.search-wrap{

  position:relative;

  width:min(
    280px,
    100%
  );
}

.search-wrap input{

  width:100%;

  padding:
    11px 12px 11px 38px;

  border-radius:12px;

  border:
    1px solid
    var(--border);

  background:#020617;

  color:white;

  outline:none;

  font-size:14px;
}

.search-icon{

  position:absolute;

  left:12px;

  top:50%;

  transform:
    translateY(-50%);
}

.projects{

  display:grid;

  gap:16px;
}

.project-card-wrap{

  position:relative;

  border-radius:16px;
}

.project-card-wrap::before{

  content:"";

  position:absolute;

  inset:-1.5px;

  border-radius:17px;

  background:
    linear-gradient(
      135deg,
      var(--c1),
      var(--c2),
      var(--c3),
      #ff007f
    );

  background-size:
    300% 300%;

  animation:
    cardRgbGlow
    5s ease infinite
    alternate;

  z-index:-2;

  opacity:.8;
}

@keyframes cardRgbGlow{

  0%{
    background-position:
      0% 50%;
  }

  100%{
    background-position:
      100% 50%;
  }

}

.project{

  position:relative;

  background:
    rgba(
      4,
      9,
      24,
      .96
    );

  border-radius:15px;

  padding:16px;

  display:flex;

  flex-direction:column;

  gap:12px;

  z-index:1;
}

.project-header{

  display:flex;

  justify-content:space-between;

  align-items:center;

  gap:10px;

  flex-wrap:wrap;
}

.project-left{

  display:flex;

  align-items:center;

  gap:12px;

  min-width:0;
}

.project-icon{

  font-size:24px;

  background:
    rgba(
      0,
      217,
      255,
      .1
    );

  padding:8px;

  border-radius:10px;
}

.project-name{

  font-size:16px;

  font-weight:800;

  color:#f8fafc;

  word-break:break-word;
}

.project-id{

  color:var(--muted);

  font-size:11px;

  margin-top:2px;
}

.project-meta-badge{

  display:flex;

  align-items:center;

  gap:10px;

  background:
    rgba(
      255,
      255,
      255,
      .05
    );

  padding:
    6px 10px;

  border-radius:8px;

  font-size:11px;

  color:var(--muted);
}

.live-dot-badge{

  color:#4ade80;

  font-weight:bold;
}

.project-url-container{

  display:flex;

  align-items:center;

  justify-content:space-between;

  background:#020617;

  border:
    1px solid
    rgba(
      255,
      255,
      255,
      .08
    );

  padding:
    8px 12px;

  border-radius:10px;

  gap:10px;
}

.url-text{

  color:var(--c1);

  font-size:13px;

  font-family:monospace;

  overflow:hidden;

  text-overflow:ellipsis;

  white-space:nowrap;
}

.copy-url-btn{

  border:0;

  background:
    linear-gradient(
      90deg,
      rgba(
        0,
        217,
        255,
        .2
      ),
      rgba(
        0,
        102,
        255,
        .2
      )
    );

  color:#bae6fd;

  padding:
    6px 12px;

  border-radius:7px;

  cursor:pointer;

  font-size:12px;

  font-weight:bold;

  white-space:nowrap;

  transition:
    background .2s;
}

.copy-url-btn:hover{

  background:
    rgba(
      0,
      217,
      255,
      .35
    );
}

.project-actions{

  display:flex;

  gap:8px;

  flex-wrap:wrap;

  margin-top:2px;
}

.action-btn{

  flex:1;

  min-width:90px;

  padding:10px;

  border-radius:9px;

  color:white;

  font-weight:bold;

  font-size:13px;

  text-align:center;

  text-decoration:none;

  border:0;

  cursor:pointer;

  transition:
    transform .1s,
    opacity .2s;
}

.action-btn:hover{

  opacity:.9;

  transform:
    translateY(-1px);
}

.live-btn{

  background:
    linear-gradient(
      135deg,
      #059669,
      #10b981
    );
}

.edit-btn{

  background:
    linear-gradient(
      135deg,
      #2563eb,
      #3b82f6
    );
}

.delete-btn{

  background:
    linear-gradient(
      135deg,
      #dc2626,
      #ef4444
    );

  width:100%;
}

.empty{

  text-align:center;

  padding:40px;

  color:var(--muted);
}

.back-btn{

  display:inline-block;

  margin-bottom:15px;

  color:var(--c1);

  text-decoration:none;

  font-weight:bold;

  font-size:14px;
}

.hidden-project{
  display:none!important;
}

</style>

</head>

<body>

<div class="container">

<div class="account-bar">

  <div class="account-user">

    ${
      req.session.userPicture
        ? `
        <img
          src="${escapeAttribute(
            req.session.userPicture
          )}"
          alt="Profile"
        >
        `
        : ""
    }

    <div>

      <div style="font-weight:800;">
        👋 ${escapeHtml(
          req.session.userName ||
          "User"
        )}
      </div>

      <div class="account-email">
        ${escapeHtml(
          req.session.userEmail ||
          ""
        )}
      </div>

    </div>

  </div>

  <button
    class="logout-btn"
    onclick="logoutUser()"
  >
    🚪 Logout
  </button>

</div>

<a
  href="/"
  class="back-btn"
>
  ← Back to Dashboard
</a>

<div class="main-card">

  <div class="section-head">

    <h2>
      📂 My Projects List
    </h2>

    <div class="search-wrap">

      <span class="search-icon">
        🔍
      </span>

      <input
        id="projectSearch"
        type="text"
        placeholder="প্রজেক্ট খুঁজুন..."
      >

    </div>

  </div>

  <div
    id="projectsList"
    class="projects"
  >

    ${projectHTML}

  </div>

  <div
    id="noSearchResult"
    class="empty"
    style="display:none"
  >
    <b>
      কোনো matching project
      পাওয়া যায়নি।
    </b>
  </div>

</div>

</div>

<script>

const projectSearch =
  document.getElementById(
    "projectSearch"
  );

const noSearchResult =
  document.getElementById(
    "noSearchResult"
  );

if(projectSearch){

  projectSearch.addEventListener(
    "input",
    ()=>{

      const query =
        projectSearch.value
          .trim()
          .toLowerCase();

      const projects =
        [
          ...document.querySelectorAll(
            ".project-card-wrap"
          )
        ];

      let visible = 0;

      projects.forEach(
        project => {

          const text =
            (
              project.dataset.search ||
              ""
            ).toLowerCase();

          const match =
            !query ||
            text.includes(
              query
            );

          project.classList.toggle(
            "hidden-project",
            !match
          );

          if(match){
            visible++;
          }

        }
      );

      noSearchResult.style.display =
        visible
          ? "none"
          : "block";

    }
  );
}

document
  .querySelectorAll(
    ".copy-url-btn"
  )
  .forEach(
    button => {

      button.addEventListener(
        "click",
        async ()=>{

          const fullUrl =
            new URL(
              button.dataset.url ||
                "",
              window.location.origin
            ).href;

          try{

            await navigator
              .clipboard
              .writeText(
                fullUrl
              );

            const originalText =
              button.textContent;

            button.textContent =
              "✅ Copied!";

            setTimeout(
              () =>
                button.textContent =
                  originalText,
              1500
            );

          }catch{}

        }
      );

    }
  );

async function logoutUser(){

  try{

    await fetch(
      "/api/auth/logout",
      {
        method:"POST"
      }
    );

  }catch{}

  window.location.href =
    "/login";
}

</script>

</body>
</html>
`);
  }
);

// ======================================================
// DEPLOY
// ======================================================

app.post(
  "/deploy",
  requireLogin,
  upload.array(
    "projectfiles",
    50
  ),
  async (req, res) => {

    const siteName =
      sanitizeSiteName(
        req.body.sitename
      );

    const deployMode =
      req.body.deployMode;

    const files =
      req.files || [];

    if (!siteName) {
      return res
        .status(400)
        .send(
          "Invalid project name."
        );
    }

    const userId =
      req.session.userId;

    const existing =
      await pool.query(
        `
        SELECT id
        FROM websites
        WHERE
          user_id = $1
          AND name = $2
        LIMIT 1
        `,
        [
          userId,
          siteName
        ]
      );

    if (
      existing.rows.length
    ) {
      return res
        .status(400)
        .send(
          "এই নামে আপনার একটি project ইতিমধ্যে আছে। অন্য নাম ব্যবহার করুন।"
        );
    }

    const folderName =
      makeFolderName(
        siteName
      );

    const targetDir =
      getProjectDir(
        userId,
        folderName
      );

    let createdRecord = null;

    try {

      await fs.ensureDir(
        getUserDir(userId)
      );

      await fs.remove(
        targetDir
      );

      await fs.ensureDir(
        targetDir
      );

      // ------------------------------------------------
      // Direct HTML
      // ------------------------------------------------

      if (
        deployMode === "code"
      ) {

        const htmlCode =
          req.body.htmlcode ||
          "";

        if (
          !htmlCode.trim()
        ) {
          return res
            .status(400)
            .send(
              "HTML code cannot be empty."
            );
        }

        if (
          Buffer.byteLength(
            htmlCode,
            "utf8"
          ) >
          2 * 1024 * 1024
        ) {
          return res
            .status(400)
            .send(
              "HTML file is too large. Maximum 2MB."
            );
        }

        await fs.writeFile(
          path.join(
            targetDir,
            "index.html"
          ),
          htmlCode,
          "utf8"
        );

      } else {

        if (!files.length) {
          return res
            .status(400)
            .send(
              "No files uploaded."
            );
        }

        // ----------------------------------------------
        // ZIP
        // ----------------------------------------------

        if (
          files.length === 1 &&
          path
            .extname(
              files[0].originalname
            )
            .toLowerCase() ===
            ".zip"
        ) {

          const buffer =
            await fs.readFile(
              files[0].path
            );

          const zip =
            validateZipBuffer(
              buffer
            );

          const entries =
            zip.getEntries();

          for (
            const entry
              of entries
          ) {

            if (
              entry.isDirectory
            ) {
              continue;
            }

            let entryName =
              entry.entryName
                .replace(
                  /\\/g,
                  "/"
                )
                .replace(
                  /^\/+/,
                  ""
                );

            if (!entryName) {
              continue;
            }

            const parts =
              entryName.split("/");

            if (
              parts.includes("..")
            ) {
              throw new Error(
                "Unsafe ZIP file path detected."
              );
            }

            const outputPath =
              safeJoin(
                targetDir,
                entryName
              );

            await fs.ensureDir(
              path.dirname(
                outputPath
              )
            );

            await fs.writeFile(
              outputPath,
              entry.getData()
            );
          }

          await fs.remove(
            files[0].path
          );

          await flattenSingleFolder(
            targetDir
          );

        } else {

          // --------------------------------------------
          // Multiple files
          // --------------------------------------------

          for (
            const file of files
          ) {

            const safeName =
              sanitizeFileName(
                file.originalname
              );

            if (!safeName) {
              await fs.remove(
                file.path
              );

              continue;
            }

            const destination =
              safeJoin(
                targetDir,
                safeName
              );

            await fs.move(
              file.path,
              destination,
              {
                overwrite:true
              }
            );
          }
        }
      }

      // ------------------------------------------------
      // Ensure index
      // ------------------------------------------------

      const indexFile =
        await ensureIndexHtml(
          targetDir
        );

      if (!indexFile) {

        await fs.remove(
          targetDir
        );

        return res
          .status(400)
          .send(
            "Project-এর মধ্যে কোনো HTML file পাওয়া যায়নি।"
          );
      }

      // ------------------------------------------------
      // Generate slug
      // ------------------------------------------------

      const slug =
        await generateSlug(
          siteName
        );

      // ------------------------------------------------
      // Database record
      // ------------------------------------------------

      const result =
        await pool.query(
          `
          INSERT INTO websites
          (
            user_id,
            name,
            slug,
            type,
            folder_name,
            title,
            description,
            keywords,
            author
          )
          VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8,
            $9
          )
          RETURNING *
          `,
          [
            userId,

            siteName,

            slug,

            deployMode === "code"
              ? "html"
              : "zip",

            folderName,

            siteName,

            `${siteName} website`,

            siteName,

            req.session.userName ||
              "Website Owner"
          ]
        );

      createdRecord =
        result.rows[0];

      const liveUrl =
        getProjectUrl(
          req,
          slug
        );

      res.send(`
<!DOCTYPE html>
<html lang="bn">

<head>

<meta charset="UTF-8">

<meta
  name="viewport"
  content="width=device-width, initial-scale=1"
>

<title>
Deployment Successful
</title>

<style>

body{

  margin:0;

  min-height:100vh;

  display:flex;

  align-items:center;

  justify-content:center;

  background:
    radial-gradient(
      circle at 20% 20%,
      #8b5cf6,
      transparent 35%
    ),

    radial-gradient(
      circle at 80% 80%,
      #0066ff,
      transparent 35%
    ),

    #020617;

  color:white;

  font-family:Arial;

}

.box{

  width:min(
    600px,
    90%
  );

  text-align:center;

  background:
    rgba(
      8,
      15,
      35,
      .95
    );

  padding:35px;

  border-radius:20px;

  position:relative;
}

.box::before{

  content:"";

  position:absolute;

  inset:-2px;

  border-radius:22px;

  background:
    linear-gradient(
      90deg,
      #00d9ff,
      #0066ff,
      #8b5cf6,
      #ff007f,
      #00d9ff
    );

  background-size:
    400% 100%;

  animation:
    rgbMove
    5s linear infinite;

  z-index:-1;

  filter:
    blur(5px);
}

@keyframes rgbMove{

  to{
    background-position:
      400% 50%;
  }

}

a{

  color:#38bdf8;

  word-break:break-all;
}

.btn{

  display:inline-block;

  margin-top:20px;

  padding:
    12px 20px;

  border-radius:10px;

  background:
    linear-gradient(
      135deg,
      #2563eb,
      #7c3aed
    );

  color:white;

  text-decoration:none;

  font-weight:bold;
}

</style>

</head>

<body>

<div class="box">

<h1>
🎉 Deployment Successful!
</h1>

<p>
আপনার website successfully
deploy হয়েছে।
</p>

<p>
<a
  href="${escapeAttribute(
    liveUrl
  )}"
  target="_blank"
>
${escapeHtml(
  liveUrl
)}
</a>
</p>

<a
  class="btn"
  href="/projects"
>
📂 My Projects
</a>

</div>

</body>

</html>
`);

    } catch (error) {

      console.error(
        "Deploy error:",
        error
      );

      if (
        files.length
      ) {
        for (
          const file of files
        ) {
          try {
            await fs.remove(
              file.path
            );
          } catch {}
        }
      }

      if (
        !createdRecord
      ) {
        try {
          await fs.remove(
            targetDir
          );
        } catch {}
      }

      res
        .status(500)
        .send(
          error.message ||
            "Deploy error."
        );
    }
  }
);

// ======================================================
// EDIT PAGE
// ======================================================

app.get(
  "/edit/:project",
  requireLogin,
  async (req, res) => {

    const folderName =
      sanitizeSiteName(
        req.params.project
      );

    const project =
      await findUserProject(
        req.session.userId,
        folderName
      );

    if (!project) {
      return res
        .status(404)
        .send(
          "Project not found."
        );
    }

    const meta = {
      slug:
        project.slug ||
        project.name,

      title:
        project.title ||
        project.name,

      description:
        project.description ||
        "",

      keywords:
        project.keywords ||
        "",

      author:
        project.author ||
        req.session.userName ||
        "Website Owner"
    };

    res.send(`
<!DOCTYPE html>
<html lang="bn">

<head>

<meta charset="UTF-8">

<meta
  name="viewport"
  content="width=device-width, initial-scale=1"
>

<title>
Edit Project
</title>

<style>

:root{
  --c1:#00d9ff;
  --c2:#0066ff;
  --c3:#8b5cf6;
  --bg:#020617;
  --muted:#94a3b8;
}

*{
  box-sizing:border-box;
}

body{

  background:
    radial-gradient(
      circle at 20% 20%,
      rgba(
        139,
        92,
        246,
        .3
      ),
      transparent 40%
    ),

    radial-gradient(
      circle at 80% 80%,
      rgba(
        0,
        102,
        255,
        .3
      ),
      transparent 40%
    ),

    var(--bg);

  color:white;

  font-family:Arial;

  padding:
    20px;
}

.box{

  max-width:
    650px;

  margin:
    30px auto;

  background:
    rgba(
      15,
      23,
      42,
      .96
    );

  padding:
    25px;

  border-radius:
    18px;

  position:relative;
}

.box::before{

  content:"";

  position:absolute;

  inset:-2px;

  border-radius:
    20px;

  background:
    linear-gradient(
      90deg,
      #00d9ff,
      #0066ff,
      #8b5cf6,
      #ff007f,
      #00d9ff
    );

  background-size:
    400% 100%;

  animation:
    rgbMove
    6s linear infinite;

  z-index:-1;

  filter:
    blur(5px);
}

@keyframes rgbMove{

  to{
    background-position:
      400% 50%;
  }

}

input,
textarea{

  width:100%;

  padding:12px;

  margin:
    8px 0 15px;

  background:
    #020617;

  color:white;

  border:
    1px solid
    #334155;

  border-radius:
    9px;

  outline:none;
}

textarea{
  min-height:130px;
}

button{

  padding:
    11px 16px;

  background:
    linear-gradient(
      135deg,
      #2563eb,
      #7c3aed,
      #db2777
    );

  color:white;

  border:0;

  border-radius:
    9px;

  cursor:pointer;

  font-weight:bold;
}

.file-box{

  border:
    2px dashed
    var(--c1);

  padding:
    18px;

  border-radius:
    12px;

  margin-bottom:
    15px;
}

.back{

  color:
    #38bdf8;

  text-decoration:none;
}

</style>

</head>

<body>

<div class="box">

<a
  class="back"
  href="/projects"
>
← Back to Projects
</a>

<h2>
✏️ Edit Project:
${escapeHtml(
  project.name
)}
</h2>

<form
  action="/update/${encodeURIComponent(
    folderName
  )}"
  method="POST"
  enctype="multipart/form-data"
>

<label>
Update Files
</label>

<div class="file-box">

<input
  type="file"
  name="projectfiles"
  required
  multiple
  accept=".html,.htm,.css,.js,.json,.png,.jpg,.jpeg,.gif,.svg,.webp,.ico,.txt,.zip,.woff,.woff2,.ttf,.mp3,.mp4,.webm"
>

<p
  style="
    color:#94a3b8;
    font-size:12px;
  "
>
ZIP অথবা multiple website
files upload করতে পারবেন।
</p>

</div>

<button type="submit">
🔄 Update Files
</button>

</form>

<hr
  style="
    border-color:#334155;
    margin:25px 0;
  "
>

<form
  action="/save-settings/${encodeURIComponent(
    folderName
  )}"
  method="POST"
>

<label>
URL Slug
</label>

<input
  type="text"
  name="slug"
  value="${escapeAttribute(
    meta.slug
  )}"
  pattern="[A-Za-z0-9_-]+"
  maxlength="50"
  required
>

<label>
Title
</label>

<input
  type="text"
  name="title"
  value="${escapeAttribute(
    meta.title
  )}"
>

<label>
Description
</label>

<textarea
  name="description"
>${escapeHtml(
  meta.description
)}</textarea>

<label>
Keywords
</label>

<input
  type="text"
  name="keywords"
  value="${escapeAttribute(
    meta.keywords
  )}"
>

<label>
Author
</label>

<input
  type="text"
  name="author"
  value="${escapeAttribute(
    meta.author
  )}"
>

<button type="submit">
💾 Save Settings
</button>

</form>

</div>

</body>

</html>
`);
  }
);

// ======================================================
// UPDATE PROJECT FILES
// ======================================================

app.post(
  "/update/:project",
  requireLogin,
  upload.array(
    "projectfiles",
    50
  ),
  async (req, res) => {

    const folderName =
      sanitizeSiteName(
        req.params.project
      );

    const files =
      req.files || [];

    const project =
      await findUserProject(
        req.session.userId,
        folderName
      );

    if (!project) {
      return res
        .status(404)
        .send(
          "Project not found."
        );
    }

    if (!files.length) {
      return res
        .status(400)
        .send(
          "No files uploaded."
        );
    }

    const targetDir =
      getProjectDir(
        req.session.userId,
        folderName
      );

    const updateDir =
      safeJoin(
        getUserDir(
          req.session.userId
        ),
        `update-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`
      );

    try {

      await fs.ensureDir(
        updateDir
      );

      // ------------------------------------------------
      // ZIP
      // ------------------------------------------------

      if (
        files.length === 1 &&
        path
          .extname(
            files[0].originalname
          )
          .toLowerCase() ===
          ".zip"
      ) {

        const buffer =
          await fs.readFile(
            files[0].path
          );

        const zip =
          validateZipBuffer(
            buffer
          );

        for (
          const entry
            of zip.getEntries()
        ) {

          if (
            entry.isDirectory
          ) {
            continue;
          }

          const entryName =
            entry.entryName
              .replace(
                /\\/g,
                "/"
              )
              .replace(
                /^\/+/,
                ""
              );

          if (!entryName) {
            continue;
          }

          if (
            entryName
              .split("/")
              .includes("..")
          ) {
            throw new Error(
              "Unsafe ZIP path."
            );
          }

          const output =
            safeJoin(
              updateDir,
              entryName
            );

          await fs.ensureDir(
            path.dirname(
              output
            )
          );

          await fs.writeFile(
            output,
            entry.getData()
          );
        }

        await fs.remove(
          files[0].path
        );

        await flattenSingleFolder(
          updateDir
        );

      } else {

        for (
          const file of files
        ) {

          const safeName =
            sanitizeFileName(
              file.originalname
            );

          const destination =
            safeJoin(
              updateDir,
              safeName
            );

          await fs.move(
            file.path,
            destination,
            {
              overwrite:true
            }
          );
        }
      }

      const index =
        await ensureIndexHtml(
          updateDir
        );

      if (!index) {
        await fs.remove(
          updateDir
        );

        return res
          .status(400)
          .send(
            "Uploaded project-এ HTML file পাওয়া যায়নি।"
          );
      }

      // ------------------------------------------------
      // Replace old files
      // ------------------------------------------------

      await fs.remove(
        targetDir
      );

      await fs.move(
        updateDir,
        targetDir
      );

      await pool.query(
        `
        UPDATE websites
        SET
          updated_at = NOW()
        WHERE
          id = $1
          AND user_id = $2
        `,
        [
          project.id,
          req.session.userId
        ]
      );

      res.redirect(
        `/edit/${encodeURIComponent(
          folderName
        )}`
      );

    } catch (error) {

      console.error(
        "Update error:",
        error
      );

      try {
        await fs.remove(
          updateDir
        );
      } catch {}

      for (
        const file of files
      ) {
        try {
          await fs.remove(
            file.path
          );
        } catch {}
      }

      res
        .status(500)
        .send(
          error.message ||
            "Update error."
        );
    }
  }
);

// ======================================================
// SAVE SETTINGS
// ======================================================

app.post(
  "/save-settings/:project",
  requireLogin,
  async (req, res) => {

    const folderName =
      sanitizeSiteName(
        req.params.project
      );

    const project =
      await findUserProject(
        req.session.userId,
        folderName
      );

    if (!project) {
      return res
        .status(404)
        .send(
          "Project not found."
        );
    }

    const newSlug =
      sanitizeSiteName(
        req.body.slug
      );

    if (!newSlug) {
      return res
        .status(400)
        .send(
          "Invalid slug."
        );
    }

    // --------------------------------------------------
    // Check slug collision
    // --------------------------------------------------

    const collision =
      await pool.query(
        `
        SELECT id
        FROM websites
        WHERE
          slug = $1
          AND id <> $2
        LIMIT 1
        `,
        [
          newSlug,
          project.id
        ]
      );

    if (
      collision.rows.length
    ) {
      return res
        .status(400)
        .send(
          "এই URL slug ইতিমধ্যে ব্যবহার হচ্ছে।"
        );
    }

    const oldSlug =
      project.slug;

    let previousSlugs =
      Array.isArray(
        project.previous_slugs
      )
        ? project.previous_slugs
        : [];

    if (
      oldSlug &&
      oldSlug !== newSlug &&
      !previousSlugs.includes(
        oldSlug
      )
    ) {
      previousSlugs.push(
        oldSlug
      );
    }

    previousSlugs =
      previousSlugs.slice(
        -50
      );

    const title =
      String(
        req.body.title ||
          project.title ||
          project.name
      ).slice(0, 200);

    const description =
      String(
        req.body.description ||
          project.description ||
          ""
      ).slice(0, 500);

    const keywords =
      String(
        req.body.keywords ||
          project.keywords ||
          ""
      ).slice(0, 500);

    const author =
      String(
        req.body.author ||
          project.author ||
          req.session.userName ||
          "Website Owner"
      ).slice(0, 100);

    await pool.query(
      `
      UPDATE websites
      SET
        slug = $1,
        title = $2,
        description = $3,
        keywords = $4,
        author = $5,
        previous_slugs = $6,
        updated_at = NOW()
      WHERE
        id = $7
        AND user_id = $8
      `,
      [
        newSlug,
        title,
        description,
        keywords,
        author,
        previousSlugs,
        project.id,
        req.session.userId
      ]
    );

    res.redirect(
      `/edit/${encodeURIComponent(
        folderName
      )}`
    );
  }
);

// ======================================================
// DELETE
// ======================================================

app.post(
  "/delete/:sitename",
  requireLogin,
  async (req, res) => {

    const folderName =
      sanitizeSiteName(
        req.params.sitename
      );

    const project =
      await findUserProject(
        req.session.userId,
        folderName
      );

    if (!project) {
      return res
        .status(404)
        .send(
          "Project not found."
        );
    }

    try {

      if (
        project.folder_name
      ) {

        const projectDir =
          getProjectDir(
            req.session.userId,
            project.folder_name
          );

        await fs.remove(
          projectDir
        );
      }

      await pool.query(
        `
        DELETE FROM websites
        WHERE
          id = $1
          AND user_id = $2
        `,
        [
          project.id,
          req.session.userId
        ]
      );

      res.redirect(
        "/projects"
      );

    } catch (error) {

      console.error(
        "Delete error:",
        error
      );

      res
        .status(500)
        .send(
          "Could not delete project."
        );
    }
  }
);

// ======================================================
// API - LIST WEBSITES
// ======================================================

app.get(
  "/api/websites",
  requireLogin,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          SELECT
            id,
            name,
            slug,
            type,
            title,
            description,
            keywords,
            author,
            created_at,
            updated_at
          FROM websites
          WHERE user_id = $1
          ORDER BY created_at DESC
          `,
          [req.session.userId]
        );

      res.json(
        result.rows
      );

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Could not load websites."
      });
    }
  }
);

// ======================================================
// API - CREATE HTML
// ======================================================

app.post(
  "/api/websites/html",
  requireLogin,
  async (req, res) => {

    try {

      const {
        name,
        html
      } = req.body;

      if (
        !name ||
        !html
      ) {
        return res
          .status(400)
          .json({
            error:
              "Website name and HTML are required."
          });
      }

      if (
        Buffer.byteLength(
          html,
          "utf8"
        ) >
        2 * 1024 * 1024
      ) {
        return res
          .status(400)
          .json({
            error:
              "HTML file is too large. Maximum 2MB."
          });
      }

      const siteName =
        sanitizeSiteName(
          name
        );

      if (!siteName) {
        return res
          .status(400)
          .json({
            error:
              "Invalid website name."
          });
      }

      const folderName =
        makeFolderName(
          siteName
        );

      const targetDir =
        getProjectDir(
          req.session.userId,
          folderName
        );

      await fs.ensureDir(
        targetDir
      );

      await fs.writeFile(
        path.join(
          targetDir,
          "index.html"
        ),
        html,
        "utf8"
      );

      const slug =
        await generateSlug(
          siteName
        );

      const result =
        await pool.query(
          `
          INSERT INTO websites
          (
            user_id,
            name,
            slug,
            type,
            html_content,
            folder_name,
            title,
            description,
            keywords,
            author
          )
          VALUES
          (
            $1,$2,$3,'html',
            $4,$5,$6,$7,$8,$9
          )
          RETURNING
            id,
            name,
            slug,
            type
          `,
          [
            req.session.userId,
            siteName,
            slug,
            html,
            folderName,
            siteName,
            `${siteName} website`,
            siteName,
            req.session.userName ||
              "Website Owner"
          ]
        );

      res.json({
        success:true,

        website:
          result.rows[0],

        url:
          `/site/${slug}/`
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Could not create website."
      });
    }
  }
);

// ======================================================
// API - ZIP CREATE
// ======================================================

app.post(
  "/api/websites/zip",
  requireLogin,
  upload.single("website"),
  async (req, res) => {

    try {

      if (!req.file) {
        return res
          .status(400)
          .json({
            error:
              "ZIP file is required."
          });
      }

      const {
        name
      } = req.body;

      if (!name) {
        return res
          .status(400)
          .json({
            error:
              "Website name is required."
          });
      }

      const buffer =
        await fs.readFile(
          req.file.path
        );

      const zip =
        validateZipBuffer(
          buffer
        );

      const siteName =
        sanitizeSiteName(
          name
        );

      const folderName =
        makeFolderName(
          siteName
        );

      const targetDir =
        getProjectDir(
          req.session.userId,
          folderName
        );

      await fs.ensureDir(
        targetDir
      );

      for (
        const entry
          of zip.getEntries()
      ) {

        if (
          entry.isDirectory
        ) {
          continue;
        }

        const entryName =
          entry.entryName
            .replace(
              /\\/g,
              "/"
            )
            .replace(
              /^\/+/,
              ""
            );

        if (
          entryName
            .split("/")
            .includes("..")
        ) {
          throw new Error(
            "Unsafe ZIP path."
          );
        }

        const output =
          safeJoin(
            targetDir,
            entryName
          );

        await fs.ensureDir(
          path.dirname(
            output
          )
        );

        await fs.writeFile(
          output,
          entry.getData()
        );
      }

      await flattenSingleFolder(
        targetDir
      );

      await ensureIndexHtml(
        targetDir
      );

      const slug =
        await generateSlug(
          siteName
        );

      const result =
        await pool.query(
          `
          INSERT INTO websites
          (
            user_id,
            name,
            slug,
            type,
            zip_data,
            folder_name,
            title,
            description,
            keywords,
            author
          )
          VALUES
          (
            $1,$2,$3,'zip',
            $4,$5,$6,$7,$8,$9
          )
          RETURNING
            id,
            name,
            slug,
            type
          `,
          [
            req.session.userId,
            siteName,
            slug,
            buffer,
            folderName,
            siteName,
            `${siteName} website`,
            siteName,
            req.session.userName ||
              "Website Owner"
          ]
        );

      await fs.remove(
        req.file.path
      );

      res.json({
        success:true,

        website:
          result.rows[0],

        url:
          `/site/${slug}/`
      });

    } catch (error) {

      console.error(error);

      if (req.file) {
        try {
          await fs.remove(
            req.file.path
          );
        } catch {}
      }

      res.status(400).json({
        error:
          error.message ||
          "Could not process ZIP."
      });
    }
  }
);

// ======================================================
// API - GET WEBSITE
// ======================================================

app.get(
  "/api/websites/:id",
  requireLogin,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          SELECT
            id,
            name,
            slug,
            type,
            html_content,
            title,
            description,
            keywords,
            author,
            created_at,
            updated_at
          FROM websites
          WHERE
            id = $1
            AND user_id = $2
          `,
          [
            req.params.id,
            req.session.userId
          ]
        );

      if (
        !result.rows.length
      ) {
        return res
          .status(404)
          .json({
            error:
              "Website not found."
          });
      }

      res.json(
        result.rows[0]
      );

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Could not load website."
      });
    }
  }
);

// ======================================================
// API - UPDATE HTML
// ======================================================

app.put(
  "/api/websites/:id/html",
  requireLogin,
  async (req, res) => {

    try {

      const {
        name,
        html
      } = req.body;

      if (
        !name ||
        !html
      ) {
        return res
          .status(400)
          .json({
            error:
              "Website name and HTML are required."
          });
      }

      if (
        Buffer.byteLength(
          html,
          "utf8"
        ) >
        2 * 1024 * 1024
      ) {
        return res
          .status(400)
          .json({
            error:
              "HTML cannot exceed 2MB."
          });
      }

      const result =
        await pool.query(
          `
          UPDATE websites
          SET
            name = $1,
            html_content = $2,
            updated_at = NOW()
          WHERE
            id = $3
            AND user_id = $4
            AND type = 'html'
          RETURNING
            id,
            name,
            slug,
            type
          `,
          [
            String(name).trim(),
            html,
            req.params.id,
            req.session.userId
          ]
        );

      if (
        !result.rows.length
      ) {
        return res
          .status(404)
          .json({
            error:
              "Website not found."
          });
      }

      const project =
        await pool.query(
          `
          SELECT
            folder_name
          FROM websites
          WHERE id = $1
          `,
          [req.params.id]
        );

      const folderName =
        project.rows[0] &&
        project.rows[0].folder_name;

      if (folderName) {

        const projectDir =
          getProjectDir(
            req.session.userId,
            folderName
          );

        await fs.ensureDir(
          projectDir
        );

        await fs.writeFile(
          path.join(
            projectDir,
            "index.html"
          ),
          html,
          "utf8"
        );
      }

      res.json({
        success:true,

        website:
          result.rows[0]
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Could not update website."
      });
    }
  }
);

// ======================================================
// LIVE SITE
// ======================================================

app.use(
  "/site/:sitename",
  async (req, res, next) => {

    try {

      const requestedSlug =
        sanitizeSiteName(
          req.params.sitename
        );

      if (!requestedSlug) {
        return res
          .status(404)
          .send(
            "404 Not Found"
          );
      }

      const project =
        await findProjectBySlug(
          requestedSlug
        );

      if (!project) {
        return res
          .status(404)
          .send(
            "404 Not Found"
          );
      }

      if (
        !project.folder_name
      ) {

        // ----------------------------------------------
        // Legacy HTML database record
        // ----------------------------------------------

        if (
          project.type ===
          "html" &&
          project.html_content
        ) {

          const meta = {
            title:
              project.title ||
              project.name,

            description:
              project.description ||
              "",

            keywords:
              project.keywords ||
              "",

            author:
              project.author ||
              "Website Owner"
          };

          const liveUrl =
            getProjectUrl(
              req,
              project.slug
            );

          if (
            project.slug !==
            requestedSlug
          ) {
            return res.redirect(
              301,
              `/site/${encodeURIComponent(
                project.slug
              )}/`
            );
          }

          return res
            .type("html")
            .send(
              injectSEO(
                project.html_content,
                meta,
                liveUrl
              )
            );
        }

        return res
          .status(404)
          .send(
            "Website files not found."
          );
      }

      const sitePath =
        getProjectDir(
          project.user_id,
          project.folder_name
        );

      if (
        !fs.existsSync(
          sitePath
        )
      ) {
        return res
          .status(404)
          .send(
            "Website files not found."
          );
      }

      // ------------------------------------------------
      // Old slug redirect
      // ------------------------------------------------

      if (
        project.slug &&
        project.slug !==
          requestedSlug
      ) {

        const suffix =
          req.path === "/"
            ? "/"
            : req.path;

        return res.redirect(
          301,
          `/site/${encodeURIComponent(
            project.slug
          )}${suffix}`
        );
      }

      // ------------------------------------------------
      // Root page
      // ------------------------------------------------

      if (
        req.path === "/" ||
        req.path === ""
      ) {

        let indexFile =
          path.join(
            sitePath,
            "index.html"
          );

        if (
          !fs.existsSync(
            indexFile
          )
        ) {
          indexFile =
            findBestHtml(
              sitePath
            );
        }

        if (!indexFile) {
          return res
            .status(404)
            .send(
              "No HTML found."
            );
        }

        const html =
          await fs.readFile(
            indexFile,
            "utf8"
          );

        const meta = {
          title:
            project.title ||
            project.name,

          description:
            project.description ||
            "",

          keywords:
            project.keywords ||
            "",

          author:
            project.author ||
            "Website Owner"
        };

        const liveUrl =
          getProjectUrl(
            req,
            project.slug ||
              requestedSlug
          );

        return res
          .type("html")
          .send(
            injectSEO(
              html,
              meta,
              liveUrl
            )
          );
      }

      // ------------------------------------------------
      // Nested assets
      // ------------------------------------------------

      const relativePath =
        decodeURIComponent(
          req.path || "/"
        )
          .replace(
            /^\/+/,
            ""
          )
          .replace(
            /\\/g,
            "/"
          );

      if (
        relativePath
          .split("/")
          .includes("..")
      ) {
        return res
          .status(400)
          .send(
            "Invalid path."
          );
      }

      const requestedFile =
        safeJoin(
          sitePath,
          relativePath
        );

      if (
        !fs.existsSync(
          requestedFile
        )
      ) {
        return res
          .status(404)
          .send(
            "File not found."
          );
      }

      const stat =
        await fs.stat(
          requestedFile
        );

      if (!stat.isFile()) {
        return res
          .status(404)
          .send(
            "File not found."
          );
      }

      res.setHeader(
        "Content-Type",
        getMimeType(
          requestedFile
        )
      );

      res.setHeader(
        "Cache-Control",
        "public, max-age=300"
      );

      return res.sendFile(
        requestedFile
      );

    } catch (error) {

      console.error(
        "Live site error:",
        error
      );

      next(error);
    }
  }
);

// ======================================================
// ROBOTS
// ======================================================

app.get(
  "/robots.txt",
  (req, res) => {

    const base =
      `${req.protocol}://${req.get("host")}`;

    res
      .type("text/plain")
      .send(
        `User-agent: *
Allow: /
Sitemap: ${base}/sitemap.xml`
      );
  }
);

// ======================================================
// SITEMAP
// ======================================================

app.get(
  "/sitemap.xml",
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          SELECT slug
          FROM websites
          WHERE slug IS NOT NULL
          ORDER BY id DESC
          `
        );

      const base =
        `${req.protocol}://${req.get("host")}`;

      const urls = [
        `${base}/`
      ];

      for (
        const project
          of result.rows
      ) {

        urls.push(
          `${base}/site/${encodeURIComponent(
            project.slug
          )}/`
        );
      }

      const xmlUrls =
        urls
          .map(
            url =>
              `<url><loc>${escapeHtml(
                url
              )}</loc></url>`
          )
          .join("");

      res
        .type("application/xml")
        .send(
`<?xml version="1.0" encoding="UTF-8"?>
<urlset
 xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
>
${xmlUrls}
</urlset>`
        );

    } catch (error) {

      console.error(
        "Sitemap error:",
        error
      );

      res
        .status(500)
        .send(
          "Could not generate sitemap."
        );
    }
  }
);

// ======================================================
// SELF PING
// ======================================================

function startSelfPing() {

  const PING_INTERVAL =
    2.5 * 60 * 1000;

  setInterval(
    () => {

      const appUrl =
        process.env.RENDER_EXTERNAL_URL ||
        `http://127.0.0.1:${PORT}/`;

      const client =
        appUrl.startsWith(
          "https"
        )
          ? https
          : http;

      client
        .get(
          appUrl,
          () => {}
        )
        .on(
          "error",
          () => {}
        );

    },
    PING_INTERVAL
  );
}

// ======================================================
// ERROR HANDLER
// ======================================================

app.use(
  (err, req, res, next) => {

    console.error(
      "Server error:",
      err
    );

    if (
      err instanceof
      multer.MulterError
    ) {

      return res
        .status(400)
        .json({
          error:
            `Upload error: ${err.message}`
        });
    }

    if (
      err.message ===
      "Unsupported file type."
    ) {

      return res
        .status(400)
        .json({
          error:
            err.message
        });
    }

    if (
      res.headersSent
    ) {
      return next(err);
    }

    res
      .status(500)
      .send(
        err.message ||
          "Internal server error."
      );
  }
);

// ======================================================
// START
// ======================================================

initDatabase()
  .then(
    () => {

      app.listen(
        PORT,
        "0.0.0.0",
        () => {

          console.log(
            `🚀 Personal Website Hosting running on port ${PORT}`
          );

          console.log(
            `📁 Data directory: ${DATA_DIR}`
          );

          startSelfPing();
        }
      );

    }
  )
  .catch(
    error => {

      console.error(
        "Database initialization failed:",
        error
      );

      process.exit(1);
    }
  );
