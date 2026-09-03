const express = require("express");
const multer = require("multer");
const fs = require("fs-extra");
const path = require("path");
const crypto = require("crypto");
const AdmZip = require("adm-zip");

const app = express();
const PORT = process.env.PORT || 3000;

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, "public");
const SITES_DIR = path.join(ROOT, "sites");
const TMP_DIR = path.join(ROOT, "tmp");
const DB_FILE = path.join(ROOT, "sites.json");

const ADMIN_PASSWORD =
  process.env.ADMIN_PASSWORD || "CHANGE_THIS_PASSWORD";

const SESSION_SECRET =
  process.env.SESSION_SECRET || "CHANGE_THIS_SESSION_SECRET";

const MAX_UPLOAD_SIZE = 25 * 1024 * 1024;

fs.ensureDirSync(PUBLIC_DIR);
fs.ensureDirSync(SITES_DIR);
fs.ensureDirSync(TMP_DIR);

if (!fs.existsSync(DB_FILE)) {
  fs.writeJsonSync(DB_FILE, [], { spaces: 2 });
}

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

const upload = multer({
  dest: TMP_DIR,
  limits: {
    fileSize: MAX_UPLOAD_SIZE
  }
});

/* =========================================================
   DATABASE
========================================================= */

function getSites() {
  try {
    return fs.readJsonSync(DB_FILE);
  } catch {
    return [];
  }
}

function saveSites(sites) {
  fs.writeJsonSync(DB_FILE, sites, { spaces: 2 });
}

/* =========================================================
   AUTH
========================================================= */

function createToken() {
  return crypto
    .createHmac("sha256", SESSION_SECRET)
    .update("TM_WEB_HOSTING_AUTH")
    .digest("hex");
}

function isAuthenticated(req) {
  const cookie = req.headers.cookie || "";

  const match = cookie
    .split(";")
    .map(v => v.trim())
    .find(v => v.startsWith("tm_auth="));

  if (!match) return false;

  const token = match.substring("tm_auth=".length);

  return token === createToken();
}

function requireAuth(req, res, next) {
  if (!isAuthenticated(req)) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized"
    });
  }

  next();
}

/* =========================================================
   AUTH API
========================================================= */

app.post("/api/auth/login", (req, res) => {
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({
      success: false,
      message: "Password required"
    });
  }

  if (password !== ADMIN_PASSWORD) {
    return res.status(401).json({
      success: false,
      message: "Wrong password"
    });
  }

  res.setHeader(
    "Set-Cookie",
    `tm_auth=${createToken()}; HttpOnly; Path=/; SameSite=Lax; Max-Age=604800`
  );

  res.json({
    success: true
  });
});

app.post("/api/auth/logout", (req, res) => {
  res.setHeader(
    "Set-Cookie",
    "tm_auth=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0"
  );

  res.json({
    success: true
  });
});

app.get("/api/auth/me", (req, res) => {
  res.json({
    authenticated: isAuthenticated(req)
  });
});

/* =========================================================
   DASHBOARD
========================================================= */

app.get("/", (req, res) => {
  if (!isAuthenticated(req)) {
    return res.sendFile(path.join(PUBLIC_DIR, "login.html"));
  }

  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

/* =========================================================
   SITE HELPERS
========================================================= */

function generateId() {
  return crypto.randomBytes(8).toString("hex");
}

function cleanSlug(value) {
  return String(value || "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9-_]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .substring(0, 60);
}

function slugExists(slug, ignoreId = null) {
  return getSites().some(
    site => site.slug === slug && site.id !== ignoreId
  );
}

function uniqueSlug(base, ignoreId = null) {
  let slug = cleanSlug(base) || "website";
  let original = slug;
  let counter = 1;

  while (slugExists(slug, ignoreId)) {
    slug = `${original}-${counter}`;
    counter++;
  }

  return slug;
}

function findIndexHtml(dir) {
  const direct = path.join(dir, "index.html");

  if (fs.existsSync(direct)) {
    return direct;
  }

  const entries = fs.readdirSync(dir, {
    withFileTypes: true
  });

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;

    const candidate = path.join(dir, entry.name, "index.html");

    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  return null;
}

function copyDirectoryContents(source, destination) {
  fs.ensureDirSync(destination);

  for (const item of fs.readdirSync(source, {
    withFileTypes: true
  })) {
    const src = path.join(source, item.name);
    const dest = path.join(destination, item.name);

    if (item.isDirectory()) {
      fs.copySync(src, dest);
    } else {
      fs.copyFileSync(src, dest);
    }
  }
}

/* =========================================================
   GET WEBSITES
========================================================= */

app.get("/api/sites", requireAuth, (req, res) => {
  const sites = getSites();

  const result = sites.map(site => ({
    id: site.id,
    name: site.name,
    slug: site.slug,
    url: `/site/${site.slug}`,
    createdAt: site.createdAt,
    updatedAt: site.updatedAt,
    type: site.type
  }));

  res.json({
    success: true,
    sites: result
  });
});

/* =========================================================
   CREATE WEBSITE
========================================================= */

app.post(
  "/api/sites",
  requireAuth,
  upload.single("website"),
  async (req, res) => {
    let uploadedFile = null;

    try {
      const name = String(req.body.name || "").trim();
      const requestedSlug = String(req.body.slug || "").trim();
      const htmlCode = String(req.body.htmlCode || "").trim();

      uploadedFile = req.file;

      if (!name) {
        return res.status(400).json({
          success: false,
          message: "Website name is required"
        });
      }

      if (!htmlCode && !uploadedFile) {
        return res.status(400).json({
          success: false,
          message: "HTML code or ZIP file is required"
        });
      }

      if (htmlCode && uploadedFile) {
        return res.status(400).json({
          success: false,
          message: "Use either HTML code or ZIP upload, not both"
        });
      }

      const id = generateId();
      const slug = uniqueSlug(requestedSlug || name);

      const siteDir = path.join(SITES_DIR, id);

      await fs.ensureDir(siteDir);

      if (htmlCode) {
        await fs.writeFile(
          path.join(siteDir, "index.html"),
          htmlCode,
          "utf8"
        );
      }

      if (uploadedFile) {
        const zip = new AdmZip(uploadedFile.path);

        const tempExtract = path.join(
          TMP_DIR,
          `extract-${id}`
        );

        await fs.ensureDir(tempExtract);

        zip.extractAllTo(tempExtract, true);

        const indexFile = findIndexHtml(tempExtract);

        if (!indexFile) {
          await fs.remove(siteDir);
          await fs.remove(tempExtract);

          return res.status(400).json({
            success: false,
            message: "ZIP file must contain index.html"
          });
        }

        const rootFolder = path.dirname(indexFile);

        copyDirectoryContents(rootFolder, siteDir);

        await fs.remove(tempExtract);
      }

      const now = new Date().toISOString();

      const site = {
        id,
        name,
        slug,
        type: htmlCode ? "html" : "zip",
        createdAt: now,
        updatedAt: now
      };

      const sites = getSites();

      sites.unshift(site);

      saveSites(sites);

      res.json({
        success: true,
        message: "Website published successfully",
        site: {
          ...site,
          url: `/site/${slug}`
        }
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message: "Failed to publish website"
      });
    } finally {
      if (uploadedFile?.path) {
        await fs.remove(uploadedFile.path).catch(() => {});
      }
    }
  }
);

/* =========================================================
   GET SINGLE WEBSITE
========================================================= */

app.get("/api/sites/:id", requireAuth, (req, res) => {
  const sites = getSites();

  const site = sites.find(
    item => item.id === req.params.id
  );

  if (!site) {
    return res.status(404).json({
      success: false,
      message: "Website not found"
    });
  }

  const siteDir = path.join(SITES_DIR, site.id);
  const indexFile = path.join(siteDir, "index.html");

  let html = "";

  if (fs.existsSync(indexFile)) {
    html = fs.readFileSync(indexFile, "utf8");
  }

  res.json({
    success: true,
    site: {
      ...site,
      htmlCode: html
    }
  });
});

/* =========================================================
   UPDATE WEBSITE
========================================================= */

app.put(
  "/api/sites/:id",
  requireAuth,
  upload.single("website"),
  async (req, res) => {
    let uploadedFile = null;

    try {
      const sites = getSites();

      const index = sites.findIndex(
        site => site.id === req.params.id
      );

      if (index === -1) {
        return res.status(404).json({
          success: false,
          message: "Website not found"
        });
      }

      const site = sites[index];

      const name =
        String(req.body.name || site.name).trim();

      const requestedSlug =
        String(req.body.slug || site.slug).trim();

      const htmlCode =
        String(req.body.htmlCode || "").trim();

      uploadedFile = req.file;

      if (htmlCode && uploadedFile) {
        return res.status(400).json({
          success: false,
          message: "Use either HTML code or ZIP upload"
        });
      }

      if (!htmlCode && !uploadedFile) {
        return res.status(400).json({
          success: false,
          message: "HTML code or ZIP file is required"
        });
      }

      const newSlug = uniqueSlug(
        requestedSlug || site.slug,
        site.id
      );

      const siteDir = path.join(SITES_DIR, site.id);

      await fs.remove(siteDir);
      await fs.ensureDir(siteDir);

      if (htmlCode) {
        await fs.writeFile(
          path.join(siteDir, "index.html"),
          htmlCode,
          "utf8"
        );

        site.type = "html";
      }

      if (uploadedFile) {
        const zip = new AdmZip(uploadedFile.path);

        const tempExtract = path.join(
          TMP_DIR,
          `update-${site.id}`
        );

        await fs.ensureDir(tempExtract);

        zip.extractAllTo(tempExtract, true);

        const indexFile = findIndexHtml(tempExtract);

        if (!indexFile) {
          await fs.remove(tempExtract);

          return res.status(400).json({
            success: false,
            message: "ZIP file must contain index.html"
          });
        }

        const rootFolder = path.dirname(indexFile);

        copyDirectoryContents(rootFolder, siteDir);

        await fs.remove(tempExtract);

        site.type = "zip";
      }

      site.name = name;
      site.slug = newSlug;
      site.updatedAt = new Date().toISOString();

      sites[index] = site;

      saveSites(sites);

      res.json({
        success: true,
        message: "Website updated successfully",
        site: {
          ...site,
          url: `/site/${site.slug}`
        }
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message: "Failed to update website"
      });
    } finally {
      if (uploadedFile?.path) {
        await fs.remove(uploadedFile.path).catch(() => {});
      }
    }
  }
);

/* =========================================================
   DELETE WEBSITE
========================================================= */

app.delete("/api/sites/:id", requireAuth, async (req, res) => {
  try {
    const sites = getSites();

    const index = sites.findIndex(
      site => site.id === req.params.id
    );

    if (index === -1) {
      return res.status(404).json({
        success: false,
        message: "Website not found"
      });
    }

    const site = sites[index];

    const siteDir = path.join(SITES_DIR, site.id);

    await fs.remove(siteDir);

    sites.splice(index, 1);

    saveSites(sites);

    res.json({
      success: true,
      message: "Website deleted successfully"
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Failed to delete website"
    });
  }
});

/* =========================================================
   PUBLIC WEBSITE HOSTING
========================================================= */

app.get("/site/:slug", serveWebsite);
app.get("/site/:slug/*splat", serveWebsite);

function serveWebsite(req, res) {
  const slug = req.params.slug;

  const sites = getSites();

  const site = sites.find(
    item => item.slug === slug
  );

  if (!site) {
    return res.status(404).send(`
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Website Not Found</title>
        <style>
          body{
            margin:0;
            background:#08090d;
            color:#fff;
            font-family:Arial,sans-serif;
            display:flex;
            align-items:center;
            justify-content:center;
            min-height:100vh;
            text-align:center;
          }
          h1{font-size:42px}
          p{color:#aaa}
        </style>
      </head>
      <body>
        <div>
          <h1>404</h1>
          <p>Website not found.</p>
        </div>
      </body>
      </html>
    `);
  }

  const siteDir = path.join(SITES_DIR, site.id);

  let requestedPath = req.path;

  const prefix = `/site/${slug}`;

  if (requestedPath.startsWith(prefix)) {
    requestedPath = requestedPath.substring(prefix.length);
  }

  if (!requestedPath || requestedPath === "/") {
    requestedPath = "/index.html";
  }

  const cleanPath = path
    .normalize(requestedPath)
    .replace(/^(\.\.(\/|\\|$))+/, "");

  const filePath = path.join(
    siteDir,
    cleanPath
  );

  if (
    !filePath.startsWith(
      path.resolve(siteDir)
    )
  ) {
    return res.status(403).send("Forbidden");
  }

  if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
    return res.sendFile(filePath);
  }

  const indexFile = path.join(
    siteDir,
    "index.html"
  );

  if (fs.existsSync(indexFile)) {
    return res.sendFile(indexFile);
  }

  res.status(404).send("File not found");
}

/* =========================================================
   STATIC DASHBOARD FILES
========================================================= */

app.use(express.static(PUBLIC_DIR));

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use((err, req, res, next) => {
  console.error(err);

  if (err.code === "LIMIT_FILE_SIZE") {
    return res.status(400).json({
      success: false,
      message: "ZIP file is too large. Maximum 25MB."
    });
  }

  res.status(500).json({
    success: false,
    message: "Internal server error"
  });
});

/* =========================================================
   START SERVER
========================================================= */

app.listen(PORT, () => {
  console.log(
    `TM Web Hosting running on port ${PORT}`
  );
});
