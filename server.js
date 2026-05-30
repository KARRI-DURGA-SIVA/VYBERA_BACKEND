const express = require("express");
const path = require("path");
const fs = require("fs");
const { Pool } = require("pg");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
require("dotenv").config({ path: path.join(__dirname, ".env") });

const app = express();
const appHtmlPath = path.join(__dirname, "..", "vybera_26.html");
const uploadsDir = path.join(__dirname, "uploads");
fs.mkdirSync(uploadsDir, { recursive: true });

app.use(cors());
app.use(bodyParser.json({ limit: "30mb" }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname)));
app.use("/VYBERA", express.static(path.join(__dirname)));
app.use("/uploads", express.static(uploadsDir));

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is missing. Add it to VYBERA/.env before starting the server.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("localhost")
    ? false
    : { rejectUnauthorized: false },
});

const r2Config = {
  endpoint: process.env.R2_ENDPOINT,
  bucket: process.env.R2_BUCKET,
  accessKeyId: process.env.R2_ACCESS_KEY_ID,
  secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
};

const hasR2Config = () =>
  r2Config.endpoint &&
  r2Config.bucket &&
  r2Config.accessKeyId &&
  r2Config.secretAccessKey;

const hmac = (key, value, encoding) =>
  crypto.createHmac("sha256", key).update(value).digest(encoding);

const sha256 = (value) =>
  crypto.createHash("sha256").update(value).digest("hex");

const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret) {
  console.error("JWT_SECRET is missing. Add it to VYBERA/.env before starting the server.");
  process.exit(1);
}
const base64Url = (value) =>
  Buffer.from(value).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
const base64UrlJson = (value) => base64Url(JSON.stringify(value));
const signJwt = (payload, expiresInSeconds = 60 * 60 * 24 * 30) => {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "HS256", typ: "JWT" };
  const body = { ...payload, iat: now, exp: now + expiresInSeconds };
  const unsigned = `${base64UrlJson(header)}.${base64UrlJson(body)}`;
  const signature = crypto.createHmac("sha256", jwtSecret).update(unsigned).digest("base64url");
  return `${unsigned}.${signature}`;
};
const verifyJwt = (token) => {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) throw new Error("Invalid token");
  const unsigned = `${parts[0]}.${parts[1]}`;
  const expected = crypto.createHmac("sha256", jwtSecret).update(unsigned).digest("base64url");
  const actual = Buffer.from(parts[2]);
  const wanted = Buffer.from(expected);
  if (actual.length !== wanted.length || !crypto.timingSafeEqual(actual, wanted)) {
    throw new Error("Invalid token signature");
  }
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) {
    throw new Error("Token expired");
  }
  return payload;
};
const publicUser = (user) => ({
  id: user.id,
  username: user.username,
  firstName: user.first_name,
  lastName: user.last_name,
  email: user.email,
  phone: user.phone,
  countryCode: user.country_code,
  city: user.city,
  profileImage: user.profile_image_url,
  profileImageKey: user.profile_image_key,
  profileImageStorage: user.profile_image_storage,
});

const getSigningKey = (secret, dateStamp) => {
  const kDate = hmac(`AWS4${secret}`, dateStamp);
  const kRegion = hmac(kDate, "auto");
  const kService = hmac(kRegion, "s3");
  return hmac(kService, "aws4_request");
};

const encodeR2Key = (key) =>
  key.split("/").map((part) => encodeURIComponent(part)).join("/");

const cleanFileName = (name) =>
  String(name || "upload")
    .replace(/[^a-zA-Z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80) || "upload";

const makeObjectKey = (folder, fileName) => {
  const safeFolder = String(folder || "misc").replace(/[^a-zA-Z0-9/_-]+/g, "-");
  const safeName = cleanFileName(fileName);
  return `${safeFolder}/${Date.now()}-${crypto.randomBytes(6).toString("hex")}-${safeName}`;
};

const presignR2 = ({ method, key, expires = 900 }) => {
  if (!hasR2Config()) {
    throw new Error("Cloudflare R2 is not configured");
  }

  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);
  const scope = `${dateStamp}/auto/s3/aws4_request`;
  const endpoint = new URL(r2Config.endpoint);
  const canonicalUri = `/${r2Config.bucket}/${encodeR2Key(key)}`;
  const credential = `${r2Config.accessKeyId}/${scope}`;
  const query = {
    "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
    "X-Amz-Credential": credential,
    "X-Amz-Date": amzDate,
    "X-Amz-Expires": String(expires),
    "X-Amz-SignedHeaders": "host",
  };
  const canonicalQuery = Object.keys(query)
    .sort()
    .map((name) => `${encodeURIComponent(name)}=${encodeURIComponent(query[name])}`)
    .join("&");
  const canonicalHeaders = `host:${endpoint.host}\n`;
  const canonicalRequest = [
    method,
    canonicalUri,
    canonicalQuery,
    canonicalHeaders,
    "host",
    "UNSIGNED-PAYLOAD",
  ].join("\n");
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    scope,
    sha256(canonicalRequest),
  ].join("\n");
  const signature = hmac(getSigningKey(r2Config.secretAccessKey, dateStamp), stringToSign, "hex");

  return `${endpoint.origin}${canonicalUri}?${canonicalQuery}&X-Amz-Signature=${signature}`;
};

const parseDataUrl = (dataUrl) => {
  const match = String(dataUrl || "").match(/^data:([^;]+);base64,(.+)$/);
  if (!match) {
    throw new Error("Invalid data URL");
  }
  return { contentType: match[1], buffer: Buffer.from(match[2], "base64") };
};

const saveLocalBuffer = ({ key, buffer, contentType }) => {
  const localKey = key.replace(/^\/+/, "");
  const filePath = path.join(uploadsDir, localKey);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, buffer);
  return {
    key: `local/${localKey}`,
    mediaUrl: `/uploads/${localKey}`,
    contentType,
    storage: "local",
  };
};

const uploadBufferToR2 = async ({ key, buffer, contentType }) => {
  const uploadUrl = presignR2({ method: "PUT", key });
  const response = await fetch(uploadUrl, {
    method: "PUT",
    headers: { "Content-Type": contentType || "application/octet-stream" },
    body: buffer,
  });
  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new Error(`R2 upload failed (${response.status}): ${body || response.statusText}`);
  }
  return {
    key,
    mediaUrl: `/r2/media/${encodeR2Key(key)}`,
    contentType,
    storage: "r2",
  };
};

const saveAsset = async ({ fileName, folder, dataUrl, requireR2 = false }) => {
  const parsed = parseDataUrl(dataUrl);
  const key = makeObjectKey(folder, fileName);
  try {
    return await uploadBufferToR2({ key, buffer: parsed.buffer, contentType: parsed.contentType });
  } catch (err) {
    console.error("R2 asset upload failed:", err.message);
    if (requireR2) {
      throw err;
    }
    const localName = key;
    const saved = saveLocalBuffer({ key: localName, buffer: parsed.buffer, contentType: parsed.contentType });
    saved.r2Error = err.message;
    return saved;
  }
};

const cleanPathSegment = (value, fallback) =>
  String(value || fallback || "user")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80) || fallback || "user";

const initDb = async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS first_name TEXT,
      ADD COLUMN IF NOT EXISTS last_name TEXT,
      ADD COLUMN IF NOT EXISTS phone TEXT,
      ADD COLUMN IF NOT EXISTS country_code TEXT,
      ADD COLUMN IF NOT EXISTS city TEXT,
      ADD COLUMN IF NOT EXISTS profile_image_url TEXT,
      ADD COLUMN IF NOT EXISTS profile_image_key TEXT,
      ADD COLUMN IF NOT EXISTS profile_image_storage TEXT,
      ADD COLUMN IF NOT EXISTS auth_provider TEXT DEFAULT 'email'
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS bookings (
      id TEXT PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      buyer_email TEXT,
      event_id TEXT,
      event_name TEXT,
      event_date TEXT,
      event_venue TEXT,
      event_banner TEXT,
      ticket_type TEXT,
      price NUMERIC,
      qty INTEGER,
      total NUMERIC,
      status TEXT DEFAULT 'upcoming',
      ticket_record_url TEXT,
      ticket_record_key TEXT,
      ticket_record_storage TEXT,
      booked_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
};

initDb().catch((err) => {
  console.error("Database initialization failed:", err);
  process.exit(1);
});


// OPEN HTML PAGE
app.get("/", (req, res) => {

  res.sendFile(appHtmlPath);

});

app.get("/vybera_26.html", (req, res) => {
  res.sendFile(appHtmlPath);
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, database: "connected", r2: hasR2Config() ? "configured" : "missing" });
  } catch (err) {
    res.status(500).json({ ok: false, database: "error", error: err.message });
  }
});

app.post("/r2/upload-url", (req, res) => {
  try {
    const { fileName, contentType, folder } = req.body || {};
    if (!fileName) {
      return res.status(400).json({ error: "fileName is required" });
    }
    const key = makeObjectKey(folder, fileName);
    res.json({
      key,
      uploadUrl: presignR2({ method: "PUT", key }),
      mediaUrl: `/r2/media/${encodeR2Key(key)}`,
      contentType: contentType || "application/octet-stream",
    });
  } catch (err) {
    console.error("R2 upload URL failed:", err);
    res.status(500).json({ error: err.message || "R2 upload URL failed" });
  }
});

app.post("/local-upload", (req, res) => {
  try {
    const { fileName, folder, dataUrl } = req.body || {};
    if (!fileName || !dataUrl) {
      return res.status(400).json({ error: "fileName and dataUrl are required" });
    }
    const match = String(dataUrl).match(/^data:([^;]+);base64,(.+)$/);
    if (!match) {
      return res.status(400).json({ error: "Invalid data URL" });
    }
    const safeFolder = String(folder || "misc").replace(/[^a-zA-Z0-9/_-]+/g, "-");
    const dir = path.join(uploadsDir, safeFolder);
    fs.mkdirSync(dir, { recursive: true });
    const safeName = `${Date.now()}-${crypto.randomBytes(6).toString("hex")}-${cleanFileName(fileName)}`;
    const filePath = path.join(dir, safeName);
    fs.writeFileSync(filePath, Buffer.from(match[2], "base64"));
    res.json({
      key: `local/${safeFolder}/${safeName}`,
      mediaUrl: `/uploads/${safeFolder}/${safeName}`,
      contentType: match[1],
      storage: "local",
    });
  } catch (err) {
    console.error("Local upload failed:", err);
    res.status(500).json({ error: err.message || "Local upload failed" });
  }
});

app.post("/assets/upload", async (req, res) => {
  try {
    const {
      fileName,
      folder,
      dataUrl,
      purpose,
      userId,
      email,
    } = req.body || {};
    if (!fileName || !dataUrl) {
      return res.status(400).json({ error: "fileName and dataUrl are required" });
    }

    const isProfileUpload = purpose === "profile";
    const cleanEmail = String(email || "").trim().toLowerCase();
    const cleanUserId = userId ? Number(userId) : null;
    if (isProfileUpload && !cleanUserId && !cleanEmail) {
      return res.status(401).json({ error: "Login is required before uploading a profile image" });
    }

    const uploadFolder = isProfileUpload
      ? `profiles/${cleanUserId ? `user-${cleanUserId}` : cleanPathSegment(cleanEmail, "email-user")}`
      : (folder || "misc");
    const asset = await saveAsset({
      fileName,
      folder: uploadFolder,
      dataUrl,
      requireR2: isProfileUpload,
    });

    if (isProfileUpload) {
      let updateResult;
      if (cleanUserId) {
        updateResult = await pool.query(
          `UPDATE users
           SET profile_image_url=$1, profile_image_key=$2, profile_image_storage=$3
           WHERE id=$4`,
          [asset.mediaUrl, asset.key, asset.storage, cleanUserId]
        );
      } else {
        updateResult = await pool.query(
          `UPDATE users
           SET profile_image_url=$1, profile_image_key=$2, profile_image_storage=$3
           WHERE email=$4`,
          [asset.mediaUrl, asset.key, asset.storage, cleanEmail]
        );
      }

      if (!updateResult || updateResult.rowCount < 1) {
        return res.status(404).json({ error: "Profile user was not found for this upload" });
      }
    }

    res.json(asset);
  } catch (err) {
    console.error("Asset upload failed:", err);
    res.status(500).json({ error: err.message || "Asset upload failed" });
  }
});

app.get("/r2/media/*key", (req, res) => {
  try {
    const key = Array.isArray(req.params.key) ? req.params.key.join("/") : req.params.key;
    if (!key) {
      return res.status(404).send("Not found");
    }
    res.redirect(presignR2({ method: "GET", key, expires: 300 }));
  } catch (err) {
    console.error("R2 media redirect failed:", err);
    res.status(500).send("Media unavailable");
  }
});

app.post("/r2/ticket-record", async (req, res) => {
  try {
    const booking = req.body || {};
    if (!booking.id) {
      return res.status(400).json({ error: "booking.id is required" });
    }
    const ticketJson = `data:application/json;base64,${Buffer.from(JSON.stringify({
      booking,
      storedAt: new Date().toISOString(),
    })).toString("base64")}`;
    const saved = await saveAsset({
      fileName: `${booking.id}.json`,
      folder: "tickets",
      dataUrl: ticketJson,
    });
    res.json(saved);
  } catch (err) {
    console.error("Ticket record upload failed:", err);
    res.status(500).json({ error: err.message || "Ticket record upload failed" });
  }
});

const payuConfig = {
  key: process.env.PAYU_KEY,
  salt: process.env.PAYU_SALT,
  action:
    (process.env.PAYU_ENV || "test").toLowerCase() === "production"
      ? "https://secure.payu.in/_payment"
      : "https://test.payu.in/_payment",
};

const formatPayuAmount = (amount) => Number(amount || 0).toFixed(2);
const cleanPayuText = (value, maxLength) =>
  String(value || "")
    .replace(/[^a-zA-Z0-9 .,_-]/g, "")
    .trim()
    .slice(0, maxLength);
const makePayuHash = (fields) => {
  const hashString = [
    fields.key,
    fields.txnid,
    fields.amount,
    fields.productinfo,
    fields.firstname,
    fields.email,
    fields.udf1 || "",
    fields.udf2 || "",
    fields.udf3 || "",
    fields.udf4 || "",
    fields.udf5 || "",
    "",
    "",
    "",
    "",
    "",
    payuConfig.salt,
  ].join("|");
  return crypto.createHash("sha512").update(hashString).digest("hex");
};
const makePayuResponseHash = (fields) => {
  const hashString = [
    payuConfig.salt,
    fields.status || "",
    "",
    "",
    "",
    "",
    "",
    fields.udf5 || "",
    fields.udf4 || "",
    fields.udf3 || "",
    fields.udf2 || "",
    fields.udf1 || "",
    fields.email || "",
    fields.firstname || "",
    fields.productinfo || "",
    fields.amount || "",
    fields.txnid || "",
    fields.key || "",
  ].join("|");
  return crypto.createHash("sha512").update(hashString).digest("hex");
};

const payuReturnHtml = (result) => `<!doctype html>
<html><head><meta charset="utf-8"><title>VYBERA Payment</title></head>
<body style="background:#000;color:#fff;font-family:Arial,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;">
<div>Completing payment...</div>
<script>
localStorage.setItem('VYBERA_PAYU_RESULT', ${JSON.stringify(JSON.stringify(result))});
window.location.href = '/';
</script>
</body></html>`;

app.post("/payments/payu/initiate", (req, res) => {
  try {
    if (!payuConfig.key || !payuConfig.salt) {
      return res.status(500).json({ error: "PAYU_KEY and PAYU_SALT must be configured" });
    }

    const amount = Number(req.body && req.body.amount);
    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ error: "Valid amount in rupees is required" });
    }

    const origin = `${req.protocol}://${req.get("host")}`;
    const txnid = String(req.body.txnid || `VYB${Date.now()}${crypto.randomBytes(3).toString("hex")}`).slice(0, 40);
    const fields = {
      key: payuConfig.key,
      txnid,
      amount: formatPayuAmount(amount),
      productinfo: cleanPayuText(req.body.productinfo || "VYBERA Event Booking", 100) || "VYBERA Event Booking",
      firstname: cleanPayuText(req.body.firstname || "VYBERA Guest", 60) || "VYBERA Guest",
      email: String(req.body.email || "guest@vybera.in").slice(0, 100),
      phone: String(req.body.phone || "9999999999").replace(/\D/g, "").slice(-10) || "9999999999",
      surl: `${origin}/payments/payu/success`,
      furl: `${origin}/payments/payu/failure`,
      udf1: cleanPayuText(req.body.bookingId || "", 64),
      udf2: cleanPayuText(req.body.eventId || "", 64),
      udf3: cleanPayuText(req.body.ticketType || "", 64),
      udf4: cleanPayuText(req.body.qty || "", 20),
      udf5: "vybera",
      service_provider: "payu_paisa",
    };
    fields.hash = makePayuHash(fields);
    res.json({ action: payuConfig.action, fields });
  } catch (err) {
    console.error("PayU initiation failed:", err);
    res.status(500).json({ error: err.message || "PayU initiation failed" });
  }
});

app.post("/payments/payu/success", (req, res) => {
  try {
    const body = req.body || {};
    const expected = makePayuResponseHash(body);
    const verified = Boolean(body.hash) && expected === body.hash;
    res.send(payuReturnHtml({
      verified,
      status: body.status || "success",
      txnid: body.txnid || "",
      mihpayid: body.mihpayid || "",
      bookingId: body.udf1 || "",
      eventId: body.udf2 || "",
      ticketType: body.udf3 || "",
      qty: body.udf4 || "",
      amount: body.amount || "",
      error: verified ? "" : "Payment signature could not be verified",
    }));
  } catch (err) {
    console.error("PayU success handling failed:", err);
    res.send(payuReturnHtml({ verified: false, status: "error", error: err.message || "PayU success handling failed" }));
  }
});

app.post("/payments/payu/failure", (req, res) => {
  try {
    const body = req.body || {};
    let verified = false;
    if (body.hash && payuConfig.salt) {
      verified = makePayuResponseHash(body) === body.hash;
    }
    res.send(payuReturnHtml({
      verified,
      status: body.status || "failed",
      txnid: body.txnid || "",
      mihpayid: body.mihpayid || "",
      bookingId: body.udf1 || "",
      eventId: body.udf2 || "",
      ticketType: body.udf3 || "",
      qty: body.udf4 || "",
      amount: body.amount || "",
      error: body.error_Message || body.error || "Payment failed",
    }));
  } catch (err) {
    console.error("PayU failure handling failed:", err);
    res.send(payuReturnHtml({ verified: false, status: "error", error: err.message || "PayU failure handling failed" }));
  }
});

app.post("/bookings", async (req, res) => {
  try {
    const booking = req.body || {};
    if (!booking.id) {
      return res.status(400).json({ error: "booking.id is required" });
    }

    const ticketJson = `data:application/json;base64,${Buffer.from(JSON.stringify({
      booking,
      storedAt: new Date().toISOString(),
    })).toString("base64")}`;
    const ticketRecord = await saveAsset({
      fileName: `${booking.id}.json`,
      folder: "tickets",
      dataUrl: ticketJson,
    });

    await pool.query(
      `INSERT INTO bookings (
        id, user_id, buyer_email, event_id, event_name, event_date, event_venue,
        event_banner, ticket_type, price, qty, total, status,
        ticket_record_url, ticket_record_key, ticket_record_storage, booked_at
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
      ON CONFLICT (id) DO UPDATE SET
        ticket_record_url=EXCLUDED.ticket_record_url,
        ticket_record_key=EXCLUDED.ticket_record_key,
        ticket_record_storage=EXCLUDED.ticket_record_storage`,
      [
        booking.id,
        booking.userId || null,
        booking.buyerEmail || null,
        booking.eventId || null,
        booking.eventName || null,
        booking.eventDate || null,
        booking.eventVenue || null,
        booking.eventBanner || null,
        booking.ticketType || null,
        booking.price || 0,
        booking.qty || 1,
        booking.total || 0,
        booking.status || "upcoming",
        ticketRecord.mediaUrl,
        ticketRecord.key,
        ticketRecord.storage,
        booking.bookedAt ? new Date(booking.bookedAt) : new Date(),
      ]
    );

    res.json({ booking: { ...booking, ticketRecordUrl: ticketRecord.mediaUrl, r2Key: ticketRecord.key, storage: ticketRecord.storage } });
  } catch (err) {
    console.error("Booking save failed:", err);
    res.status(500).json({ error: err.message || "Booking save failed" });
  }
});


const verifyMsg91AccessToken = async (accessToken) => {
  if (!process.env.MSG91_AUTHKEY) {
    throw new Error("MSG91_AUTHKEY is not configured");
  }
  const response = await fetch("https://control.msg91.com/api/v5/widget/verifyAccessToken", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      authkey: process.env.MSG91_AUTHKEY,
      "access-token": accessToken,
    }),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const msg = data.message || data.error || data.error_message || "MSG91 token verification failed";
    const err = new Error(msg);
    err.status = response.status;
    throw err;
  }
  if (String(data.type || "").toLowerCase() === "error" || data.error || data.error_message) {
    const err = new Error(data.message || data.error || data.error_message || "MSG91 token verification failed");
    err.status = 400;
    throw err;
  }
  return data;
};

const msg91ErrorMessage = (data, fallback) => {
  if (!data || typeof data !== "object") return fallback;
  return data.message || data.error || data.error_message || data.description || fallback;
};
const assertMsg91Success = (response, data, fallback) => {
  if (!response.ok || String(data.type || "").toLowerCase() === "error" || data.error || data.error_message) {
    const err = new Error(msg91ErrorMessage(data, fallback));
    err.status = response.ok ? 400 : response.status;
    throw err;
  }
};

const makeSignupOtpToken = (identifier) =>
  signJwt({ scope: "signup-phone-otp", identifier }, 10 * 60);

const verifySignupOtpToken = async (token, countryCode, phone) => {
  const identifier = `${String(countryCode || "+91").replace(/\D/g, "")}${String(phone || "").replace(/\D/g, "")}`;
  try {
    const payload = verifyJwt(token);
    if (payload.scope !== "signup-phone-otp" || payload.identifier !== identifier) {
      throw new Error("OTP verification does not match this phone number");
    }
    return payload;
  } catch (err) {
    if (String(token || "").split(".").length === 3 && err.message !== "Invalid token signature") {
      throw err;
    }
    await verifyMsg91AccessToken(token);
    return { scope: "msg91-widget-otp", identifier };
  }
};

app.post("/otp/msg91/send", async (req, res) => {
  try {
    if (!process.env.MSG91_AUTHKEY) {
      return res.status(500).json({ error: "MSG91_AUTHKEY must be configured" });
    }
    if (!process.env.MSG91_OTP_TEMPLATE_ID) {
      return res.status(500).json({ error: "MSG91_OTP_TEMPLATE_ID is required for captcha-free OTP sending" });
    }
    const identifier = String((req.body && req.body.identifier) || "").replace(/\D/g, "");
    if (!/^91\d{10}$/.test(identifier)) {
      return res.status(400).json({ error: "A valid India mobile number with country code is required" });
    }
    const url = new URL("https://control.msg91.com/api/v5/otp");
    url.searchParams.set("template_id", process.env.MSG91_OTP_TEMPLATE_ID);
    url.searchParams.set("mobile", identifier);
    url.searchParams.set("authkey", process.env.MSG91_AUTHKEY);
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    const data = await response.json().catch(() => ({}));
    assertMsg91Success(response, data, "MSG91 OTP send failed");
    res.json({ sent: true, identifier, data });
  } catch (err) {
    console.error("MSG91 OTP send failed:", err);
    res.status(err.status || 500).json({ sent: false, error: err.message || "MSG91 OTP send failed" });
  }
});

app.post("/otp/msg91/verify", async (req, res) => {
  try {
    if (!process.env.MSG91_AUTHKEY) {
      return res.status(500).json({ error: "MSG91_AUTHKEY is not configured" });
    }
    const identifier = String((req.body && req.body.identifier) || "").replace(/\D/g, "");
    const otp = String((req.body && req.body.otp) || "").trim();
    if (!/^91\d{10}$/.test(identifier) || !/^\d{4,8}$/.test(otp)) {
      return res.status(400).json({ verified: false, error: "A valid mobile number and OTP are required" });
    }
    const url = new URL("https://control.msg91.com/api/v5/otp/verify");
    url.searchParams.set("otp", otp);
    url.searchParams.set("mobile", identifier);
    const response = await fetch(url, {
      method: "GET",
      headers: { authkey: process.env.MSG91_AUTHKEY },
    });
    const data = await response.json().catch(() => ({}));
    assertMsg91Success(response, data, "MSG91 OTP verification failed");
    if (data.message && !String(data.message).toLowerCase().includes("verified")) {
      return res.status(400).json({ verified: false, error: data.message, data });
    }
    res.json({ verified: true, accessToken: makeSignupOtpToken(identifier), data });
  } catch (err) {
    console.error("MSG91 OTP verification failed:", err);
    res.status(err.status || 500).json({ verified: false, error: err.message || "MSG91 OTP verification failed" });
  }
});

app.post("/otp/msg91/verify-token", async (req, res) => {
  try {
    const accessToken = String((req.body && (req.body.accessToken || req.body["access-token"])) || "").trim();
    if (!accessToken) {
      return res.status(400).json({ verified: false, error: "MSG91 access token is required" });
    }
    const data = await verifyMsg91AccessToken(accessToken);
    res.json({ verified: true, data });
  } catch (err) {
    console.error("MSG91 access token verification failed:", err);
    res.status(err.status || 500).json({ verified: false, error: err.message || "MSG91 token verification failed" });
  }
});

// SIGNUP API
app.post("/signup", async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      username,
      email,
      phone,
      countryCode,
      city,
      password,
      otpAccessToken,
    } = req.body;

    const cleanFirstName = String(firstName || username || "").trim();
    const cleanLastName = String(lastName || "").trim();
    const cleanEmail = String(email || "").trim().toLowerCase();
    const cleanPhone = String(phone || "").trim();
    const cleanCountryCode = String(countryCode || "+91").trim();
    const cleanCity = String(city || "").trim();

    if (!cleanFirstName || !cleanEmail || !password) {
      return res.status(400).json({
        error: "First name, email, and password are required",
      });
    }
    if (!cleanPhone) {
      return res.status(400).json({ error: "Phone number is required" });
    }
    if (!otpAccessToken) {
      return res.status(400).json({ error: "Please verify your phone number with OTP before creating an account" });
    }
    await verifySignupOtpToken(otpAccessToken, cleanCountryCode, cleanPhone);

    const hashedPassword = await bcrypt.hash(password, 10);
    const displayName = [cleanFirstName, cleanLastName].filter(Boolean).join(" ");

    const result = await pool.query(
      `INSERT INTO users (
        username,
        first_name,
        last_name,
        email,
        phone,
        country_code,
        city,
        password
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
      RETURNING id, username, first_name, last_name, email, phone, country_code, city, created_at`,
      [
        displayName || cleanFirstName,
        cleanFirstName,
        cleanLastName,
        cleanEmail,
        cleanPhone,
        cleanCountryCode,
        cleanCity,
        hashedPassword,
      ]
    );

    res.json({
      message: "Signup successful",
      user: result.rows[0],
    });
  } catch (err) {
    console.error(err);

    if (err.code === "23505") {
      return res.status(409).json({
        error: "An account with this email already exists",
      });
    }

    res.status(500).json({
      error: "Signup failed",
    });
  }
});

app.post("/social-login", async (req, res) => {
  try {
    const { name, email, photoURL, provider } = req.body || {};
    const cleanEmail = String(email || "").trim().toLowerCase();
    const cleanName = String(name || "Google User").trim();
    if (!cleanEmail) {
      return res.status(400).json({ error: "Email is required" });
    }
    const parts = cleanName.split(/\s+/);
    const firstName = parts.shift() || cleanName;
    const lastName = parts.join(" ");
    const result = await pool.query(
      `INSERT INTO users (
        username, first_name, last_name, email, password, auth_provider, profile_image_url
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7)
      ON CONFLICT (email) DO UPDATE SET
        username=EXCLUDED.username,
        first_name=EXCLUDED.first_name,
        last_name=EXCLUDED.last_name,
        auth_provider=EXCLUDED.auth_provider,
        profile_image_url=COALESCE(users.profile_image_url, EXCLUDED.profile_image_url)
      RETURNING id, username, first_name, last_name, email, phone, country_code, city,
        profile_image_url, profile_image_key, profile_image_storage, auth_provider`,
      [
        cleanName,
        firstName,
        lastName,
        cleanEmail,
        "oauth-provider",
        provider || "google",
        photoURL || "",
      ]
    );
    const user = result.rows[0];
    res.json({
      message: "Login successful",
      user: publicUser(user),
      token: signJwt({ sub: user.id, email: user.email }),
      expiresInDays: 30,
    });
  } catch (err) {
    console.error("Social login failed:", err);
    res.status(500).json({ error: "Social login failed" });
  }
});


// LOGIN API
app.post("/login", async (req, res) => {
  try {
    const {
      email,
      password,
    } = req.body;

    const cleanEmail = String(email || "").trim().toLowerCase();

    if (!cleanEmail || !password) {
      return res.status(400).json({
        error: "Email and password are required",
      });
    }

    const result = await pool.query(
      `SELECT
        id,
        username,
        first_name,
        last_name,
        email,
        phone,
        country_code,
        city,
        profile_image_url,
        profile_image_key,
        profile_image_storage,
        password
      FROM users
      WHERE email=$1`,
      [cleanEmail]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({
        error: "User not found",
      });
    }

    const user = result.rows[0];

    const validPassword =
      await bcrypt.compare(
        password,
        user.password
      );

    if (!validPassword) {
      return res.status(400).json({
        error: "Invalid password",
      });
    }

    res.json({
      message: "Login successful",
      user: publicUser(user),
      token: signJwt({ sub: user.id, email: user.email }),
      expiresInDays: 30,
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Login failed",
    });
  }
});

app.get("/session", async (req, res) => {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    const payload = verifyJwt(token);
    const result = await pool.query(
      `SELECT id, username, first_name, last_name, email, phone, country_code, city,
        profile_image_url, profile_image_key, profile_image_storage
       FROM users
       WHERE id=$1`,
      [payload.sub]
    );
    if (!result.rows.length) {
      return res.status(401).json({ error: "Session user not found" });
    }
    res.json({ user: publicUser(result.rows[0]) });
  } catch (err) {
    res.status(401).json({ error: err.message || "Invalid session" });
  }
});


const PORT = process.env.PORT || 3003;

app.listen(PORT, () => {

  console.log(
    `Server running on port ${PORT}`
  );

});
