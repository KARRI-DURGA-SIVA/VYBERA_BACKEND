const express = require("express");
const path = require("path");
const fs = require("fs");
const { Pool } = require("pg");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const QRCode = require("qrcode");
const twilio = require("twilio");
require("dotenv").config({ path: path.join(__dirname, ".env") });

const app = express();
const appHtmlPath = path.join(__dirname, "..", "vybera_26.html");
const uploadsDir = path.join(__dirname, "uploads");
fs.mkdirSync(uploadsDir, { recursive: true });

const corsOptions = {
  origin: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "ngrok-skip-browser-warning", "X-Requested-With"],
  exposedHeaders: ["Content-Length", "Content-Type"],
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", req.headers.origin || "*");
  res.header("Vary", "Origin");
  res.header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, ngrok-skip-browser-warning, X-Requested-With");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});
app.use(bodyParser.json({ limit: "30mb" }));
app.use(bodyParser.urlencoded({ extended: true }));
// Static middleware will be added at the end, AFTER all API routes

app.get(["/firebaseconfig.js", "/VYBERA/firebaseconfig.js"], (req, res) => {
  res.type("text/javascript").sendFile(path.join(__dirname, "firebaseconfig.js"));
});

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    twilioVerifyConfigured: Boolean(twilioClient && twilioVerifyServiceSid),
  });
});

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

// Twilio configuration
const twilioAccountSid = process.env.TWILIO_ACCOUNT_SID;
const twilioAuthToken = process.env.TWILIO_AUTH_TOKEN;
const twilioVerifyServiceSid = process.env.TWILIO_VERIFY_SERVICE_SID || process.env.TWILIO_PHONE_NUMBER;
const twilioVerifyChannel = process.env.TWILIO_VERIFY_CHANNEL || "sms";
if (twilioAccountSid && twilioAuthToken && twilioVerifyServiceSid) {
  console.log("Twilio configured successfully");
} else {
  console.warn("Twilio configuration incomplete: TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and TWILIO_VERIFY_SERVICE_SID are required for OTP functionality");
}
const twilioClient = twilioAccountSid && twilioAuthToken ? twilio(twilioAccountSid, twilioAuthToken) : null;

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

const publicCreator = (creator) => ({
  id: creator.id,
  name: creator.name,
  email: creator.email,
  phone: creator.phone,
  category: creator.category,
  about: creator.about,
  kycStatus: creator.kyc_status,
  joinedAt: creator.created_at,
});

const publicCreatorEvent = (event) => ({
  id: event.id,
  creatorId: event.creator_id,
  creatorName: event.creator_name,
  name: event.name,
  category: event.category,
  description: event.description,
  date: event.event_date,
  time: event.start_time,
  endTime: event.end_time,
  venue: event.venue,
  city: event.city,
  capacity: event.capacity,
  latitude: event.latitude,
  longitude: event.longitude,
  banner: event.banner_url,
  bannerKey: event.banner_key,
  visibility: event.visibility,
  status: event.status,
  tickets: event.tickets || [],
  bookingCount: Number(event.booking_count || 0),
  revenue: Number(event.revenue || 0),
  checkins: Number(event.checkins || 0),
  createdAt: event.created_at,
});

const creatorEventSalesQuery = `
  SELECT e.*,
    COALESCE(SUM(CASE WHEN b.status <> 'refunded' THEN b.qty ELSE 0 END),0)::INTEGER AS booking_count,
    COALESCE(SUM(CASE WHEN b.status <> 'refunded' THEN b.total ELSE 0 END),0)::NUMERIC AS revenue
  FROM creator_events e
  LEFT JOIN bookings b ON b.event_id=e.id
`;

const publicStaffAssignment = (assignment) => ({
  id: assignment.id,
  staffPk: assignment.staff_id,
  staffId: assignment.staff_id,
  eventId: assignment.event_id,
  eventName: assignment.event_name,
  tierName: assignment.tier_name,
  qty: Number(assignment.qty || 0),
  soldCount: Number(assignment.sold_count || 0),
  price: Number(assignment.price || 0),
  mode: assignment.allocation_mode || "creator_quota",
  allocationMode: assignment.allocation_mode || "creator_quota",
  commissionRate: Number(assignment.commission_rate || 0),
  purchasePrice: Number(assignment.purchase_price || assignment.price || 0),
  resalePrice: Number(assignment.resale_price || assignment.price || 0),
  assignedAt: assignment.created_at,
});

const publicStaffShareUrl = (req, member) => {
  if (!member || !member.share_token) return "";
  const origin = req ? `${req.protocol}://${req.get("host")}` : "";
  const eventId = member.primary_event_id ? `&event=${encodeURIComponent(member.primary_event_id)}` : "";
  return `${origin}/?staff=${encodeURIComponent(member.share_token)}${eventId}`;
};

const publicStaffSale = (sale) => ({
  id: sale.id,
  staffPk: sale.staff_id,
  assignmentId: sale.assignment_id,
  eventId: sale.event_id,
  eventName: sale.event_name,
  tierName: sale.tier_name,
  buyerName: sale.buyer_name,
  buyerPhone: sale.buyer_phone,
  buyerEmail: sale.buyer_email,
  qty: Number(sale.qty || 0),
  price: Number(sale.price || 0),
  total: Number(sale.total || 0),
  commission: Number(sale.commission || 0),
  revenueOwner: sale.revenue_owner || "staff",
  allocationMode: sale.allocation_mode || "creator_quota",
  paymentMode: sale.payment_mode,
  bookingId: sale.booking_id,
  soldAt: sale.created_at,
});

const publicStaffWithdrawal = (withdrawal) => ({
  id: withdrawal.id,
  staffPk: withdrawal.staff_id,
  amount: Number(withdrawal.amount || 0),
  method: withdrawal.method,
  bankAccountName: withdrawal.bank_account_name,
  bankAccountNumber: withdrawal.bank_account_number,
  bankIfsc: withdrawal.bank_ifsc,
  upiId: withdrawal.upi_id,
  status: withdrawal.status,
  requestedAt: withdrawal.created_at,
});

const publicStaff = (member) => ({
  id: member.id,
  creatorId: member.creator_id,
  name: member.name,
  staffId: member.staff_id,
  email: member.email,
  phone: member.phone,
  role: member.role,
  assignedGate: member.assigned_gate,
  gates: member.assigned_gate ? [member.assigned_gate] : [],
  primaryEventId: member.primary_event_id,
  shareToken: member.share_token,
  shareUrl: member.share_url || "",
  status: member.status,
  assignedTickets: Number(member.assigned_tickets || 0),
  soldTickets: Number(member.sold_tickets || 0),
  earnings: Number(member.earnings || 0),
  createdAt: member.created_at,
});

const publicAdmin = (admin) => ({
  id: admin.id,
  name: admin.name,
  email: admin.email,
  role: admin.role,
  status: admin.status,
  lastLogin: admin.last_login,
  createdAt: admin.created_at,
});

const requireCreator = (req, res, next) => {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    const payload = verifyJwt(token);
    if (payload.scope !== "creator") throw new Error("Creator login required");
    req.creator = payload;
    next();
  } catch (err) {
    res.status(401).json({ error: err.message || "Creator login required" });
  }
};

const requireAdmin = (req, res, next) => {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    const payload = verifyJwt(token);
    if (payload.scope !== "admin") throw new Error("Admin login required");
    req.admin = payload;
    next();
  } catch (err) {
    res.status(401).json({ error: err.message || "Admin login required" });
  }
};

const requireStaff = (req, res, next) => {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    const payload = verifyJwt(token);
    if (payload.scope !== "staff") throw new Error("Staff login required");
    req.staff = payload;
    next();
  } catch (err) {
    res.status(401).json({ error: err.message || "Staff login required" });
  }
};

const requireBuyer = (req, res, next) => {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    const payload = verifyJwt(token);
    if (!payload.sub || payload.scope) throw new Error("Buyer login required");
    req.buyer = payload;
    next();
  } catch (err) {
    res.status(401).json({ error: err.message || "Buyer login required" });
  }
};

const requireProfileIdentity = (req, res, next) => {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    const payload = verifyJwt(token);
    const email = String(payload.email || "").trim().toLowerCase();
    if (!email) throw new Error("Profile login required");
    req.profileIdentity = { ...payload, email };
    next();
  } catch (err) {
    res.status(401).json({ error: err.message || "Profile login required" });
  }
};

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

  await pool.query(`
    ALTER TABLE bookings
      ADD COLUMN IF NOT EXISTS buyer_name TEXT,
      ADD COLUMN IF NOT EXISTS qr_token TEXT,
      ADD COLUMN IF NOT EXISTS scanned_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS staff_id TEXT,
      ADD COLUMN IF NOT EXISTS staff_ref TEXT
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS creator_accounts (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      phone TEXT NOT NULL,
      category TEXT NOT NULL,
      about TEXT NOT NULL,
      password TEXT NOT NULL,
      kyc_status TEXT NOT NULL DEFAULT 'Pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE creator_accounts
      ADD COLUMN IF NOT EXISTS finance_pin TEXT
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS creator_kyc_documents (
      id SERIAL PRIMARY KEY,
      creator_id INTEGER NOT NULL REFERENCES creator_accounts(id) ON DELETE CASCADE,
      document_type TEXT NOT NULL,
      file_name TEXT NOT NULL,
      object_key TEXT NOT NULL,
      storage TEXT NOT NULL,
      content_type TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS creator_events (
      id TEXT PRIMARY KEY,
      creator_id INTEGER NOT NULL REFERENCES creator_accounts(id) ON DELETE CASCADE,
      creator_name TEXT NOT NULL,
      name TEXT NOT NULL,
      category TEXT NOT NULL,
      description TEXT NOT NULL,
      event_date TEXT NOT NULL,
      start_time TEXT NOT NULL,
      end_time TEXT,
      venue TEXT NOT NULL,
      city TEXT NOT NULL,
      capacity INTEGER NOT NULL,
      latitude NUMERIC,
      longitude NUMERIC,
      banner_url TEXT NOT NULL,
      banner_key TEXT NOT NULL,
      visibility TEXT NOT NULL DEFAULT 'Public',
      status TEXT NOT NULL DEFAULT 'live',
      tickets JSONB NOT NULL DEFAULT '[]'::jsonb,
      booking_count INTEGER NOT NULL DEFAULT 0,
      revenue NUMERIC NOT NULL DEFAULT 0,
      checkins INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS admin_accounts (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'Super Admin',
      status TEXT NOT NULL DEFAULT 'Active',
      last_login TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS staff_accounts (
      id TEXT PRIMARY KEY,
      creator_id INTEGER REFERENCES creator_accounts(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      staff_id TEXT UNIQUE NOT NULL,
      email TEXT,
      phone TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      assigned_tickets INTEGER NOT NULL DEFAULT 0,
      sold_tickets INTEGER NOT NULL DEFAULT 0,
      earnings NUMERIC NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE staff_accounts
      ADD COLUMN IF NOT EXISTS password TEXT,
      ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'Scanner',
      ADD COLUMN IF NOT EXISTS assigned_gate TEXT,
      ADD COLUMN IF NOT EXISTS primary_event_id TEXT,
      ADD COLUMN IF NOT EXISTS share_token TEXT UNIQUE
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS staff_assignments (
      id TEXT PRIMARY KEY,
      creator_id INTEGER NOT NULL REFERENCES creator_accounts(id) ON DELETE CASCADE,
      staff_id TEXT NOT NULL REFERENCES staff_accounts(id) ON DELETE CASCADE,
      event_id TEXT NOT NULL REFERENCES creator_events(id) ON DELETE CASCADE,
      event_name TEXT NOT NULL,
      tier_name TEXT NOT NULL,
      qty INTEGER NOT NULL,
      sold_count INTEGER NOT NULL DEFAULT 0,
      price NUMERIC NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE staff_assignments
      ADD COLUMN IF NOT EXISTS allocation_mode TEXT NOT NULL DEFAULT 'creator_quota',
      ADD COLUMN IF NOT EXISTS commission_rate NUMERIC NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS purchase_price NUMERIC NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS resale_price NUMERIC NOT NULL DEFAULT 0
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS staff_sales (
      id TEXT PRIMARY KEY,
      creator_id INTEGER NOT NULL REFERENCES creator_accounts(id) ON DELETE CASCADE,
      staff_id TEXT NOT NULL REFERENCES staff_accounts(id) ON DELETE CASCADE,
      assignment_id TEXT REFERENCES staff_assignments(id) ON DELETE SET NULL,
      event_id TEXT NOT NULL REFERENCES creator_events(id) ON DELETE CASCADE,
      event_name TEXT NOT NULL,
      tier_name TEXT NOT NULL,
      buyer_name TEXT,
      buyer_phone TEXT,
      buyer_email TEXT,
      qty INTEGER NOT NULL DEFAULT 1,
      price NUMERIC NOT NULL DEFAULT 0,
      total NUMERIC NOT NULL DEFAULT 0,
      payment_mode TEXT NOT NULL DEFAULT 'cash',
      booking_id TEXT REFERENCES bookings(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE staff_sales
      ADD COLUMN IF NOT EXISTS commission NUMERIC NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS revenue_owner TEXT NOT NULL DEFAULT 'staff',
      ADD COLUMN IF NOT EXISTS allocation_mode TEXT NOT NULL DEFAULT 'creator_quota'
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS staff_withdrawals (
      id TEXT PRIMARY KEY,
      creator_id INTEGER NOT NULL REFERENCES creator_accounts(id) ON DELETE CASCADE,
      staff_id TEXT NOT NULL REFERENCES staff_accounts(id) ON DELETE CASCADE,
      amount NUMERIC NOT NULL,
      method TEXT NOT NULL DEFAULT 'upi',
      bank_account_name TEXT,
      bank_account_number TEXT,
      bank_ifsc TEXT,
      upi_id TEXT,
      status TEXT NOT NULL DEFAULT 'Pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS payment_transactions (
      txnid TEXT PRIMARY KEY,
      booking_id TEXT,
      event_id TEXT,
      ticket_type TEXT,
      qty INTEGER,
      buyer_email TEXT,
      amount NUMERIC NOT NULL DEFAULT 0,
      gateway_payment_id TEXT,
      status TEXT NOT NULL DEFAULT 'Pending',
      verified BOOLEAN NOT NULL DEFAULT FALSE,
      error TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    UPDATE creator_events e SET
      booking_count=COALESCE(s.tickets,0),
      revenue=COALESCE(s.revenue,0)
    FROM (
      SELECT event_id,
        COALESCE(SUM(CASE WHEN status <> 'refunded' THEN qty ELSE 0 END),0)::INTEGER AS tickets,
        COALESCE(SUM(CASE WHEN status <> 'refunded' THEN total ELSE 0 END),0)::NUMERIC AS revenue
      FROM bookings
      WHERE event_id IS NOT NULL
      GROUP BY event_id
    ) s
    WHERE e.id=s.event_id
  `);

  const superAdminEmail = String(process.env.SUPERADMIN_EMAIL || "superadmin@vybera.in").trim().toLowerCase();
  const superAdminPassword = process.env.SUPERADMIN_PASSWORD;
  if (!superAdminPassword) {
    console.warn("SUPERADMIN_PASSWORD is missing. Skipping super-admin account bootstrap.");
    return;
  }
  const existingAdmin = await pool.query("SELECT id, password FROM admin_accounts WHERE email=$1", [superAdminEmail]);
  const passwordMatches = existingAdmin.rows[0]
    ? await bcrypt.compare(superAdminPassword, existingAdmin.rows[0].password)
    : false;
  const passwordHash = passwordMatches ? existingAdmin.rows[0].password : await bcrypt.hash(superAdminPassword, 10);
  await pool.query(
    `INSERT INTO admin_accounts (name, email, password, role, status)
     VALUES ($1,$2,$3,'Super Admin','Active')
     ON CONFLICT (email) DO UPDATE SET
       name=EXCLUDED.name,
       password=EXCLUDED.password,
       role=EXCLUDED.role,
       status=EXCLUDED.status`,
    ["Vybera Super Admin", superAdminEmail, passwordHash]
  );
};

initDb().catch((err) => {
  console.error("Database initialization failed:", err);
  process.exit(1);
});


// OPEN HTML PAGE
app.get("/", (req, res) => {
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
  res.sendFile(appHtmlPath);

});

app.get("/vybera_26.html", (req, res) => {
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
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

app.get("/qr", async (req, res) => {
  try {
    const text = String((req.query && req.query.text) || "").trim();
    if (!text) return res.status(400).send("Missing QR text");
    const png = await QRCode.toBuffer(text, { width: 420, margin: 2, errorCorrectionLevel: "M" });
    res.setHeader("Content-Type", "image/png");
    res.setHeader("Cache-Control", "public, max-age=300");
    res.send(png);
  } catch (err) {
    console.error("QR generation failed:", err);
    res.status(500).send("Could not generate QR");
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

app.post("/creator/applications", async (req, res) => {
  const client = await pool.connect();
  try {
    const { name, email, phone, category, about, password, documents } = req.body || {};
    const cleanName = String(name || "").trim();
    const cleanEmail = String(email || "").trim().toLowerCase();
    const cleanPhone = String(phone || "").trim();
    const cleanCategory = String(category || "").trim();
    const cleanAbout = String(about || "").trim();
    const cleanPassword = String(password || "");
    const files = Array.isArray(documents) ? documents : [];

    if (!cleanName || !cleanEmail || !cleanPhone || !cleanCategory || !cleanAbout || !cleanPassword) {
      return res.status(400).json({ error: "Name, email, phone, event type, about, and password are required" });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      return res.status(400).json({ error: "Enter a valid creator email address" });
    }
    if (cleanPassword.length < 8) {
      return res.status(400).json({ error: "Creator password must be at least 8 characters" });
    }
    if (!files.length) {
      return res.status(400).json({ error: "Upload at least one KYC document" });
    }
    const existing = await client.query("SELECT 1 FROM creator_accounts WHERE email=$1", [cleanEmail]);
    if (existing.rows.length) {
      return res.status(409).json({ error: "A creator account with this email already exists" });
    }

    const allowedTypes = new Set(["aadhaar", "gst", "bank"]);
    const uploaded = [];
    for (const file of files) {
      const documentType = String(file.documentType || "").trim().toLowerCase();
      if (!allowedTypes.has(documentType) || !file.fileName || !file.dataUrl) {
        return res.status(400).json({ error: "Each KYC document must include a valid type, file name, and file data" });
      }
      const asset = await saveAsset({
        fileName: file.fileName,
        folder: `kyc-documents/${cleanPathSegment(cleanEmail, "creator")}/${documentType}`,
        dataUrl: file.dataUrl,
        requireR2: true,
      });
      uploaded.push({ documentType, fileName: file.fileName, ...asset });
    }

    const hashedPassword = await bcrypt.hash(cleanPassword, 10);
    await client.query("BEGIN");
    const creatorResult = await client.query(
      `INSERT INTO creator_accounts (name, email, phone, category, about, password)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING id, name, email, phone, category, about, kyc_status, created_at`,
      [cleanName, cleanEmail, cleanPhone, cleanCategory, cleanAbout, hashedPassword]
    );
    const creator = creatorResult.rows[0];
    for (const file of uploaded) {
      await client.query(
        `INSERT INTO creator_kyc_documents (
          creator_id, document_type, file_name, object_key, storage, content_type
        ) VALUES ($1,$2,$3,$4,$5,$6)`,
        [creator.id, file.documentType, file.fileName, file.key, file.storage, file.contentType]
      );
    }
    await client.query("COMMIT");
    res.status(201).json({
      message: "Creator application and KYC submitted successfully. Sign in with your creator email and password.",
      creator: publicCreator(creator),
    });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Creator application failed:", err);
    if (err.code === "23505") {
      return res.status(409).json({ error: "A creator account with this email already exists" });
    }
    res.status(500).json({ error: err.message || "Creator application failed" });
  } finally {
    client.release();
  }
});

app.post("/creator/login", async (req, res) => {
  try {
    const cleanEmail = String((req.body && req.body.email) || "").trim().toLowerCase();
    const password = String((req.body && req.body.password) || "");
    if (!cleanEmail || !password) {
      return res.status(400).json({ error: "Creator email and password are required" });
    }
    const result = await pool.query(
      `SELECT id, name, email, phone, category, about, password, kyc_status, created_at
       FROM creator_accounts
       WHERE email=$1`,
      [cleanEmail]
    );
    if (!result.rows.length || !(await bcrypt.compare(password, result.rows[0].password))) {
      return res.status(401).json({ error: "Invalid creator email or password" });
    }
    const creator = result.rows[0];
    res.json({
      message: "Creator login successful",
      creator: publicCreator(creator),
      token: signJwt({ sub: creator.id, email: creator.email, scope: "creator" }),
      expiresInDays: 30,
    });
  } catch (err) {
    console.error("Creator login failed:", err);
    res.status(500).json({ error: "Creator login failed" });
  }
});

app.get("/creator/events", requireCreator, async (req, res) => {
  try {
    const result = await pool.query(
      `${creatorEventSalesQuery}
       WHERE e.creator_id=$1
       GROUP BY e.id
       ORDER BY e.created_at DESC`,
      [req.creator.sub]
    );
    res.json({ events: result.rows.map(publicCreatorEvent) });
  } catch (err) {
    console.error("Creator events list failed:", err);
    res.status(500).json({ error: "Could not load creator events" });
  }
});

app.get("/events", async (req, res) => {
  try {
    const result = await pool.query(
      `${creatorEventSalesQuery}
       WHERE e.status='live' AND e.visibility='Public'
       GROUP BY e.id
       ORDER BY e.created_at DESC`
    );
    res.json({ events: result.rows.map(publicCreatorEvent) });
  } catch (err) {
    console.error("Public events list failed:", err);
    res.status(500).json({ error: "Could not load events" });
  }
});

app.post("/creator/events/banner", requireCreator, async (req, res) => {
  try {
    const { fileName, dataUrl } = req.body || {};
    if (!fileName || !dataUrl) {
      return res.status(400).json({ error: "Banner file name and data are required" });
    }
    const asset = await saveAsset({
      fileName,
      folder: `event-banners/creator-${req.creator.sub}`,
      dataUrl,
      requireR2: true,
    });
    res.status(201).json(asset);
  } catch (err) {
    console.error("Creator banner upload failed:", err);
    res.status(500).json({ error: err.message || "Banner upload failed" });
  }
});

app.post("/creator/events", requireCreator, async (req, res) => {
  try {
    const {
      name, category, description, date, time, endTime, venue, city, capacity,
      latitude, longitude, banner, bannerKey, visibility, tickets,
    } = req.body || {};
    const cleanTickets = Array.isArray(tickets) ? tickets.map((ticket) => ({
      name: String(ticket.name || "").trim(),
      price: Number(ticket.price || 0),
      qty: Number(ticket.qty || 0),
      perks: String(ticket.perks || "").trim(),
    })).filter((ticket) => ticket.name && ticket.qty > 0 && ticket.price >= 0) : [];
    if (!name || !category || !description || !date || !time || !venue || !city || !Number(capacity)) {
      return res.status(400).json({ error: "Complete the event details, date, time, venue, city, and capacity" });
    }
    if (!banner || !bannerKey) {
      return res.status(400).json({ error: "Upload an event banner before publishing" });
    }
    if (!cleanTickets.length) {
      return res.status(400).json({ error: "Add at least one valid ticket tier" });
    }
    const creatorResult = await pool.query("SELECT name FROM creator_accounts WHERE id=$1", [req.creator.sub]);
    if (!creatorResult.rows.length) return res.status(401).json({ error: "Creator account not found" });
    const id = `EVT-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`;
    const result = await pool.query(
      `INSERT INTO creator_events (
        id, creator_id, creator_name, name, category, description, event_date,
        start_time, end_time, venue, city, capacity, latitude, longitude,
        banner_url, banner_key, visibility, tickets
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
      RETURNING *`,
      [
        id, req.creator.sub, creatorResult.rows[0].name, String(name).trim(),
        String(category).trim(), String(description).trim(), String(date).trim(),
        String(time).trim(), String(endTime || "").trim() || null, String(venue).trim(),
        String(city).trim(), Number(capacity), latitude || null, longitude || null,
        String(banner), String(bannerKey), String(visibility || "Public"), JSON.stringify(cleanTickets),
      ]
    );
    if (!result.rows.length) {
      throw new Error("Event was not saved in the database");
    }
    res.status(201).json({ message: "Event published successfully", event: publicCreatorEvent(result.rows[0]) });
  } catch (err) {
    console.error("Creator event publish failed:", err);
    res.status(500).json({ error: err.message || "Event publish failed" });
  }
});

app.get("/creator/staff", requireCreator, async (req, res) => {
  try {
    const [staff, assignments, salesSummary] = await Promise.all([
      pool.query(
        `SELECT s.*,
           COALESCE(SUM(ss.qty),0)::INTEGER AS db_sold_tickets,
           COALESCE(SUM(CASE WHEN ss.revenue_owner='staff' THEN ss.total ELSE ss.commission END),0)::NUMERIC AS db_earnings
         FROM staff_accounts s
         LEFT JOIN staff_sales ss ON ss.staff_id=s.id
         WHERE s.creator_id=$1
         GROUP BY s.id
         ORDER BY s.created_at DESC`,
        [req.creator.sub]
      ),
      pool.query("SELECT * FROM staff_assignments WHERE creator_id=$1 ORDER BY created_at DESC", [req.creator.sub]),
      pool.query(
        `SELECT
           COALESCE(SUM(qty),0)::INTEGER AS tickets_sold,
           COALESCE(SUM(total),0)::NUMERIC AS revenue
         FROM staff_sales
         WHERE creator_id=$1`,
        [req.creator.sub]
      ),
    ]);
    const summary = salesSummary.rows[0] || {};
    res.json({
      staff: staff.rows.map((member) => {
        const mapped = {
          ...member,
          sold_tickets: Number(member.db_sold_tickets || member.sold_tickets || 0),
          earnings: Number(member.db_earnings || member.earnings || 0),
        };
        return publicStaff({ ...mapped, share_url: publicStaffShareUrl(req, mapped) });
      }),
      assignments: assignments.rows.map(publicStaffAssignment),
      summary: {
        totalStaff: staff.rows.length,
        ticketsSold: Number(summary.tickets_sold || 0),
        revenue: Number(summary.revenue || 0),
      },
    });
  } catch (err) {
    console.error("Creator staff list failed:", err);
    res.status(500).json({ error: "Could not load staff" });
  }
});

app.get("/creator/analytics", requireCreator, async (req, res) => {
  try {
    const [summary, events, staff] = await Promise.all([
      pool.query(
        `SELECT
           COALESCE(SUM(CASE WHEN b.status <> 'refunded' THEN b.total ELSE 0 END),0)::NUMERIC AS gross,
           COALESCE(SUM(CASE WHEN b.status <> 'refunded' THEN b.qty ELSE 0 END),0)::INTEGER AS tickets
         FROM creator_events e
         LEFT JOIN bookings b ON b.event_id=e.id
         WHERE e.creator_id=$1`,
        [req.creator.sub]
      ),
      pool.query(
        `SELECT e.id, e.name, e.status, e.event_date,
           COALESCE(SUM(CASE WHEN b.status <> 'refunded' THEN b.total ELSE 0 END),0)::NUMERIC AS revenue,
           COALESCE(SUM(CASE WHEN b.status <> 'refunded' THEN b.qty ELSE 0 END),0)::INTEGER AS tickets
         FROM creator_events e
         LEFT JOIN bookings b ON b.event_id=e.id
         WHERE e.creator_id=$1
         GROUP BY e.id
         ORDER BY e.created_at DESC`,
        [req.creator.sub]
      ),
      pool.query(
        `SELECT id, name, staff_id, assigned_tickets, sold_tickets, earnings
         FROM staff_accounts
         WHERE creator_id=$1
         ORDER BY earnings DESC, sold_tickets DESC, created_at DESC`,
        [req.creator.sub]
      ),
    ]);
    const gross = Number(summary.rows[0].gross || 0);
    const tickets = Number(summary.rows[0].tickets || 0);
    const fee = Math.round(gross * 0.08);
    const net = gross - fee;
    res.json({
      summary: {
        gross,
        fee,
        net,
        tickets,
        averageTicketPrice: tickets ? Math.round(gross / tickets) : 0,
        payoutStatus: gross > 0 ? "Pending" : "No payout due",
      },
      events: events.rows.map((event) => ({
        id: event.id,
        name: event.name,
        status: event.status,
        date: event.event_date,
        revenue: Number(event.revenue || 0),
        tickets: Number(event.tickets || 0),
      })),
      staff: staff.rows.map((member) => ({
        id: member.id,
        name: member.name,
        staffId: member.staff_id,
        assignedTickets: Number(member.assigned_tickets || 0),
        soldTickets: Number(member.sold_tickets || 0),
        earnings: Number(member.earnings || 0),
      })),
    });
  } catch (err) {
    console.error("Creator analytics failed:", err);
    res.status(500).json({ error: "Could not load creator analytics" });
  }
});

app.post("/creator/staff", requireCreator, async (req, res) => {
  const client = await pool.connect();
  try {
    const {
      name, phone, email, staffId, password, role, assignedGate, eventId, tierName, qty,
      allocationMode, mode, commissionRate, purchasePrice, resalePrice,
    } = req.body || {};
    const cleanStaffId = String(staffId || "").trim().toLowerCase();
    const cleanPassword = String(password || "");
    if (!name || !cleanStaffId || cleanPassword.length < 6) {
      return res.status(400).json({ error: "Name, login ID, and a temporary password of at least 6 characters are required" });
    }
    await client.query("BEGIN");
    const id = `STF-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`;
    const shareToken = `${cleanPathSegment(cleanStaffId, "staff")}-${crypto.randomBytes(4).toString("hex")}`;
    const result = await client.query(
      `INSERT INTO staff_accounts (id, creator_id, name, staff_id, email, phone, password, role, assigned_gate, primary_event_id, share_token)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       RETURNING *`,
      [
        id, req.creator.sub, String(name).trim(), cleanStaffId,
        String(email || "").trim() || null, String(phone || "").trim() || null,
        await bcrypt.hash(cleanPassword, 10), String(role || "Scanner").trim(),
        String(assignedGate || "").trim() || null,
        eventId ? String(eventId) : null,
        shareToken,
      ]
    );
    let assignment = null;
    if (eventId && tierName && Number(qty) > 0) {
      assignment = await createStaffAssignment(client, {
      creatorId: req.creator.sub,
      staffId: id,
      eventId,
      tierName,
      qty: Number(qty),
      allocationMode,
      mode,
      commissionRate,
      purchasePrice,
      resalePrice,
      });
    }
    await client.query("COMMIT");
    res.status(201).json({
      message: "Staff member added successfully",
      staff: publicStaff({ ...result.rows[0], share_url: publicStaffShareUrl(req, result.rows[0]) }),
      assignment: assignment ? publicStaffAssignment(assignment) : null,
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Creator staff create failed:", err);
    if (err.code === "23505") return res.status(409).json({ error: "Staff login ID is already taken" });
    res.status(400).json({ error: err.message || "Could not add staff" });
  } finally {
    client.release();
  }
});

const createStaffAssignment = async (client, {
  creatorId, staffId, eventId, tierName, qty,
  allocationMode, mode, commissionRate, purchasePrice, resalePrice,
}) => {
  const cleanQty = Number(qty);
  if (!Number.isInteger(cleanQty) || cleanQty < 1) throw new Error("Enter a valid ticket quantity");
  const cleanMode = String(allocationMode || mode || "creator_quota") === "staff_owned"
    ? "staff_owned"
    : "creator_quota";
  const cleanCommissionRate = Math.max(0, Number(commissionRate || 0));
  const staff = await client.query("SELECT id FROM staff_accounts WHERE id=$1 AND creator_id=$2", [staffId, creatorId]);
  if (!staff.rows.length) throw new Error("Staff member not found");
  const event = await client.query("SELECT * FROM creator_events WHERE id=$1 AND creator_id=$2 FOR UPDATE", [eventId, creatorId]);
  if (!event.rows.length) throw new Error("Creator event not found");
  const tickets = Array.isArray(event.rows[0].tickets) ? event.rows[0].tickets : [];
  const tier = tickets.find((ticket) => ticket.name === tierName);
  if (!tier) throw new Error("Ticket tier not found");
  if (Number(tier.qty || 0) < cleanQty) throw new Error("Not enough tickets available");
  const basePrice = Number(tier.price || 0);
  const cleanPurchasePrice = Number.isFinite(Number(purchasePrice)) && Number(purchasePrice) >= 0
    ? Number(purchasePrice)
    : basePrice;
  const cleanResalePrice = Number.isFinite(Number(resalePrice)) && Number(resalePrice) >= 0
    ? Number(resalePrice)
    : basePrice;
  tier.qty = Number(tier.qty || 0) - cleanQty;
  await client.query("UPDATE creator_events SET tickets=$1 WHERE id=$2", [JSON.stringify(tickets), eventId]);
  await client.query(
    "UPDATE staff_accounts SET assigned_tickets=assigned_tickets+$1, primary_event_id=COALESCE(primary_event_id,$3) WHERE id=$2",
    [cleanQty, staffId, eventId]
  );
  const id = `ASN-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`;
  const result = await client.query(
    `INSERT INTO staff_assignments (
       id, creator_id, staff_id, event_id, event_name, tier_name, qty, price,
       allocation_mode, commission_rate, purchase_price, resale_price
     )
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
     RETURNING *`,
    [
      id, creatorId, staffId, eventId, event.rows[0].name, tierName, cleanQty, basePrice,
      cleanMode, cleanCommissionRate, cleanPurchasePrice, cleanResalePrice,
    ]
  );
  if (cleanMode === "staff_owned") {
    await client.query(
      "UPDATE creator_events SET revenue=COALESCE(revenue,0)+$1 WHERE id=$2",
      [cleanPurchasePrice * cleanQty, eventId]
    );
  }
  return result.rows[0];
};

const eventSalesClosed = (event) => {
  const value = String(event && event.event_date || "").trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const eventDate = new Date(`${value}T23:59:59.999Z`);
  return Number.isFinite(eventDate.getTime()) && eventDate < new Date();
};

const staffWalletFor = async (staffId) => {
  const result = await pool.query(
    `SELECT
       COALESCE(SUM(CASE WHEN payment_mode='online' THEN
         CASE WHEN revenue_owner='staff' THEN total ELSE commission END
       ELSE 0 END),0)::NUMERIC AS online_revenue,
       COALESCE(SUM(CASE WHEN payment_mode='cash' THEN
         CASE WHEN revenue_owner='staff' THEN total ELSE commission END
       ELSE 0 END),0)::NUMERIC AS cash_revenue,
       COALESCE(SUM(CASE WHEN revenue_owner='staff' THEN total ELSE commission END),0)::NUMERIC AS total_earned,
       COALESCE(SUM(qty),0)::INTEGER AS tickets_sold
     FROM staff_sales
     WHERE staff_id=$1`,
    [staffId]
  );
  const withdrawals = await pool.query(
    `SELECT COALESCE(SUM(amount),0)::NUMERIC AS withdrawn
     FROM staff_withdrawals
     WHERE staff_id=$1 AND status <> 'Rejected'`,
    [staffId]
  );
  const row = result.rows[0] || {};
  const withdrawn = Number((withdrawals.rows[0] && withdrawals.rows[0].withdrawn) || 0);
  const totalEarned = Number(row.total_earned || 0);
  return {
    onlineRevenue: Number(row.online_revenue || 0),
    cashRevenue: Number(row.cash_revenue || 0),
    totalEarned,
    withdrawn,
    availableBalance: Math.max(0, totalEarned - withdrawn),
    ticketsSold: Number(row.tickets_sold || 0),
  };
};

app.post("/creator/staff/:staffId/assignments", requireCreator, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const assignment = await createStaffAssignment(client, {
      creatorId: req.creator.sub,
      staffId: req.params.staffId,
      eventId: req.body && req.body.eventId,
      tierName: req.body && req.body.tierName,
      qty: Number(req.body && req.body.qty),
      allocationMode: req.body && req.body.allocationMode,
      mode: req.body && req.body.mode,
      commissionRate: req.body && req.body.commissionRate,
      purchasePrice: req.body && req.body.purchasePrice,
      resalePrice: req.body && req.body.resalePrice,
    });
    await client.query("COMMIT");
    res.status(201).json({ message: "Tickets assigned successfully", assignment: publicStaffAssignment(assignment) });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Creator staff assignment failed:", err);
    res.status(400).json({ error: err.message || "Could not assign tickets" });
  } finally {
    client.release();
  }
});

app.post("/staff/login", async (req, res) => {
  try {
    const staffId = String((req.body && req.body.staffId) || "").trim();
    const cleanStaffId = staffId.toLowerCase();
    const digits = staffId.replace(/\D/g, "");
    const password = String((req.body && req.body.password) || "");
    if (!staffId || !password) {
      return res.status(400).json({ error: "Staff login ID and password are required" });
    }
    const result = await pool.query(
      `SELECT *
       FROM staff_accounts
       WHERE status='active'
         AND (
           LOWER(staff_id)=LOWER($1)
           OR LOWER(COALESCE(email,''))=LOWER($1)
           OR regexp_replace(COALESCE(phone,''), '[^0-9]', '', 'g')=$2
         )
       LIMIT 1`,
      [cleanStaffId, digits]
    );
    if (!result.rows.length || !result.rows[0].password) {
      return res.status(404).json({ error: "Staff account not found", staffNotFound: true });
    }
    const member = result.rows[0];
    const ok = await bcrypt.compare(password, member.password);
    if (!ok) return res.status(401).json({ error: "Invalid staff login ID or password" });
    const [assignments, events, sales, withdrawals, wallet] = await Promise.all([
      pool.query("SELECT * FROM staff_assignments WHERE staff_id=$1 ORDER BY created_at DESC", [member.id]),
      pool.query(
        `${creatorEventSalesQuery}
         WHERE e.creator_id=$1
         GROUP BY e.id
         ORDER BY e.created_at DESC`,
        [member.creator_id]
      ),
      pool.query("SELECT * FROM staff_sales WHERE staff_id=$1 ORDER BY created_at DESC", [member.id]),
      pool.query("SELECT * FROM staff_withdrawals WHERE staff_id=$1 ORDER BY created_at DESC", [member.id]),
      staffWalletFor(member.id),
    ]);
    res.json({
      message: "Staff login successful",
      staff: publicStaff({ ...member, share_url: publicStaffShareUrl(req, member) }),
      assignments: assignments.rows.map(publicStaffAssignment),
      events: events.rows.map(publicCreatorEvent),
      sales: sales.rows.map(publicStaffSale),
      withdrawals: withdrawals.rows.map(publicStaffWithdrawal),
      wallet,
      token: signJwt({ sub: member.id, staffId: member.staff_id, creatorId: member.creator_id, scope: "staff" }),
    });
  } catch (err) {
    console.error("Staff login failed:", err);
    res.status(500).json({ error: "Staff login failed" });
  }
});

app.get("/staff/lookup", async (req, res) => {
  try {
    res.setHeader("Cache-Control", "no-store");
    const identifier = String((req.query && req.query.identifier) || "").trim();
    const digits = identifier.replace(/\D/g, "");
    if (!identifier) return res.json({ exists: false });
    const result = await pool.query(
      `SELECT 1
       FROM staff_accounts
       WHERE status='active'
         AND (
           LOWER(staff_id)=LOWER($1)
           OR LOWER(COALESCE(email,''))=LOWER($1)
           OR regexp_replace(COALESCE(phone,''), '[^0-9]', '', 'g')=$2
         )
       LIMIT 1`,
      [identifier.toLowerCase(), digits]
    );
    res.json({ exists: Boolean(result.rows.length) });
  } catch (err) {
    console.error("Staff lookup failed:", err);
    res.status(500).json({ error: "Could not check staff account" });
  }
});

app.get("/staff/share/:token", async (req, res) => {
  try {
    const token = decodeURIComponent(String(req.params.token || "")).trim().replace(/[.)\]\s]+$/g, "");
    const digits = token.replace(/\D/g, "");
    const result = await pool.query(
      `SELECT s.id, s.name, s.staff_id, s.email, s.phone, s.share_token, s.primary_event_id, e.name AS event_name
       FROM staff_accounts s
       LEFT JOIN creator_events e ON e.id=s.primary_event_id
       WHERE s.status='active'
         AND (
           s.share_token=$1
           OR LOWER(s.staff_id)=LOWER($1)
           OR LOWER(COALESCE(s.email,''))=LOWER($1)
           OR regexp_replace(COALESCE(s.phone,''), '\\D', '', 'g')=$2
         )
       LIMIT 1`,
      [token, digits]
    );
    if (!result.rows.length) return res.status(404).json({ error: "Staff share link not found" });
    const row = result.rows[0];
    res.json({
      staff: {
        id: row.id,
        name: row.name,
        staffId: row.staff_id,
        shareToken: row.share_token,
        primaryEventId: row.primary_event_id,
        eventName: row.event_name,
      },
    });
  } catch (err) {
    console.error("Staff share lookup failed:", err);
    res.status(500).json({ error: "Could not load staff share link" });
  }
});

app.get("/staff/dashboard", requireStaff, async (req, res) => {
  try {
    const staff = await pool.query("SELECT * FROM staff_accounts WHERE id=$1 AND status='active'", [req.staff.sub]);
    if (!staff.rows.length) return res.status(404).json({ error: "Staff account not found" });
    const member = staff.rows[0];
    const [assignments, events, sales, withdrawals, wallet] = await Promise.all([
      pool.query("SELECT * FROM staff_assignments WHERE staff_id=$1 ORDER BY created_at DESC", [member.id]),
      pool.query(
        `${creatorEventSalesQuery}
         WHERE e.creator_id=$1
         GROUP BY e.id
         ORDER BY e.created_at DESC`,
        [member.creator_id]
      ),
      pool.query("SELECT * FROM staff_sales WHERE staff_id=$1 ORDER BY created_at DESC", [member.id]),
      pool.query("SELECT * FROM staff_withdrawals WHERE staff_id=$1 ORDER BY created_at DESC", [member.id]),
      staffWalletFor(member.id),
    ]);
    res.json({
      staff: publicStaff({ ...member, share_url: publicStaffShareUrl(req, member) }),
      assignments: assignments.rows.map(publicStaffAssignment),
      events: events.rows.map(publicCreatorEvent),
      sales: sales.rows.map(publicStaffSale),
      withdrawals: withdrawals.rows.map(publicStaffWithdrawal),
      wallet,
    });
  } catch (err) {
    console.error("Staff dashboard failed:", err);
    res.status(500).json({ error: "Could not load staff dashboard" });
  }
});

app.post("/staff/sales", requireStaff, async (req, res) => {
  const client = await pool.connect();
  try {
    const { assignmentId, buyerName, buyerPhone, buyerEmail, qty, paymentMode } = req.body || {};
    const cleanQty = Number(qty || 1);
    if (!assignmentId) return res.status(400).json({ error: "Select assigned tickets to sell" });
    if (!Number.isInteger(cleanQty) || cleanQty < 1) return res.status(400).json({ error: "Enter a valid ticket quantity" });
    const mode = String(paymentMode || "cash").trim().toLowerCase() === "online" ? "online" : "cash";
    await client.query("BEGIN");
    const staff = await client.query("SELECT * FROM staff_accounts WHERE id=$1 AND status='active' FOR UPDATE", [req.staff.sub]);
    if (!staff.rows.length) throw new Error("Staff account not found");
    const assignment = await client.query(
      `SELECT a.*, e.event_date, e.venue, e.banner_url, e.status AS event_status
       FROM staff_assignments a
       JOIN creator_events e ON e.id=a.event_id
       WHERE a.id=$1 AND a.staff_id=$2
       FOR UPDATE OF a`,
      [assignmentId, req.staff.sub]
    );
    if (!assignment.rows.length) throw new Error("Assigned tickets not found");
    const assigned = assignment.rows[0];
    if (eventSalesClosed(assigned) || assigned.event_status !== "live") {
      throw new Error("This event is completed or not live. Staff can view data only.");
    }
    const remaining = Number(assigned.qty || 0) - Number(assigned.sold_count || 0);
    if (cleanQty > remaining) throw new Error(`Only ${remaining} tickets are available in this assignment`);
    const id = `SLS-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`;
    const bookingId = `STF-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`;
    const assignmentMode = String(assigned.allocation_mode || "creator_quota") === "staff_owned"
      ? "staff_owned"
      : "creator_quota";
    const salePrice = assignmentMode === "staff_owned"
      ? Number(assigned.resale_price || assigned.price || 0)
      : Number(assigned.price || 0);
    const total = salePrice * cleanQty;
    const commission = assignmentMode === "creator_quota"
      ? Math.round(total * Number(assigned.commission_rate || 0) / 100)
      : 0;
    const revenueOwner = assignmentMode === "staff_owned" ? "staff" : "creator";
    const qrToken = crypto.randomBytes(18).toString("hex");
    const savedBooking = await client.query(
      `INSERT INTO bookings (
        id, buyer_name, buyer_email, event_id, event_name, event_date, event_venue,
        event_banner, ticket_type, price, qty, total, status, qr_token, booked_at
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'upcoming',$13,NOW())
      RETURNING *`,
      [
        bookingId,
        String(buyerName || "Walk-in Customer").trim(),
        String(buyerEmail || "").trim() || null,
        assigned.event_id,
        assigned.event_name,
        assigned.event_date,
        assigned.venue,
        assigned.banner_url,
        assigned.tier_name,
        salePrice,
        cleanQty,
        total,
        qrToken,
      ]
    );
    const sale = await client.query(
      `INSERT INTO staff_sales (
        id, creator_id, staff_id, assignment_id, event_id, event_name, tier_name,
        buyer_name, buyer_phone, buyer_email, qty, price, total, payment_mode, booking_id,
        commission, revenue_owner, allocation_mode
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
      RETURNING *`,
      [
        id,
        staff.rows[0].creator_id,
        staff.rows[0].id,
        assigned.id,
        assigned.event_id,
        assigned.event_name,
        assigned.tier_name,
        String(buyerName || "Walk-in Customer").trim(),
        String(buyerPhone || "").trim() || null,
        String(buyerEmail || "").trim() || null,
        cleanQty,
        salePrice,
        total,
        mode,
        bookingId,
        commission,
        revenueOwner,
        assignmentMode,
      ]
    );
    await client.query("UPDATE staff_assignments SET sold_count=sold_count+$1 WHERE id=$2", [cleanQty, assigned.id]);
    await client.query(
      "UPDATE staff_accounts SET sold_tickets=sold_tickets+$1, earnings=earnings+$2 WHERE id=$3",
      [cleanQty, revenueOwner === "staff" ? total : commission, staff.rows[0].id]
    );
    await client.query(
      `UPDATE creator_events e SET
         booking_count=COALESCE(s.tickets,0),
         revenue=COALESCE(s.revenue,0)
       FROM (
         SELECT event_id,
           COALESCE(SUM(CASE WHEN status <> 'refunded' THEN qty ELSE 0 END),0)::INTEGER AS tickets,
           COALESCE(SUM(CASE WHEN status <> 'refunded' THEN total ELSE 0 END),0)::NUMERIC AS revenue
         FROM bookings
         WHERE event_id=$1
         GROUP BY event_id
       ) s
       WHERE e.id=s.event_id`,
      [assigned.event_id]
    );
    await client.query("COMMIT");
    const wallet = await staffWalletFor(staff.rows[0].id);
    res.status(201).json({
      message: "Ticket sold successfully",
      sale: publicStaffSale(sale.rows[0]),
      booking: await ticketResponse(savedBooking.rows[0]),
      wallet,
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Staff sale failed:", err);
    res.status(400).json({ error: err.message || "Could not sell ticket" });
  } finally {
    client.release();
  }
});

app.post("/staff/withdrawals", requireStaff, async (req, res) => {
  try {
    const amount = Number(req.body && req.body.amount);
    const method = String((req.body && req.body.method) || "upi").trim().toLowerCase() === "bank" ? "bank" : "upi";
    if (!Number.isFinite(amount) || amount <= 0) return res.status(400).json({ error: "Enter a valid withdrawal amount" });
    const staff = await pool.query("SELECT * FROM staff_accounts WHERE id=$1 AND status='active'", [req.staff.sub]);
    if (!staff.rows.length) return res.status(404).json({ error: "Staff account not found" });
    const wallet = await staffWalletFor(req.staff.sub);
    if (amount > wallet.availableBalance) return res.status(400).json({ error: "Amount exceeds available balance" });
    const bankAccountName = String((req.body && req.body.bankAccountName) || "").trim();
    const bankAccountNumber = String((req.body && req.body.bankAccountNumber) || "").trim();
    const bankIfsc = String((req.body && req.body.bankIfsc) || "").trim().toUpperCase();
    const upiId = String((req.body && req.body.upiId) || "").trim();
    if (method === "bank" && (!bankAccountName || !bankAccountNumber || !bankIfsc)) {
      return res.status(400).json({ error: "Add bank account name, account number, and IFSC before withdrawal" });
    }
    if (method === "upi" && !upiId) {
      return res.status(400).json({ error: "Add a UPI ID before withdrawal" });
    }
    const id = `WD-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`;
    const result = await pool.query(
      `INSERT INTO staff_withdrawals (
        id, creator_id, staff_id, amount, method, bank_account_name, bank_account_number, bank_ifsc, upi_id
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
      RETURNING *`,
      [
        id,
        staff.rows[0].creator_id,
        staff.rows[0].id,
        amount,
        method,
        bankAccountName || null,
        bankAccountNumber || null,
        bankIfsc || null,
        upiId || null,
      ]
    );
    res.status(201).json({
      message: "Withdrawal requested successfully",
      withdrawal: publicStaffWithdrawal(result.rows[0]),
      wallet: await staffWalletFor(req.staff.sub),
    });
  } catch (err) {
    console.error("Staff withdrawal failed:", err);
    res.status(400).json({ error: err.message || "Could not request withdrawal" });
  }
});

app.post("/creator/finance/unlock", requireCreator, async (req, res) => {
  try {
    const pin = String((req.body && req.body.pin) || "").trim();
    if (!/^\d{4}$/.test(pin)) return res.status(400).json({ error: "Enter a valid 4-digit PIN" });
    const creator = await pool.query("SELECT finance_pin FROM creator_accounts WHERE id=$1", [req.creator.sub]);
    if (!creator.rows.length) return res.status(401).json({ error: "Creator account not found" });
    const hash = creator.rows[0].finance_pin;
    let initialized = false;
    if (!hash) {
      await pool.query("UPDATE creator_accounts SET finance_pin=$1 WHERE id=$2", [await bcrypt.hash(pin, 10), req.creator.sub]);
      initialized = true;
    } else if (!(await bcrypt.compare(pin, hash))) {
      return res.status(401).json({ error: "Incorrect finance PIN" });
    }
    const result = await pool.query(
      `SELECT
         COALESCE(SUM(CASE WHEN b.status <> 'refunded' THEN b.total ELSE 0 END),0)::NUMERIC AS gross,
         COALESCE(SUM(CASE WHEN b.status <> 'refunded' THEN b.qty ELSE 0 END),0)::INTEGER AS tickets
       FROM creator_events e
       LEFT JOIN bookings b ON b.event_id=e.id
       WHERE e.creator_id=$1`,
      [req.creator.sub]
    );
    const gross = Number(result.rows[0].gross || 0);
    res.json({ initialized, gross, net: Math.round(gross * 0.94), tickets: Number(result.rows[0].tickets || 0) });
  } catch (err) {
    console.error("Creator finance unlock failed:", err);
    res.status(500).json({ error: "Could not unlock finance" });
  }
});

app.post("/admin/login", async (req, res) => {
  try {
    const email = String((req.body && req.body.email) || "").trim().toLowerCase();
    const password = String((req.body && req.body.password) || "");
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }
    const result = await pool.query("SELECT * FROM admin_accounts WHERE email=$1", [email]);
    const admin = result.rows[0];
    if (!admin || admin.status !== "Active" || !(await bcrypt.compare(password, admin.password))) {
      return res.status(401).json({ error: "Invalid admin email or password" });
    }
    const updated = await pool.query(
      "UPDATE admin_accounts SET last_login=NOW() WHERE id=$1 RETURNING *",
      [admin.id]
    );
    res.json({
      message: "Admin login successful",
      admin: publicAdmin(updated.rows[0]),
      token: signJwt({ sub: admin.id, email: admin.email, scope: "admin" }),
    });
  } catch (err) {
    console.error("Admin login failed:", err);
    res.status(500).json({ error: "Admin login failed" });
  }
});

app.get("/admin/snapshot", requireAdmin, async (req, res) => {
  try {
    const [buyers, creators, events, bookings, payments, staff] = await Promise.all([
      pool.query(`
        SELECT u.id, u.username, u.first_name, u.last_name, u.email, u.city, u.created_at,
          COUNT(b.id)::INTEGER AS bookings
        FROM users u
        LEFT JOIN bookings b ON b.user_id=u.id OR (b.user_id IS NULL AND LOWER(b.buyer_email)=LOWER(u.email))
        GROUP BY u.id
        ORDER BY u.created_at DESC
      `),
      pool.query(`
        SELECT c.id, c.name, c.email, c.phone, c.category, c.kyc_status, c.created_at,
          COUNT(DISTINCT e.id)::INTEGER AS events,
          COALESCE(SUM(b.total),0)::NUMERIC AS revenue
        FROM creator_accounts c
        LEFT JOIN creator_events e ON e.creator_id=c.id
        LEFT JOIN bookings b ON b.event_id=e.id
        GROUP BY c.id
        ORDER BY c.created_at DESC
      `),
      pool.query(`
        SELECT e.*,
          COALESCE(SUM(b.qty),0)::INTEGER AS booking_count,
          COALESCE(SUM(b.total),0)::NUMERIC AS revenue
        FROM creator_events e
        LEFT JOIN bookings b ON b.event_id=e.id
        GROUP BY e.id
        ORDER BY e.created_at DESC
      `),
      pool.query("SELECT * FROM bookings ORDER BY booked_at DESC"),
      pool.query("SELECT * FROM payment_transactions ORDER BY updated_at DESC"),
      pool.query("SELECT * FROM staff_accounts ORDER BY created_at DESC"),
    ]);
    res.json({
      buyers: buyers.rows.map((buyer) => ({
        id: `USR-${buyer.id}`,
        name: buyer.username || [buyer.first_name, buyer.last_name].filter(Boolean).join(" ") || buyer.email,
        email: buyer.email,
        city: buyer.city || "",
        bookings: Number(buyer.bookings || 0),
        status: "Active",
        createdAt: buyer.created_at,
      })),
      creators: creators.rows.map((creator) => ({
        id: `CRT-${creator.id}`,
        creatorId: creator.id,
        name: creator.name,
        email: creator.email,
        phone: creator.phone,
        category: creator.category,
        status: creator.kyc_status,
        events: Number(creator.events || 0),
        revenue: Number(creator.revenue || 0),
        fee: 8,
        createdAt: creator.created_at,
      })),
      events: events.rows.map(publicCreatorEvent),
      bookings: bookings.rows.map((booking) => ({
        id: booking.id,
        userId: booking.user_id,
        buyerEmail: booking.buyer_email,
        buyer: booking.buyer_email || "Buyer",
        eventId: booking.event_id,
        eventName: booking.event_name,
        eventDate: booking.event_date,
        eventVenue: booking.event_venue,
        eventBanner: booking.event_banner,
        ticketType: booking.ticket_type,
        price: Number(booking.price || 0),
        qty: Number(booking.qty || 0),
        total: Number(booking.total || 0),
        status: booking.status,
        bookedAt: booking.booked_at,
      })),
      payments: payments.rows.map((payment) => ({
        txnid: payment.txnid,
        bookingId: payment.booking_id,
        eventId: payment.event_id,
        ticketType: payment.ticket_type,
        qty: Number(payment.qty || 0),
        buyerEmail: payment.buyer_email,
        amount: Number(payment.amount || 0),
        gatewayPaymentId: payment.gateway_payment_id,
        status: payment.status,
        verified: payment.verified,
        error: payment.error,
        updatedAt: payment.updated_at,
      })),
      staff: staff.rows.map((member) => ({
        id: member.id,
        creatorId: member.creator_id,
        name: member.name,
        staffId: member.staff_id,
        email: member.email,
        phone: member.phone,
        status: member.status,
        assignedTickets: Number(member.assigned_tickets || 0),
        soldTickets: Number(member.sold_tickets || 0),
        earnings: Number(member.earnings || 0),
        createdAt: member.created_at,
      })),
    });
  } catch (err) {
    console.error("Admin snapshot failed:", err);
    res.status(500).json({ error: "Could not load admin data" });
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

const savePaymentTransaction = async (fields, status, verified, error = "") => {
  const txnid = String(fields.txnid || "").trim();
  if (!txnid) return;
  await pool.query(
    `INSERT INTO payment_transactions (
      txnid, booking_id, event_id, ticket_type, qty, buyer_email, amount,
      gateway_payment_id, status, verified, error, updated_at
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW())
    ON CONFLICT (txnid) DO UPDATE SET
      booking_id=COALESCE(EXCLUDED.booking_id, payment_transactions.booking_id),
      event_id=COALESCE(EXCLUDED.event_id, payment_transactions.event_id),
      ticket_type=COALESCE(EXCLUDED.ticket_type, payment_transactions.ticket_type),
      qty=COALESCE(EXCLUDED.qty, payment_transactions.qty),
      buyer_email=COALESCE(EXCLUDED.buyer_email, payment_transactions.buyer_email),
      amount=EXCLUDED.amount,
      gateway_payment_id=COALESCE(EXCLUDED.gateway_payment_id, payment_transactions.gateway_payment_id),
      status=EXCLUDED.status,
      verified=EXCLUDED.verified,
      error=EXCLUDED.error,
      updated_at=NOW()`,
    [
      txnid,
      fields.udf1 || null,
      fields.udf2 || null,
      fields.udf3 || null,
      Number(fields.udf4 || 0) || null,
      fields.email || null,
      Number(fields.amount || 0),
      fields.mihpayid || null,
      status,
      Boolean(verified),
      error || null,
    ]
  );
};

const payuReturnHtml = (result) => `<!doctype html>
<html><head><meta charset="utf-8"><title>VYBERA Payment</title></head>
<body style="background:#000;color:#fff;font-family:Arial,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;">
<div>Completing payment...</div>
<script>
localStorage.setItem('VYBERA_PAYU_RESULT', ${JSON.stringify(JSON.stringify(result))});
window.location.replace('/?payment=payu&booking=' + encodeURIComponent(${JSON.stringify(result.bookingId || "")}));
</script>
</body></html>`;

const makeTicketQrPayload = (bookingId, token) => `VYBERA-TICKET|${bookingId}|${token}`;

const ticketResponse = async (booking) => {
  const qrPayload = makeTicketQrPayload(booking.id, booking.qr_token);
  return {
    id: booking.id,
    buyerName: booking.buyer_name || booking.buyer_email || "VYBERA Guest",
    buyerEmail: booking.buyer_email,
    eventId: booking.event_id,
    eventName: booking.event_name,
    eventDate: booking.event_date,
    eventVenue: booking.event_venue,
    eventBanner: booking.event_banner,
    ticketType: booking.ticket_type,
    price: Number(booking.price || 0),
    qty: Number(booking.qty || 1),
    total: Number(booking.total || 0),
    status: booking.status,
    scannedAt: booking.scanned_at,
    qrPayload,
    qrImage: await QRCode.toDataURL(qrPayload, { width: 320, margin: 2, errorCorrectionLevel: "M" }),
  };
};

app.post("/payments/payu/initiate", async (req, res) => {
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
      surl: `${origin}/payments/payu/success?booking=${encodeURIComponent(txnid)}`,
      furl: `${origin}/payments/payu/failure?booking=${encodeURIComponent(txnid)}`,
      udf1: cleanPayuText(req.body.bookingId || "", 64),
      udf2: cleanPayuText(req.body.eventId || "", 64),
      udf3: cleanPayuText(req.body.ticketType || "", 64),
      udf4: cleanPayuText(req.body.qty || "", 20),
      udf5: "vybera",
      service_provider: "payu_paisa",
    };
    fields.hash = makePayuHash(fields);
    await savePaymentTransaction(fields, "Pending", false);
    res.json({ action: payuConfig.action, fields });
  } catch (err) {
    console.error("PayU initiation failed:", err);
    res.status(500).json({ error: err.message || "PayU initiation failed" });
  }
});

app.post("/payments/payu/success", async (req, res) => {
  try {
    const body = req.body || {};
    const expected = makePayuResponseHash(body);
    const verified = Boolean(body.hash) && expected === body.hash;
    await savePaymentTransaction(body, verified ? "Success" : "Failed", verified, verified ? "" : "Payment signature could not be verified");
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

app.post("/payments/payu/failure", async (req, res) => {
  try {
    const body = req.body || {};
    let verified = false;
    if (body.hash && payuConfig.salt) {
      verified = makePayuResponseHash(body) === body.hash;
    }
    await savePaymentTransaction(body, "Failed", verified, body.error_Message || body.error || "Payment failed");
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
  const client = await pool.connect();
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

    await client.query("BEGIN");
    let userId = booking.userId || null;
    if (!userId && booking.buyerEmail) {
      const user = await client.query("SELECT id FROM users WHERE LOWER(email)=LOWER($1) LIMIT 1", [booking.buyerEmail]);
      userId = user.rows[0] ? user.rows[0].id : null;
    }
    const qrToken = crypto.randomBytes(18).toString("hex");
    let staffMember = null;
    const staffRef = String(
      booking.staffId ||
      booking.staffPk ||
      booking.staffRef ||
      (booking.staffReferral && (booking.staffReferral.staffDbId || booking.staffReferral.staffId || booking.staffReferral.token)) ||
      ""
    ).trim();
    if (staffRef) {
      const digits = staffRef.replace(/\D/g, "");
      const staffResult = await client.query(
        `SELECT * FROM staff_accounts
         WHERE status='active'
           AND (
             id=$1 OR share_token=$1 OR LOWER(staff_id)=LOWER($1)
             OR LOWER(COALESCE(email,''))=LOWER($1)
             OR regexp_replace(COALESCE(phone,''), '\\D', '', 'g')=$2
           )
         LIMIT 1`,
        [staffRef, digits]
      );
      staffMember = staffResult.rows[0] || null;
    }
    const savedBooking = await client.query(
      `INSERT INTO bookings (
        id, user_id, buyer_name, buyer_email, event_id, event_name, event_date, event_venue,
        event_banner, ticket_type, price, qty, total, status,
        ticket_record_url, ticket_record_key, ticket_record_storage, qr_token, staff_id, staff_ref, booked_at
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
      ON CONFLICT (id) DO UPDATE SET
        ticket_record_url=EXCLUDED.ticket_record_url,
        ticket_record_key=EXCLUDED.ticket_record_key,
        ticket_record_storage=EXCLUDED.ticket_record_storage,
        buyer_name=COALESCE(bookings.buyer_name, EXCLUDED.buyer_name),
        staff_id=COALESCE(bookings.staff_id, EXCLUDED.staff_id),
        staff_ref=COALESCE(bookings.staff_ref, EXCLUDED.staff_ref),
        qr_token=COALESCE(bookings.qr_token, EXCLUDED.qr_token)
      RETURNING *`,
      [
        booking.id,
        userId,
        booking.buyer || booking.buyerName || null,
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
        qrToken,
        staffMember ? staffMember.id : null,
        staffRef || null,
        booking.bookedAt ? new Date(booking.bookedAt) : new Date(),
      ]
    );
    if (staffMember && booking.eventId && booking.ticketType) {
      const assignmentResult = await client.query(
        `SELECT * FROM staff_assignments
         WHERE staff_id=$1 AND event_id=$2 AND tier_name=$3
         ORDER BY created_at DESC
         LIMIT 1
         FOR UPDATE`,
        [staffMember.id, booking.eventId, booking.ticketType]
      );
      const assignment = assignmentResult.rows[0] || null;
      const cleanQty = Number(booking.qty || 1);
      if (cleanQty > 0) {
        const existingStaffSale = await client.query(
          "SELECT id FROM staff_sales WHERE booking_id=$1 AND staff_id=$2 LIMIT 1",
          [booking.id, staffMember.id]
        );
        if (!existingStaffSale.rows.length) {
          let assignmentMode = "creator_quota";
          let salePrice = Number(booking.price || 0);
          let staffSaleTotal = salePrice * cleanQty;
          let commission = 0;
          let revenueOwner = "creator";
          let assignmentId = null;
          let saleEventName = booking.eventName || null;
          let canRecordSale = true;
          if (assignment) {
            assignmentMode = String(assignment.allocation_mode || "creator_quota") === "staff_owned" ? "staff_owned" : "creator_quota";
            salePrice = assignmentMode === "staff_owned"
              ? Number(assignment.resale_price || assignment.price || booking.price || 0)
              : Number(assignment.price || booking.price || 0);
            staffSaleTotal = salePrice * cleanQty;
            commission = assignmentMode === "creator_quota"
              ? Math.round(staffSaleTotal * Number(assignment.commission_rate || 0) / 100)
              : 0;
            revenueOwner = assignmentMode === "staff_owned" ? "staff" : "creator";
            assignmentId = assignment.id;
            saleEventName = booking.eventName || assignment.event_name;
            const remaining = Number(assignment.qty || 0) - Number(assignment.sold_count || 0);
            canRecordSale = remaining >= cleanQty;
          } else if (!salePrice && booking.total) {
            salePrice = Number(booking.total || 0) / cleanQty;
            staffSaleTotal = Number(booking.total || 0);
          }
          if (canRecordSale) {
          const saleId = `SLS-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`;
          await client.query(
            `INSERT INTO staff_sales (
              id, creator_id, staff_id, assignment_id, event_id, event_name, tier_name,
              buyer_name, buyer_phone, buyer_email, qty, price, total, payment_mode, booking_id,
              commission, revenue_owner, allocation_mode
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
            ON CONFLICT (id) DO NOTHING`,
            [
              saleId, staffMember.creator_id, staffMember.id, assignmentId, booking.eventId,
              saleEventName, booking.ticketType,
              booking.buyer || booking.buyerName || "Buyer", booking.buyerPhone || null, booking.buyerEmail || null,
              cleanQty, salePrice, staffSaleTotal, (booking.payment && booking.payment.gateway) ? "online" : "cash",
              booking.id, commission, revenueOwner, assignmentMode,
            ]
          );
          if (assignmentId) {
            await client.query("UPDATE staff_assignments SET sold_count=sold_count+$1 WHERE id=$2", [cleanQty, assignmentId]);
          }
          await client.query(
            "UPDATE staff_accounts SET sold_tickets=sold_tickets+$1, earnings=earnings+$2 WHERE id=$3",
            [cleanQty, revenueOwner === "staff" ? staffSaleTotal : commission, staffMember.id]
          );
          }
        }
      }
    }
    if (booking.eventId) {
      await client.query(
        `UPDATE creator_events e SET
           booking_count=COALESCE(s.tickets,0),
           revenue=COALESCE(s.revenue,0)
         FROM (
           SELECT event_id,
             COALESCE(SUM(CASE WHEN status <> 'refunded' THEN qty ELSE 0 END),0)::INTEGER AS tickets,
             COALESCE(SUM(CASE WHEN status <> 'refunded' THEN total ELSE 0 END),0)::NUMERIC AS revenue
           FROM bookings
           WHERE event_id=$1
           GROUP BY event_id
         ) s
         WHERE e.id=s.event_id`,
        [booking.eventId]
      );
    }
    await client.query("COMMIT");

    res.json({ booking: await ticketResponse(savedBooking.rows[0]) });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Booking save failed:", err);
    res.status(500).json({ error: err.message || "Booking save failed" });
  } finally {
    client.release();
  }
});

app.get("/bookings/mine", requireBuyer, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT *
       FROM bookings
       WHERE user_id=$1 OR (user_id IS NULL AND LOWER(buyer_email)=LOWER($2))
       ORDER BY booked_at DESC`,
      [req.buyer.sub, req.buyer.email]
    );
    const bookings = await Promise.all(result.rows.map(async (booking) => {
      if (!booking.qr_token) {
        const updated = await pool.query(
          "UPDATE bookings SET qr_token=$1 WHERE id=$2 RETURNING *",
          [crypto.randomBytes(24).toString("hex"), booking.id]
        );
        booking = updated.rows[0];
      }
      return ticketResponse(booking);
    }));
    res.json({ bookings });
  } catch (err) {
    console.error("Buyer booking history failed:", err);
    res.status(500).json({ error: "Could not load booking history" });
  }
});

app.get("/profile/tickets", requireProfileIdentity, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT b.*
       FROM bookings b
       LEFT JOIN users u ON u.id=b.user_id
       WHERE LOWER(COALESCE(b.buyer_email, u.email, ''))=LOWER($1)
       ORDER BY b.booked_at DESC`,
      [req.profileIdentity.email]
    );
    const bookings = await Promise.all(result.rows.map(async (booking) => {
      if (!booking.qr_token) {
        const updated = await pool.query(
          "UPDATE bookings SET qr_token=$1 WHERE id=$2 RETURNING *",
          [crypto.randomBytes(24).toString("hex"), booking.id]
        );
        booking = updated.rows[0];
      }
      return ticketResponse(booking);
    }));
    res.json({ bookings });
  } catch (err) {
    console.error("Profile tickets failed:", err);
    res.status(500).json({ error: "Could not load profile tickets" });
  }
});

app.get("/profile/creator-events", requireProfileIdentity, async (req, res) => {
  try {
    const result = await pool.query(
      `${creatorEventSalesQuery}
       JOIN creator_accounts c ON c.id=e.creator_id
       WHERE LOWER(c.email)=LOWER($1)
       GROUP BY e.id
       ORDER BY e.created_at DESC`,
      [req.profileIdentity.email]
    );
    res.json({ events: result.rows.map(publicCreatorEvent) });
  } catch (err) {
    console.error("Profile creator events failed:", err);
    res.status(500).json({ error: "Could not load your created events" });
  }
});

app.get("/bookings/:bookingId/ticket", async (req, res) => {
  try {
    const bookingId = String(req.params.bookingId || "").trim();
    let result = await pool.query("SELECT * FROM bookings WHERE id=$1", [bookingId]);
    if (!result.rows.length) return res.status(404).json({ error: "Ticket not found" });
    if (!result.rows[0].qr_token) {
      result = await pool.query(
        "UPDATE bookings SET qr_token=$1 WHERE id=$2 RETURNING *",
        [crypto.randomBytes(18).toString("hex"), bookingId]
      );
    }
    res.json({ booking: await ticketResponse(result.rows[0]) });
  } catch (err) {
    console.error("Ticket load failed:", err);
    res.status(500).json({ error: "Could not load ticket" });
  }
});

app.post("/bookings/scan", requireCreator, async (req, res) => {
  const client = await pool.connect();
  try {
    const payload = String((req.body && req.body.qrPayload) || "").trim();
    const parts = payload.split("|");
    if (parts.length !== 3 || parts[0] !== "VYBERA-TICKET") {
      return res.status(400).json({ result: "invalid", error: "Invalid VYBERA ticket QR" });
    }
    await client.query("BEGIN");
    const result = await client.query(
      `SELECT b.* FROM bookings b
       JOIN creator_events e ON e.id=b.event_id
       WHERE b.id=$1 AND b.qr_token=$2 AND e.creator_id=$3
       FOR UPDATE OF b`,
      [parts[1], parts[2], req.creator.sub]
    );
    if (!result.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ result: "invalid", error: "Ticket not found" });
    }
    const booking = result.rows[0];
    if (booking.status === "refunded") {
      await client.query("ROLLBACK");
      return res.status(409).json({ result: "invalid", error: "Ticket was refunded" });
    }
    if (booking.scanned_at) {
      await client.query("ROLLBACK");
      return res.status(409).json({ result: "duplicate", booking: await ticketResponse(booking) });
    }
    const updated = await client.query("UPDATE bookings SET scanned_at=NOW() WHERE id=$1 RETURNING *", [booking.id]);
    await client.query("COMMIT");
    res.json({ result: "valid", booking: await ticketResponse(updated.rows[0]) });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Ticket scan failed:", err);
    res.status(500).json({ result: "invalid", error: "Could not validate ticket" });
  } finally {
    client.release();
  }
});


// TWILIO OTP ENDPOINTS
const makeTwilioOtpToken = (identifier) =>
  signJwt({ scope: "twilio-phone-otp", identifier }, 10 * 60);

const normalizeOtpPhone = (countryCode, phoneNumber) => {
  const rawCountryCode = String(countryCode === undefined || countryCode === null ? "+91" : countryCode).trim();
  const rawPhoneNumber = String(phoneNumber || "").trim();
  const countryDigits = rawCountryCode.replace(/\D/g, "");
  const phoneDigits = rawPhoneNumber.replace(/\D/g, "");
  const isFullInternationalNumber =
    rawPhoneNumber.startsWith("+") ||
    rawPhoneNumber.startsWith("00") ||
    rawCountryCode === "+" ||
    rawCountryCode === "";
  const identifier = isFullInternationalNumber ? phoneDigits : `${countryDigits}${phoneDigits}`;

  if (!/^\d{7,15}$/.test(identifier)) {
    throw new Error("A valid phone number is required");
  }
  return {
    identifier,
    e164: `+${identifier}`,
  };
};

const verifyTwilioOtpToken = async (token, countryCode, phone) => {
  const { identifier } = normalizeOtpPhone(countryCode, phone);
  try {
    const payload = verifyJwt(token);
    if (payload.scope !== "twilio-phone-otp" || payload.identifier !== identifier) {
      throw new Error("OTP verification does not match this phone number");
    }
    return payload;
  } catch (err) {
    throw err;
  }
};

const sendTwilioOtp = async (req, res) => {
  try {
    const phoneNumber = String((req.body && req.body.phoneNumber) || "").trim();
    const countryCode = String((req.body && req.body.countryCode) || "+91").trim();
    const { e164 } = normalizeOtpPhone(countryCode, phoneNumber);

    if (!twilioClient || !twilioVerifyServiceSid) {
      return res.status(500).json({ sent: false, error: "Twilio Verify is not configured" });
    }

    const verification = await twilioClient.verify.v2
      .services(twilioVerifyServiceSid)
      .verifications
      .create({ to: e164, channel: twilioVerifyChannel });

    res.json({
      sent: true,
      status: verification.status,
      phoneNumber: e164,
      message: "OTP sent successfully",
    });
  } catch (err) {
    console.error("Twilio OTP send error:", err);
    const status = err.message === "A valid phone number is required" ? 400 : 500;
    res.status(status).json({ sent: false, error: err.message || "Twilio OTP send failed" });
  }
};

const verifyTwilioOtp = async (req, res) => {
  try {
    const phoneNumber = String((req.body && req.body.phoneNumber) || "").trim();
    const countryCode = String((req.body && req.body.countryCode) || "+91").trim();
    const otp = String((req.body && req.body.otp) || "").trim();
    const { identifier, e164 } = normalizeOtpPhone(countryCode, phoneNumber);

    if (!twilioClient || !twilioVerifyServiceSid) {
      return res.status(500).json({ verified: false, error: "Twilio Verify is not configured" });
    }
    if (!/^\d{6}$/.test(otp)) {
      return res.status(400).json({ verified: false, error: "OTP must be 6 digits" });
    }

    const verification = await twilioClient.verify.v2
      .services(twilioVerifyServiceSid)
      .verificationChecks
      .create({ to: e164, code: otp });

    if (verification.status !== "approved") {
      return res.status(400).json({ verified: false, error: "Invalid OTP" });
    }

    res.json({
      verified: true,
      accessToken: makeTwilioOtpToken(identifier),
      phoneNumber: e164,
      message: "OTP verified successfully",
    });
  } catch (err) {
    console.error("Twilio OTP verification failed:", err);
    const status = err.message === "A valid phone number is required" ? 400 : 500;
    res.status(status).json({ verified: false, error: err.message || "Twilio OTP verification failed" });
  }
};

app.post(["/otp/send", "/otp/twilio/send"], sendTwilioOtp);
app.post(["/otp/verify", "/otp/twilio/verify"], verifyTwilioOtp);

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

    // Verify with Twilio OTP token
    try {
      await verifyTwilioOtpToken(otpAccessToken, cleanCountryCode, cleanPhone);
    } catch (err) {
      return res.status(400).json({ error: "OTP verification failed. Please verify your phone number again." });
    }

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

app.use("/uploads", express.static(uploadsDir));
app.use(express.static(path.join(__dirname)));
app.use("/VYBERA", express.static(path.join(__dirname)));

const PORT = process.env.PORT || 3003;

app.listen(PORT, () => {

  console.log(
    `Server running on port ${PORT}`
  );

});
