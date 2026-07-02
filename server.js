const express = require("express");
const path    = require("path");
const jwt     = require("jsonwebtoken");
const bcrypt  = require("bcrypt");

const { pool } = require("./db");

const app  = express();
const PORT = process.env.PORT || 5000;

// ================================================================
// CONFIG  –  set these as environment variables in production!
// ================================================================
const JWT_SECRET      = process.env.JWT_SECRET      || "velora_jwt_secret_change_me";
const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET || "sk_test_your_paystack_key_here";

/*
  ================================================================
  REQUIRED DB TABLES — create these in your PostgreSQL database
  ================================================================

  CREATE TABLE IF NOT EXISTS Users (
    id               SERIAL PRIMARY KEY,
    "fullName"       VARCHAR(255),
    email            VARCHAR(255) UNIQUE,
    password         VARCHAR(255),
    "walletBalance"  DECIMAL(18,2) DEFAULT 0,
    "depositBalance" DECIMAL(18,2) DEFAULT 0,
    "referralCode"   VARCHAR(50),
    "referredBy"     VARCHAR(255),
    plan             VARCHAR(100) DEFAULT 'Starter',
    "isBlocked"      BOOLEAN DEFAULT false,
    "isAdmin"        BOOLEAN DEFAULT false,
    "withdrawPassword" VARCHAR(255),
    "bankName"       VARCHAR(255),
    "accountName"    VARCHAR(255),
    "accountNumber"  VARCHAR(20)
  );

  CREATE TABLE IF NOT EXISTS Tasks (
    id        SERIAL PRIMARY KEY,
    email     VARCHAR(255),
    date      DATE,
    completed INT DEFAULT 0,
    total     INT DEFAULT 0,
    reward    DECIMAL(18,2) DEFAULT 0,
    rewarded  BOOLEAN DEFAULT false
  );

  CREATE TABLE IF NOT EXISTS InvestmentPlans (
    id           SERIAL PRIMARY KEY,
    name         VARCHAR(100),
    price        DECIMAL(18,2),
    "dailyProfit" DECIMAL(18,2),
    "durationDays" INT
  );

  INSERT INTO InvestmentPlans (name, price, "dailyProfit", "durationDays") VALUES
    ('Starter', 5000,   500,   30),
    ('Silver',  15000,  1800,  30),
    ('Gold',    50000,  7000,  30),
    ('VIP',     100000, 15000, 30)
  ON CONFLICT DO NOTHING;

  CREATE TABLE IF NOT EXISTS UserInvestments (
    id          SERIAL PRIMARY KEY,
    email       VARCHAR(255),
    "planId"    INT,
    "planName"  VARCHAR(100),
    "dailyProfit" DECIMAL(18,2),
    "startDate" TIMESTAMP,
    active      BOOLEAN DEFAULT true
  );

  CREATE TABLE IF NOT EXISTS Transactions (
    id          SERIAL PRIMARY KEY,
    email       VARCHAR(255),
    type        VARCHAR(50),
    amount      DECIMAL(18,2),
    reference   VARCHAR(500),
    "createdAt" TIMESTAMP DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS Withdrawals (
    id          SERIAL PRIMARY KEY,
    email       VARCHAR(255),
    amount      DECIMAL(18,2),
    fee         DECIMAL(18,2) DEFAULT 0,
    status      VARCHAR(50) DEFAULT 'pending',
    "createdAt" TIMESTAMP DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS DailyOrders (
    id            SERIAL PRIMARY KEY,
    email         VARCHAR(255),
    "orderDate"   DATE,
    "orderRef"    VARCHAR(100),
    "productName" VARCHAR(255),
    "productPrice" DECIMAL(18,2),
    commission    DECIMAL(18,2),
    status        VARCHAR(50) DEFAULT 'pending'
  );

  CREATE TABLE IF NOT EXISTS DepositRequests (
    id          SERIAL PRIMARY KEY,
    email       VARCHAR(255),
    amount      DECIMAL(18,2),
    "planName"  VARCHAR(100),
    "proofNote" VARCHAR(500),
    status      VARCHAR(50) DEFAULT 'pending',
    "createdAt" TIMESTAMP DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS SystemSettings (
    key   VARCHAR(100) PRIMARY KEY,
    value TEXT
  );

  CREATE TABLE IF NOT EXISTS ShopInvestments (
    id          SERIAL PRIMARY KEY,
    email       VARCHAR(255),
    "shopId"    INT,
    amount      DECIMAL(18,2),
    "proofNote" VARCHAR(500),
    status      VARCHAR(50) DEFAULT 'pending',
    "startDate" TIMESTAMP,
    "createdAt" TIMESTAMP DEFAULT NOW()
  );
  ================================================================
*/

// ================================================================
// MIDDLEWARE
// ================================================================
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ================================================================
// HELPERS
// ================================================================
function generateReferralCode() {
  return Math.random().toString(36).substring(2, 8).toUpperCase();
}

// Returns today's date string in WAT (UTC+1) e.g. "2025-01-15"
function todayWAT() {
  const now = new Date();
  const wat = new Date(now.getTime() + 60 * 60 * 1000); // UTC+1
  return wat.toISOString().split("T")[0];
}

// ================================================================
// MIDDLEWARES – Auth
// ================================================================
function verifyToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: "No token" });
  try {
    req.user = jwt.verify(auth.split(" ")[1], JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

function verifyAdmin(req, res, next) {
  if (!req.user.isAdmin) return res.status(403).json({ message: "Admin only" });
  next();
}

// ================================================================
// AUTH  –  /api/auth/*
// ================================================================

// ── REGISTER ─────────────────────────────────────────────────────
app.post("/api/auth/register", async (req, res) => {
  const { fullName, email, password, referralCode } = req.body;

  if (!fullName || !email || !password)
    return res.status(400).json({ message: "All fields are required" });

  if (password.length < 6)
    return res.status(400).json({ message: "Password must be at least 6 characters" });

  try {
    const existing = await pool.query(
      'SELECT email FROM Users WHERE email = $1',
      [email]
    );
    if (existing.rows.length)
      return res.status(400).json({ message: "Email already registered" });

    let referrerEmail = null;
    if (referralCode) {
      const referrer = await pool.query(
        'SELECT email FROM Users WHERE "referralCode" = $1',
        [referralCode]
      );
      if (referrer.rows.length) referrerEmail = referrer.rows[0].email;
    }

    const hash    = await bcrypt.hash(password, 10);
    const refCode = generateReferralCode();

    await pool.query(
      `INSERT INTO Users ("fullName", email, password, "walletBalance", "referralCode", "referredBy", plan, "isBlocked", "isAdmin")
       VALUES ($1, $2, $3, 0, $4, $5, 'Starter', false, false)`,
      [fullName, email, hash, refCode, referrerEmail]
    );

    res.json({ message: "Registration successful ✔" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Registration error" });
  }
});

// ── LOGIN ─────────────────────────────────────────────────────────
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ message: "Email and password required" });

  try {
    const result = await pool.query(
      'SELECT * FROM Users WHERE email = $1',
      [email]
    );

    if (!result.rows.length)
      return res.status(400).json({ message: "User not found" });

    const user = result.rows[0];

    if (user.isBlocked === true)
      return res.status(403).json({ message: "Account banned" });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(400).json({ message: "Wrong password" });

    const token = jwt.sign(
      { email: user.email, isAdmin: user.isAdmin },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Login error" });
  }
});

// ================================================================
// USER  –  /api/user/*
// ================================================================

// ── PROFILE ───────────────────────────────────────────────────────
app.get("/api/user/profile", verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT "fullName", email, "walletBalance", COALESCE("depositBalance", 0) AS "depositBalance", "referralCode", plan
       FROM Users WHERE email = $1`,
      [req.user.email]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Profile error" });
  }
});

// ── DEPOSIT WALLET BALANCE ────────────────────────────────────────
app.get("/api/user/deposit-balance", verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT COALESCE("depositBalance", 0) AS "depositBalance" FROM Users WHERE email = $1',
      [req.user.email]
    );
    res.json({ depositBalance: result.rows[0]?.depositBalance || 0 });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Balance error" });
  }
});

// ── REFERRALS ─────────────────────────────────────────────────────
app.get("/api/user/referrals", verifyToken, async (req, res) => {
  try {
    const total = await pool.query(
      `SELECT COALESCE(SUM(amount), 0) AS total FROM Transactions
       WHERE email = $1 AND type = 'REFERRAL_BONUS'`,
      [req.user.email]
    );

    const referrals = await pool.query(
      'SELECT "fullName", email FROM Users WHERE "referredBy" = $1',
      [req.user.email]
    );

    res.json({
      totalEarnings: total.rows[0].total,
      referrals:     referrals.rows
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Referrals error" });
  }
});

// ── CHANGE LOGIN PASSWORD ─────────────────────────────────────────
app.post("/api/user/change-password", verifyToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword)
      return res.status(400).json({ message: "Both current and new password are required" });

    if (newPassword.length < 6)
      return res.status(400).json({ message: "New password must be at least 6 characters" });

    if (currentPassword === newPassword)
      return res.status(400).json({ message: "New password must be different from current password" });

    const userRes = await pool.query(
      'SELECT password, "withdrawPassword" FROM Users WHERE email = $1',
      [req.user.email]
    );

    if (!userRes.rows.length)
      return res.status(404).json({ message: "User not found" });

    const user = userRes.rows[0];

    const match = await bcrypt.compare(currentPassword, user.password);
    if (!match)
      return res.status(400).json({ message: "Current password is incorrect" });

    if (user.withdrawPassword) {
      const sameAsWithdraw = await bcrypt.compare(newPassword, user.withdrawPassword);
      if (sameAsWithdraw)
        return res.status(400).json({ message: "Login password must be different from your withdrawal password" });
    }

    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query(
      'UPDATE Users SET password = $1 WHERE email = $2',
      [hash, req.user.email]
    );

    res.json({ message: "Password changed successfully ✔" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Password change error" });
  }
});

// ================================================================
// BANK DETAILS  –  /api/user/bank-details
// ================================================================

app.get("/api/user/bank-details", verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT "bankName", "accountName", "accountNumber" FROM Users WHERE email = $1',
      [req.user.email]
    );
    res.json(result.rows[0] || {});
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Bank details error" });
  }
});

app.post("/api/user/bank-details", verifyToken, async (req, res) => {
  try {
    const { bankName, accountName, accountNumber } = req.body;

    if (!bankName || !accountName || !accountNumber)
      return res.status(400).json({ message: "All bank details are required" });

    if (!/^\d{10}$/.test(accountNumber))
      return res.status(400).json({ message: "Account number must be exactly 10 digits" });

    await pool.query(
      'UPDATE Users SET "bankName" = $1, "accountName" = $2, "accountNumber" = $3 WHERE email = $4',
      [bankName, accountName, accountNumber, req.user.email]
    );

    res.json({ message: "Bank details saved ✔" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Save error" });
  }
});

// ── ADMIN: GET PAYMENT BANK DETAILS ──────────────────────────────
app.get("/api/admin/bank-details", verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT key, value FROM SystemSettings
       WHERE key IN ('adminBankName','adminAccountName','adminAccountNumber')`
    );
    const data = {};
    result.rows.forEach(r => { data[r.key] = r.value; });
    res.json({
      bankName:      data.adminBankName      || null,
      accountName:   data.adminAccountName   || null,
      accountNumber: data.adminAccountNumber || null,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error fetching bank details" });
  }
});

// ── ADMIN: SET PAYMENT BANK DETAILS ──────────────────────────────
app.post("/api/admin/bank-details", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { bankName, accountName, accountNumber } = req.body;
    if (!bankName || !accountName || !accountNumber)
      return res.status(400).json({ message: "All fields required" });
    await setSetting("adminBankName",      bankName);
    await setSetting("adminAccountName",   accountName);
    await setSetting("adminAccountNumber", accountNumber);
    res.json({ message: "Payment bank details saved ✔" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Save error" });
  }
});

// ── ADMIN: RESET BANK DETAILS ─────────────────────────────────────
app.post("/api/admin/user/reset-bank", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { email } = req.body;
    await pool.query(
      'UPDATE Users SET "bankName" = NULL, "accountName" = NULL, "accountNumber" = NULL WHERE email = $1',
      [email]
    );
    res.json({ message: "Bank details reset ✔" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Reset error" });
  }
});

// ================================================================
// WITHDRAWAL PASSWORD  –  /api/user/withdraw-password
// ================================================================

app.get("/api/user/withdraw-password/status", verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT "withdrawPassword" FROM Users WHERE email = $1',
      [req.user.email]
    );
    const isSet = !!result.rows[0]?.withdrawPassword;
    res.json({ isSet });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Status error" });
  }
});

app.post("/api/user/withdraw-password", verifyToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!newPassword || newPassword.length < 6)
      return res.status(400).json({ message: "Password must be at least 6 characters" });

    const userRes = await pool.query(
      'SELECT password, "withdrawPassword" FROM Users WHERE email = $1',
      [req.user.email]
    );
    const user = userRes.rows[0];

    if (user.withdrawPassword) {
      if (!currentPassword)
        return res.status(400).json({ message: "Please enter your current withdrawal password" });

      const match = await bcrypt.compare(currentPassword, user.withdrawPassword);
      if (!match)
        return res.status(400).json({ message: "Current withdrawal password is incorrect" });
    }

    const sameAsLogin = await bcrypt.compare(newPassword, user.password);
    if (sameAsLogin)
      return res.status(400).json({ message: "Withdrawal password must be different from your login password" });

    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query(
      'UPDATE Users SET "withdrawPassword" = $1 WHERE email = $2',
      [hash, req.user.email]
    );

    res.json({ message: "Withdrawal password saved ✔" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Save error" });
  }
});

// ── ADMIN: RESET WITHDRAWAL PASSWORD ─────────────────────────────
app.post("/api/admin/reset-withdraw-password", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { email } = req.body;
    await pool.query(
      'UPDATE Users SET "withdrawPassword" = NULL WHERE email = $1',
      [email]
    );
    res.json({ message: "Withdrawal password reset. User must set a new one before withdrawing." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Reset error" });
  }
});

// ================================================================
// TASKS  –  /api/tasks/*
// ================================================================

app.get("/api/tasks", verifyToken, async (req, res) => {
  try {
    const today     = todayWAT();
    const dayOfWeek = new Date().getDay();

    if (dayOfWeek === 0 || dayOfWeek === 6) {
      return res.json({ completed: 0, total: 0, weekend: true });
    }

    const blackout = await isTaskBlackout();
    if (blackout) {
      return res.json({ completed: 0, total: 0, blackout: true });
    }

    let task = await pool.query(
      'SELECT * FROM Tasks WHERE email = $1 AND date = $2',
      [req.user.email, today]
    );

    if (!task.rows.length) {
      const userRes = await pool.query(
        'SELECT plan FROM Users WHERE email = $1',
        [req.user.email]
      );
      const plan  = userRes.rows[0]?.plan || "Starter";
      const total = plan === "VIP" ? 10 : plan === "Gold" ? 8 : plan === "Silver" ? 7 : 5;

      await pool.query(
        'INSERT INTO Tasks (email, date, completed, total, reward, rewarded) VALUES ($1, $2, 0, $3, 0, false)',
        [req.user.email, today, total]
      );
      return res.json({ completed: 0, total });
    }

    const t = task.rows[0];
    res.json({ completed: t.completed, total: t.total });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Tasks error" });
  }
});

app.post("/api/tasks/complete", verifyToken, async (req, res) => {
  return res.status(400).json({
    message: "Tasks are completed by approving your daily orders. Go to Daily Orders to proceed."
  });
});

// ================================================================
// PROFIT  –  /api/profit/*
// ================================================================

app.post("/api/profit/claim", verifyToken, async (req, res) => {
  try {
    const today = todayWAT();

    const task = await pool.query(
      'SELECT * FROM Tasks WHERE email = $1 AND date = $2',
      [req.user.email, today]
    );

    if (!task.rows.length || task.rows[0].completed < task.rows[0].total)
      return res.status(400).json({ message: "Complete all tasks first" });

    if (task.rows[0].rewarded === true)
      return res.status(400).json({ message: "Profit already claimed today" });

    const inv = await pool.query(
      `SELECT * FROM UserInvestments WHERE email = $1 AND active = true ORDER BY id DESC LIMIT 1`,
      [req.user.email]
    );

    if (!inv.rows.length)
      return res.status(400).json({ message: "No active investment found" });

    const profit     = inv.rows[0].dailyProfit;
    const profitDesc = "Daily profit";

    await pool.query(
      'UPDATE Users SET "walletBalance" = "walletBalance" + $1 WHERE email = $2',
      [profit, req.user.email]
    );
    await pool.query(
      'UPDATE Tasks SET rewarded = true, reward = $1 WHERE email = $2 AND date = $3',
      [profit, req.user.email, today]
    );
    await pool.query(
      `INSERT INTO Transactions (email, type, amount, reference, "createdAt")
       VALUES ($1, 'DAILY_PROFIT', $2, $3, NOW())`,
      [req.user.email, profit, profitDesc]
    );

    res.json({ message: `₦${profit} profit claimed ✔` });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Claim error" });
  }
});

// ================================================================
// DAILY ORDERS  –  /api/orders/*
// ================================================================

const PRODUCTS = [
  { name: "Wireless Earbuds Pro",         price: 15000 },
  { name: "Smart Watch Series X",         price: 45000 },
  { name: "Portable Power Bank 20000mAh", price: 8500  },
  { name: "Bluetooth Speaker Mini",       price: 12000 },
  { name: "USB-C Fast Charger 65W",       price: 6500  },
  { name: "Phone Case Premium",           price: 3500  },
  { name: "Laptop Stand Aluminium",       price: 18000 },
  { name: "Mechanical Keyboard RGB",      price: 35000 },
  { name: "Gaming Mouse Wireless",        price: 22000 },
  { name: "Webcam HD 1080p",              price: 25000 },
  { name: "LED Desk Lamp Smart",          price: 9500  },
  { name: "Neck Massager Electric",       price: 14000 },
  { name: "Air Purifier Compact",         price: 28000 },
  { name: "Coffee Maker Automatic",       price: 32000 },
  { name: "Blender Portable USB",         price: 11000 },
  { name: "Digital Kitchen Scale",        price: 7000  },
  { name: "Resistance Bands Set",         price: 5500  },
  { name: "Yoga Mat Premium",             price: 8000  },
  { name: "Stainless Water Bottle",       price: 4500  },
  { name: "Sunglasses Polarized",         price: 12500 },
  { name: "Portable Mini Projector",      price: 55000 },
  { name: "Electric Toothbrush",          price: 9000  },
  { name: "Smart Plug WiFi",              price: 6000  },
  { name: "Ring Light 10 inch",           price: 13000 },
  { name: "Foldable Drone Camera",        price: 75000 },
  { name: "Massage Gun Deep Tissue",      price: 28000 },
  { name: "Car Phone Holder Magnetic",    price: 4000  },
  { name: "Cooling Pad Laptop",           price: 10000 },
  { name: "Solar Power Bank",             price: 16000 },
  { name: "HDMI Cable 4K",                price: 3000  },
  { name: "Wrist Blood Pressure Monitor", price: 18500 },
  { name: "Mini Sewing Machine",          price: 22000 },
  { name: "Hair Dryer Professional",      price: 15500 },
  { name: "Electric Kettle 1.8L",         price: 11000 },
  { name: "Non-stick Frying Pan Set",     price: 20000 },
];

const ORDER_COUNTS = { Starter: 5, Silver: 12, Gold: 20, VIP: 35 };

app.get("/api/orders/today", verifyToken, async (req, res) => {
  try {
    const today = todayWAT();

    const dayOfWeek = new Date().getDay();
    if (dayOfWeek === 0 || dayOfWeek === 6) {
      return res.status(403).json({
        message: "Tasks are only available Monday to Friday. Please come back on a working day.",
        weekend: true
      });
    }

    const blackout = await isTaskBlackout();
    if (blackout) {
      const start = await getSetting("taskBlackoutStart");
      const end   = await getSetting("taskBlackoutEnd");
      return res.status(403).json({
        message: `Tasks are disabled from ${start} to ${end} (holiday period). No orders available.`,
        blackout: true
      });
    }

    const existing = await pool.query(
      'SELECT * FROM DailyOrders WHERE email = $1 AND "orderDate" = $2 ORDER BY id ASC',
      [req.user.email, today]
    );

    if (existing.rows.length) return res.json(existing.rows);

    const userResult = await pool.query(
      `SELECT u.plan, i."dailyProfit"
       FROM Users u
       LEFT JOIN UserInvestments i ON u.email = i.email AND i.active = true
       WHERE u.email = $1`,
      [req.user.email]
    );

    const plan        = userResult.rows[0]?.plan        || "Starter";
    const dailyProfit = userResult.rows[0]?.dailyProfit || 100;
    const totalOrders = ORDER_COUNTS[plan] || 5;
    const commission  = parseFloat((dailyProfit / totalOrders).toFixed(2));

    const shuffled = [...PRODUCTS].sort(() => Math.random() - 0.5).slice(0, totalOrders);

    for (let i = 0; i < shuffled.length; i++) {
      const p        = shuffled[i];
      const orderRef = "ORD-" + Date.now() + "-" + (i + 1);
      await pool.query(
        `INSERT INTO DailyOrders (email, "orderDate", "orderRef", "productName", "productPrice", commission, status)
         VALUES ($1, $2, $3, $4, $5, $6, 'pending')`,
        [req.user.email, today, orderRef, p.name, p.price, commission]
      );
    }

    const newOrders = await pool.query(
      'SELECT * FROM DailyOrders WHERE email = $1 AND "orderDate" = $2 ORDER BY id ASC',
      [req.user.email, today]
    );

    res.json(newOrders.rows);

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Orders error" });
  }
});

app.post("/api/orders/approve", verifyToken, async (req, res) => {
  try {
    const { orderId } = req.body;
    const today       = todayWAT();

    const order = await pool.query(
      'SELECT * FROM DailyOrders WHERE id = $1 AND email = $2',
      [orderId, req.user.email]
    );

    if (!order.rows.length)
      return res.status(404).json({ message: "Order not found" });

    if (order.rows[0].status === "approved")
      return res.status(400).json({ message: "Order already approved" });

    await pool.query(
      "UPDATE DailyOrders SET status = 'approved' WHERE id = $1 AND email = $2",
      [orderId, req.user.email]
    );

    const approvedRes = await pool.query(
      `SELECT COUNT(*) AS count FROM DailyOrders
       WHERE email = $1 AND "orderDate" = $2 AND status = 'approved'`,
      [req.user.email, today]
    );
    const totalRes = await pool.query(
      'SELECT COUNT(*) AS count FROM DailyOrders WHERE email = $1 AND "orderDate" = $2',
      [req.user.email, today]
    );

    const approvedCount = parseInt(approvedRes.rows[0].count);
    const totalCount    = parseInt(totalRes.rows[0].count);

    const taskRecord = await pool.query(
      'SELECT id FROM Tasks WHERE email = $1 AND date = $2',
      [req.user.email, today]
    );

    if (!taskRecord.rows.length) {
      await pool.query(
        'INSERT INTO Tasks (email, date, completed, total, reward, rewarded) VALUES ($1, $2, $3, $4, 0, false)',
        [req.user.email, today, approvedCount, totalCount]
      );
    } else {
      await pool.query(
        'UPDATE Tasks SET completed = $1, total = $2 WHERE email = $3 AND date = $4',
        [approvedCount, totalCount, req.user.email, today]
      );
    }

    res.json({
      message:   "Order approved ✔",
      completed: approvedCount,
      total:     totalCount,
      allDone:   approvedCount >= totalCount
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Approve error" });
  }
});

// ================================================================
// WITHDRAWAL  –  /api/withdraw/*
// ================================================================

app.post("/api/withdraw/request", verifyToken, async (req, res) => {
  try {
    const { amount, withdrawPassword, source } = req.body;
    const withdrawSource = source || "main";

    if (!amount || Number(amount) < 500)
      return res.status(400).json({ message: "Minimum withdrawal is ₦500" });

    if (!withdrawPassword)
      return res.status(400).json({ message: "Withdrawal password is required" });

    const planDayRes = await pool.query(
      'SELECT plan FROM Users WHERE email = $1',
      [req.user.email]
    );
    const userPlanWD = planDayRes.rows[0]?.plan || "None";
    if (userPlanWD && userPlanWD !== "None") {
      const allowedDay = await getSetting(`planWithdrawDay_${userPlanWD}`);
      if (allowedDay && allowedDay !== "null" && allowedDay !== "any") {
        const DAY_NAMES_W = ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"];
        const todayDay    = new Date().getDay();
        if (String(todayDay) !== String(allowedDay)) {
          return res.status(400).json({
            message: `${userPlanWD} plan withdrawals are only allowed on ${DAY_NAMES_W[Number(allowedDay)]}s.`
          });
        }
      }
    }

    const activeMode = await getActiveWithdrawMode();
    if (withdrawSource !== activeMode) {
      const blockedLabel = withdrawSource === "main" ? "Main wallet" : "Referral";
      const activeLabel  = activeMode === "main" ? "main wallet" : "referral earnings";
      return res.status(400).json({
        message: `${blockedLabel} withdrawals are currently disabled. Only ${activeLabel} withdrawals are allowed right now.`
      });
    }

    const userRes = await pool.query(
      'SELECT "walletBalance", "withdrawPassword" FROM Users WHERE email = $1',
      [req.user.email]
    );

    if (!userRes.rows.length)
      return res.status(404).json({ message: "User not found" });

    const user = userRes.rows[0];

    if (!user.withdrawPassword)
      return res.status(400).json({ message: "Please set a withdrawal password first in Bank Details" });

    const pwMatch = await bcrypt.compare(withdrawPassword, user.withdrawPassword);
    if (!pwMatch)
      return res.status(400).json({ message: "Incorrect withdrawal password" });

    if (user.walletBalance < Number(amount))
      return res.status(400).json({ message: "Insufficient balance" });

    const grossAmount = Number(amount);
    const fee         = parseFloat((grossAmount * 0.08).toFixed(2));
    const netAmount   = parseFloat((grossAmount - fee).toFixed(2));

    const withdrawDesc = "Withdrawal request";

    await pool.query(
      'UPDATE Users SET "walletBalance" = "walletBalance" - $1 WHERE email = $2',
      [grossAmount, req.user.email]
    );
    await pool.query(
      `INSERT INTO Withdrawals (email, amount, fee, status, "createdAt")
       VALUES ($1, $2, $3, 'pending', NOW())`,
      [req.user.email, grossAmount, fee]
    );
    await pool.query(
      `INSERT INTO Transactions (email, type, amount, reference, "createdAt")
       VALUES ($1, 'WITHDRAW', $2, $3, NOW())`,
      [req.user.email, grossAmount, withdrawDesc]
    );

    res.json({ message: `Withdrawal request submitted ✔ A fee of ₦${fee.toLocaleString()} (8%) has been deducted. You will receive ₦${netAmount.toLocaleString()}.` });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Withdrawal error" });
  }
});

// ================================================================
// INVESTMENTS  –  /api/invest/*
// ================================================================

app.get("/api/invest/plans", async (req, res) => {
  try {
    const plans = await pool.query('SELECT * FROM InvestmentPlans ORDER BY price ASC');
    res.json(plans.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Plans error" });
  }
});

app.post("/api/invest/activate", verifyToken, async (req, res) => {
  try {
    const { planId } = req.body;

    const planResult = await pool.query(
      'SELECT * FROM InvestmentPlans WHERE id = $1',
      [planId]
    );
    if (!planResult.rows.length)
      return res.status(404).json({ message: "Plan not found" });

    const plan = planResult.rows[0];

    const user = await pool.query(
      'SELECT COALESCE("depositBalance", 0) AS "depositBalance" FROM Users WHERE email = $1',
      [req.user.email]
    );
    const depBal = Number(user.rows[0]?.depositBalance || 0);
    if (depBal < plan.price)
      return res.status(400).json({ message: "Insufficient deposit wallet balance. Please fund your deposit wallet first." });

    const startDate  = new Date();
    const investDesc = `${plan.name} plan activated`;

    await pool.query(
      `UPDATE Users SET "depositBalance" = COALESCE("depositBalance", 0) - $1, plan = $2 WHERE email = $3`,
      [plan.price, plan.name, req.user.email]
    );
    await pool.query(
      'UPDATE UserInvestments SET active = false WHERE email = $1',
      [req.user.email]
    );
    await pool.query(
      `INSERT INTO UserInvestments (email, "planId", "planName", "dailyProfit", "startDate", active)
       VALUES ($1, $2, $3, $4, $5, true)`,
      [req.user.email, plan.id, plan.name, plan.dailyProfit, startDate]
    );
    await pool.query(
      `INSERT INTO Transactions (email, type, amount, reference, "createdAt")
       VALUES ($1, 'INVESTMENT', $2, $3, NOW())`,
      [req.user.email, plan.price, investDesc]
    );

    const referredByRes = await pool.query(
      'SELECT "referredBy" FROM Users WHERE email = $1',
      [req.user.email]
    );
    const referredBy = referredByRes.rows[0]?.referredBy;
    if (referredBy) {
      const referralBonus = Math.round(plan.price * 0.10);
      const bonusDesc     = `Referral bonus – ${req.user.email} activated ${plan.name} plan`;
      await pool.query(
        'UPDATE Users SET "walletBalance" = "walletBalance" + $1 WHERE email = $2',
        [referralBonus, referredBy]
      );
      await pool.query(
        `INSERT INTO Transactions (email, type, amount, reference, "createdAt")
         VALUES ($1, 'REFERRAL_BONUS', $2, $3, NOW())`,
        [referredBy, referralBonus, bonusDesc]
      );
    }

    res.json({ message: `${plan.name} plan activated ✔` });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Activation error" });
  }
});

app.get("/api/invest/my", verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM UserInvestments WHERE email = $1 ORDER BY id DESC',
      [req.user.email]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Investments error" });
  }
});

// ── WALLET HISTORY ────────────────────────────────────────────────
app.get("/api/wallet/history", verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM Transactions WHERE email = $1 ORDER BY id DESC',
      [req.user.email]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "History error" });
  }
});

// ================================================================
// ADMIN  –  /api/admin/*
// ================================================================

app.get("/api/admin/analytics", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const users       = await pool.query('SELECT COUNT(*) AS "totalUsers" FROM Users');
    const wallet      = await pool.query('SELECT COALESCE(SUM("walletBalance"), 0) AS "totalWallet" FROM Users');
    const investments = await pool.query('SELECT COUNT(*) AS "totalInvestments" FROM UserInvestments');
    const referrals   = await pool.query(
      `SELECT COALESCE(SUM(amount), 0) AS "totalReferral" FROM Transactions WHERE type = 'REFERRAL_BONUS'`
    );
    const withdrawals = await pool.query(
      `SELECT COALESCE(SUM(amount), 0) AS "totalWithdrawals" FROM Transactions WHERE type = 'WITHDRAW'`
    );
    const fundDeposit = await pool.query(
      `SELECT COALESCE(SUM(amount), 0) AS "totalFundDepositWallet" FROM Transactions WHERE type = 'DEPOSIT_WALLET'`
    );
    const activity = await pool.query('SELECT * FROM Transactions ORDER BY id DESC LIMIT 10');

    res.json({
      totalUsers:       users.rows[0].totalUsers,
      totalWallet:      wallet.rows[0].totalWallet,
      totalInvestments: investments.rows[0].totalInvestments,
      totalReferral:    referrals.rows[0].totalReferral,
      totalWithdrawals: withdrawals.rows[0].totalWithdrawals,
      totalFundDepositWallet: fundDeposit.rows[0].totalFundDepositWallet,
      activity:         activity.rows
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Analytics error" });
  }
});

app.get("/api/admin/users", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const users = await pool.query(
      'SELECT "fullName", email, "walletBalance", plan, "isBlocked", "isAdmin" FROM Users'
    );
    res.json(users.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Users error" });
  }
});

app.get("/api/admin/withdrawals", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const withdrawals = await pool.query(
      `SELECT w.id, w.email, w.amount,
              COALESCE(w.fee, ROUND(w.amount * 0.08, 2)) AS fee,
              w.amount - COALESCE(w.fee, ROUND(w.amount * 0.08, 2)) AS "netAmount",
              w.status, w."createdAt",
              u."bankName", u."accountName", u."accountNumber"
       FROM Withdrawals w
       LEFT JOIN Users u ON w.email = u.email
       ORDER BY w.id DESC`
    );
    res.json(withdrawals.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Withdrawals error" });
  }
});

app.post("/api/admin/withdraw/approve", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { id } = req.body;

    const w = await pool.query('SELECT * FROM Withdrawals WHERE id = $1', [id]);
    if (!w.rows.length)
      return res.status(404).json({ message: "Withdrawal not found" });

    if (w.rows[0].status !== "pending")
      return res.status(400).json({ message: "Already processed" });

    await pool.query("UPDATE Withdrawals SET status = 'approved' WHERE id = $1", [id]);
    res.json({ message: "Withdrawal approved ✔" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Approve error" });
  }
});

app.post("/api/admin/withdraw/reject", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { id, email, amount } = req.body;

    const w = await pool.query('SELECT * FROM Withdrawals WHERE id = $1', [id]);
    if (!w.rows.length)
      return res.status(404).json({ message: "Withdrawal not found" });

    if (w.rows[0].status !== "pending")
      return res.status(400).json({ message: "Already processed" });

    const refundDesc = "Withdrawal rejected - refunded";

    await pool.query(
      'UPDATE Users SET "walletBalance" = "walletBalance" + $1 WHERE email = $2',
      [amount, email]
    );
    await pool.query("UPDATE Withdrawals SET status = 'rejected' WHERE id = $1", [id]);
    await pool.query(
      `INSERT INTO Transactions (email, type, amount, reference, "createdAt")
       VALUES ($1, 'REFUND', $2, $3, NOW())`,
      [email, amount, refundDesc]
    );

    res.json({ message: "Withdrawal rejected and refunded ✔" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Reject error" });
  }
});

app.post("/api/admin/invest/end", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { email } = req.body;

    const inv = await pool.query(
      'SELECT id FROM UserInvestments WHERE email = $1 AND active = true',
      [email]
    );

    if (!inv.rows.length)
      return res.status(404).json({ message: "No active investment found for this user" });

    await pool.query(
      'UPDATE UserInvestments SET active = false WHERE email = $1 AND active = true',
      [email]
    );
    await pool.query(
      "UPDATE Users SET plan = 'Starter' WHERE email = $1",
      [email]
    );

    res.json({ message: "Investment ended ✔" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "End investment error" });
  }
});

app.post("/api/admin/user/toggle-ban", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { email } = req.body;

    const user = await pool.query('SELECT "isBlocked" FROM Users WHERE email = $1', [email]);
    if (!user.rows.length)
      return res.status(404).json({ message: "User not found" });

    const newStatus = !user.rows[0].isBlocked;

    await pool.query('UPDATE Users SET "isBlocked" = $1 WHERE email = $2', [newStatus, email]);
    res.json({ message: newStatus ? "User banned ❌" : "User unbanned ✅" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Ban error" });
  }
});

app.post("/api/admin/reset-password", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { email }    = req.body;
    const tempPassword = Math.random().toString(36).slice(-8);
    const hash         = await bcrypt.hash(tempPassword, 10);

    await pool.query('UPDATE Users SET password = $1 WHERE email = $2', [hash, email]);
    res.json({ message: "Password reset ✔", tempPassword });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Reset error" });
  }
});

// ================================================================
// SYSTEM SETTINGS
// ================================================================

app.get("/api/admin/settings", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT key, value FROM SystemSettings');
    const settings = {};
    result.rows.forEach(r => { settings[r.key] = r.value; });
    const today = todayWAT();
    const start = settings.withdrawStart;
    const end   = settings.withdrawEnd;
    settings.currentWithdrawMode = (start && end && start !== "null" && end !== "null" && today >= start && today <= end)
      ? "main" : "referral";
    res.json(settings);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Settings error" });
  }
});

// ── HELPER: upsert a setting ──────────────────────────────────────
async function setSetting(key, value) {
  await pool.query(
    `INSERT INTO SystemSettings (key, value) VALUES ($1, $2)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
    [key, value]
  );
}

// ── HELPER: get a setting ─────────────────────────────────────────
async function getSetting(key) {
  const result = await pool.query('SELECT value FROM SystemSettings WHERE key = $1', [key]);
  return result.rows[0]?.value || null;
}

// ================================================================
// TASK BLACKOUT  –  /api/admin/task-blackout
// ================================================================

app.post("/api/admin/task-blackout", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { startDate, endDate } = req.body;

    if (!startDate || !endDate)
      return res.status(400).json({ message: "Start and end date are required" });

    if (new Date(startDate) > new Date(endDate))
      return res.status(400).json({ message: "Start date must be before end date" });

    await setSetting("taskBlackoutStart", startDate);
    await setSetting("taskBlackoutEnd",   endDate);

    res.json({ message: `Task blackout set from ${startDate} to ${endDate} ✔` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Blackout error" });
  }
});

app.post("/api/admin/task-blackout/clear", verifyToken, verifyAdmin, async (req, res) => {
  try {
    await setSetting("taskBlackoutStart", null);
    await setSetting("taskBlackoutEnd",   null);
    res.json({ message: "Task blackout cleared ✔" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Clear error" });
  }
});

async function isTaskBlackout() {
  const start = await getSetting("taskBlackoutStart");
  const end   = await getSetting("taskBlackoutEnd");
  if (!start || !end) return false;
  const today = todayWAT();
  return today >= start && today <= end;
}

// ================================================================
// WITHDRAWAL SCHEDULE  –  /api/admin/withdrawal-schedule
// ================================================================

app.post("/api/admin/withdrawal-schedule", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { startDate, endDate } = req.body;
    if (!startDate || !endDate)
      return res.status(400).json({ message: "Start and end date required" });
    if (startDate > endDate)
      return res.status(400).json({ message: "Start must be before end date" });
    await setSetting("withdrawStart", startDate);
    await setSetting("withdrawEnd",   endDate);
    res.json({ message: `Main wallet withdrawals scheduled from ${startDate} to ${endDate} ✔` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Schedule error" });
  }
});

app.post("/api/admin/withdrawal-schedule/clear", verifyToken, verifyAdmin, async (req, res) => {
  try {
    await setSetting("withdrawStart", null);
    await setSetting("withdrawEnd",   null);
    res.json({ message: "Withdrawal schedule cleared. Referral withdrawals are now active ✔" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Clear error" });
  }
});

async function getActiveWithdrawMode() {
  const start = await getSetting("withdrawStart");
  const end   = await getSetting("withdrawEnd");
  if (!start || !end || start === "null" || end === "null") return "referral";
  const today = todayWAT();
  return (today >= start && today <= end) ? "main" : "referral";
}

app.get("/api/admin/withdrawal-mode", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const mode = await getActiveWithdrawMode();
    res.json({ mode });
  } catch (err) {
    res.status(500).json({ message: "Mode error" });
  }
});

app.get("/api/withdrawal-mode", verifyToken, async (req, res) => {
  try {
    const mode = await getActiveWithdrawMode();
    res.json({ mode });
  } catch (err) {
    res.json({ mode: "referral" });
  }
});

// ================================================================
// MANUAL DEPOSIT REQUESTS  –  /api/deposit-request/*
// ================================================================

app.post("/api/deposit-request", verifyToken, async (req, res) => {
  try {
    const { amount, planName, proofNote } = req.body;

    if (!amount || Number(amount) <= 0)
      return res.status(400).json({ message: "Valid amount is required" });

    if (!planName)
      return res.status(400).json({ message: "Plan name is required" });

    await pool.query(
      `INSERT INTO DepositRequests (email, amount, "planName", "proofNote", status, "createdAt")
       VALUES ($1, $2, $3, $4, 'pending', NOW())`,
      [req.user.email, Number(amount), planName, proofNote || ""]
    );

    res.json({ message: "Deposit request submitted. Awaiting admin confirmation ✔" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Request error" });
  }
});

app.get("/api/deposit-request/my", verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM DepositRequests WHERE email = $1 ORDER BY id DESC',
      [req.user.email]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Fetch error" });
  }
});

app.get("/api/admin/deposit-requests", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM DepositRequests ORDER BY id DESC');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Fetch error" });
  }
});

app.post("/api/admin/deposit-request/confirm", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { id } = req.body;

    const reqRes = await pool.query('SELECT * FROM DepositRequests WHERE id = $1', [id]);
    if (!reqRes.rows.length)
      return res.status(404).json({ message: "Request not found" });

    const dr = reqRes.rows[0];

    if (dr.status !== "pending")
      return res.status(400).json({ message: "Already processed" });

    const depositDesc = `Manual deposit confirmed – ${dr.planName} plan`;

    await pool.query(
      'UPDATE Users SET "depositBalance" = COALESCE("depositBalance", 0) + $1 WHERE email = $2',
      [dr.amount, dr.email]
    );
    await pool.query(
      `INSERT INTO Transactions (email, type, amount, reference, "createdAt")
       VALUES ($1, 'DEPOSIT_WALLET', $2, $3, NOW())`,
      [dr.email, dr.amount, depositDesc]
    );
    await pool.query(
      "UPDATE DepositRequests SET status = 'confirmed' WHERE id = $1",
      [id]
    );

    res.json({ message: `₦${Number(dr.amount).toLocaleString()} credited to ${dr.email} ✔` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Confirm error" });
  }
});

app.post("/api/admin/deposit-request/reject", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { id } = req.body;

    const reqRes = await pool.query('SELECT * FROM DepositRequests WHERE id = $1', [id]);
    if (!reqRes.rows.length)
      return res.status(404).json({ message: "Request not found" });

    if (reqRes.rows[0].status !== "pending")
      return res.status(400).json({ message: "Already processed" });

    await pool.query("UPDATE DepositRequests SET status = 'rejected' WHERE id = $1", [id]);
    res.json({ message: "Deposit request rejected ✔" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Reject error" });
  }
});

// ================================================================
// ANNOUNCEMENTS  –  /api/announcement
// ================================================================

app.post("/api/admin/announcement", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text || !text.trim())
      return res.status(400).json({ message: "Announcement text is required" });
    await setSetting("announcementText", text.trim());
    await setSetting("announcementDate", new Date().toISOString());
    res.json({ message: "Announcement published ✔" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Save error" });
  }
});

app.post("/api/admin/announcement/clear", verifyToken, verifyAdmin, async (req, res) => {
  try {
    await setSetting("announcementText", null);
    await setSetting("announcementDate", null);
    res.json({ message: "Announcement cleared ✔" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Clear error" });
  }
});

app.get("/api/announcement", verifyToken, async (req, res) => {
  try {
    const text = await getSetting("announcementText");
    const date = await getSetting("announcementDate");
    if (!text || text === "null") return res.json({ active: false });
    res.json({ active: true, text, date });
  } catch (err) {
    res.json({ active: false });
  }
});

// ================================================================
// SHOP FILL SETTINGS
// ================================================================

app.post("/api/admin/shop-fill", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { shopId, percent, totalSlots } = req.body;
    if (!shopId || shopId < 1 || shopId > 5)
      return res.status(400).json({ message: "Invalid shop ID (1-5)" });
    if (percent === undefined || percent < 0 || percent > 100)
      return res.status(400).json({ message: "Percent must be between 0 and 100" });
    if (!totalSlots || totalSlots < 1)
      return res.status(400).json({ message: "Total slots must be at least 1" });

    await setSetting(`shopFill_${shopId}`, JSON.stringify({ percent: Number(percent), totalSlots: Number(totalSlots) }));
    res.json({ message: `Shop ${shopId} fill updated ✔` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Save error" });
  }
});

app.get("/api/shop-fills", verifyToken, async (req, res) => {
  try {
    const fills = {};
    for (let i = 1; i <= 5; i++) {
      const val = await getSetting(`shopFill_${i}`);
      if (val && val !== "null") {
        try { fills[i] = JSON.parse(val); } catch { fills[i] = null; }
      } else {
        fills[i] = null;
      }
    }
    res.json(fills);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Fetch error" });
  }
});

// ================================================================
// PLAN WITHDRAWAL DAY SETTINGS
// ================================================================

app.post("/api/admin/plan-withdraw-day", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { plan, day } = req.body;
    const validPlans = ["Starter","Silver","Gold","VIP"];
    if (!validPlans.includes(plan))
      return res.status(400).json({ message: "Invalid plan name" });
    await setSetting(`planWithdrawDay_${plan}`, String(day));
    res.json({ message: `Withdrawal day set for ${plan} plan ✔` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Save error" });
  }
});

app.get("/api/plan-withdraw-days", verifyToken, async (req, res) => {
  try {
    const plans = ["Starter","Silver","Gold","VIP"];
    const result = {};
    for (const p of plans) {
      const val = await getSetting(`planWithdrawDay_${p}`);
      result[p] = (val && val !== "null") ? val : "any";
    }
    res.json(result);
  } catch (err) {
    res.json({ Starter:"any", Silver:"any", Gold:"any", VIP:"any" });
  }
});

// ================================================================
// TASK BLACKOUT CHECK
// ================================================================

app.get("/api/tasks/blackout-check", verifyToken, async (req, res) => {
  try {
    const blocked = await isTaskBlackout();
    if (blocked) {
      const start = await getSetting("taskBlackoutStart");
      const end   = await getSetting("taskBlackoutEnd");
      return res.json({ blocked: true, start, end });
    }
    res.json({ blocked: false });
  } catch (err) {
    res.json({ blocked: false });
  }
});

// ================================================================
// IN-SHOP INVESTMENTS  –  /api/shop-invest/*
// ================================================================

const SHOP_CONFIG = {
  1: { name:"Shop 1 – Stationery",        duration:60,  rate:0.05, min:5000   },
  2: { name:"Shop 2 – Electronics",        duration:120, rate:0.10, min:20000  },
  3: { name:"Shop 3 – Fashion & Clothing", duration:210, rate:0.15, min:50000  },
  4: { name:"Shop 4 – Supermarket",        duration:270, rate:0.20, min:100000 },
  5: { name:"Shop 5 – Wholesale",          duration:365, rate:0.25, min:200000 },
};

app.post("/api/shop-invest/request", verifyToken, async (req, res) => {
  try {
    const { shopId, amount } = req.body;
    const shop = SHOP_CONFIG[shopId];
    if (!shop)
      return res.status(400).json({ message: "Invalid shop" });
    if (!amount || Number(amount) < shop.min)
      return res.status(400).json({ message: `Minimum investment for this shop is ₦${shop.min.toLocaleString()}` });

    const fillVal = await getSetting(`shopFill_${shopId}`);
    if (fillVal && fillVal !== "null") {
      try {
        const fillData = JSON.parse(fillVal);
        if (fillData.percent >= 100)
          return res.status(400).json({ message: "This shop is fully funded. No new investments are accepted at this time." });
      } catch {}
    }

    const userRes = await pool.query(
      'SELECT COALESCE("depositBalance", 0) AS "depositBalance" FROM Users WHERE email = $1',
      [req.user.email]
    );
    const depBal = Number(userRes.rows[0]?.depositBalance || 0);
    if (depBal < Number(amount))
      return res.status(400).json({ message: "Insufficient deposit wallet balance. Please fund your deposit wallet first." });

    await pool.query(
      'UPDATE Users SET "depositBalance" = COALESCE("depositBalance", 0) - $1 WHERE email = $2',
      [Number(amount), req.user.email]
    );

    const now = new Date();
    await pool.query(
      `INSERT INTO ShopInvestments (email, "shopId", amount, "proofNote", status, "startDate", "createdAt")
       VALUES ($1, $2, $3, $4, 'active', $5, NOW())`,
      [req.user.email, shopId, Number(amount), "", now]
    );

    const desc = `${shop.name} investment activated`;
    await pool.query(
      `INSERT INTO Transactions (email, type, amount, reference, "createdAt")
       VALUES ($1, 'SHOP_INVEST', $2, $3, NOW())`,
      [req.user.email, Number(amount), desc]
    );

    res.json({ message: "Investment activated ✔ Your investment starts today!" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Request error" });
  }
});

app.get("/api/shop-invest/my", verifyToken, async (req, res) => {
  try {
    await processMaturedShopInvestments(req.user.email);
    const { shopId } = req.query;
    const result = await pool.query(
      'SELECT * FROM ShopInvestments WHERE email = $1 AND "shopId" = $2 ORDER BY id DESC',
      [req.user.email, shopId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Fetch error" });
  }
});

app.get("/api/shop-invest/my/all", verifyToken, async (req, res) => {
  try {
    await processMaturedShopInvestments(req.user.email);
    const result = await pool.query(
      'SELECT * FROM ShopInvestments WHERE email = $1 ORDER BY id DESC',
      [req.user.email]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Fetch error" });
  }
});

app.get("/api/admin/shop-investments", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM ShopInvestments ORDER BY id DESC');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Fetch error" });
  }
});

app.post("/api/admin/shop-invest/confirm", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { id } = req.body;
    const invRes = await pool.query('SELECT * FROM ShopInvestments WHERE id = $1', [id]);
    if (!invRes.rows.length)
      return res.status(404).json({ message: "Investment not found" });

    const inv = invRes.rows[0];
    if (inv.status !== "pending")
      return res.status(400).json({ message: "Already processed" });

    const shop = SHOP_CONFIG[inv.shopId];
    const now  = new Date();

    await pool.query(
      "UPDATE ShopInvestments SET status = 'active', \"startDate\" = $1 WHERE id = $2",
      [now, id]
    );

    const desc = `${shop.name} investment confirmed`;
    await pool.query(
      `INSERT INTO Transactions (email, type, amount, reference, "createdAt")
       VALUES ($1, 'SHOP_INVEST', $2, $3, NOW())`,
      [inv.email, inv.amount, desc]
    );

    res.json({ message: `Investment confirmed ✔ Starts today, ends in ${shop.duration} days.` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Confirm error" });
  }
});

app.post("/api/admin/shop-invest/reject", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { id } = req.body;
    const invRes = await pool.query('SELECT * FROM ShopInvestments WHERE id = $1', [id]);
    if (!invRes.rows.length)
      return res.status(404).json({ message: "Not found" });
    if (invRes.rows[0].status !== "pending")
      return res.status(400).json({ message: "Already processed" });

    const rejInv = invRes.rows[0];
    await pool.query(
      'UPDATE Users SET "depositBalance" = COALESCE("depositBalance", 0) + $1 WHERE email = $2',
      [rejInv.amount, rejInv.email]
    );
    await pool.query(
      `INSERT INTO Transactions (email, type, amount, reference, "createdAt")
       VALUES ($1, 'SHOP_INVEST_REFUND', $2, 'Shop investment rejected - refunded to deposit wallet', NOW())`,
      [rejInv.email, rejInv.amount]
    );
    await pool.query("UPDATE ShopInvestments SET status = 'rejected' WHERE id = $1", [id]);
    res.json({ message: "Investment request rejected and deposit wallet refunded ✔" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Reject error" });
  }
});

async function processMaturedShopInvestments(email) {
  try {
    const active = await pool.query(
      "SELECT * FROM ShopInvestments WHERE email = $1 AND status = 'active'",
      [email]
    );
    const now = new Date();

    for (const inv of active.rows) {
      const shop = SHOP_CONFIG[inv.shopId];
      if (!shop) continue;
      const start       = new Date(inv.startDate);
      const daysElapsed = Math.floor((now - start) / (1000 * 60 * 60 * 24));

      if (daysElapsed >= shop.duration) {
        const totalProfit = inv.amount * shop.rate * shop.duration;
        const payout      = Number(inv.amount) + totalProfit;
        const payoutDesc  = `${shop.name} matured – capital + profit payout`;

        await pool.query(
          'UPDATE Users SET "walletBalance" = "walletBalance" + $1 WHERE email = $2',
          [payout, email]
        );
        await pool.query(
          "UPDATE ShopInvestments SET status = 'paid_out' WHERE id = $1",
          [inv.id]
        );
        await pool.query(
          `INSERT INTO Transactions (email, type, amount, reference, "createdAt")
           VALUES ($1, 'SHOP_PAYOUT', $2, $3, NOW())`,
          [email, payout, payoutDesc]
        );
      }
    }
  } catch (err) {
    console.error("Maturity check error:", err);
  }
}

app.get("/api/shop-invest/maturity-check", verifyToken, async (req, res) => {
  await processMaturedShopInvestments(req.user.email);
  res.json({ ok: true });
});

app.get("/api/admin/shop-invest/stats", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const total = await pool.query(
      `SELECT
        COUNT(*) AS "totalRequests",
        COALESCE(SUM(CASE WHEN status='active'   THEN amount ELSE 0 END), 0) AS "activeAmount",
        COALESCE(SUM(CASE WHEN status='pending'  THEN amount ELSE 0 END), 0) AS "pendingAmount",
        COALESCE(SUM(CASE WHEN status='paid_out' THEN amount ELSE 0 END), 0) AS "paidOutAmount",
        COUNT(CASE WHEN status='active'  THEN 1 END) AS "activeCount",
        COUNT(CASE WHEN status='pending' THEN 1 END) AS "pendingCount"
       FROM ShopInvestments`
    );
    res.json(total.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Stats error" });
  }
});

// ================================================================
// START
// ================================================================
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Velora running on http://localhost:${PORT}`);
});
