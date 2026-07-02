const { Pool } = require("pg");
require("dotenv").config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

const connectDB = async () => {
  try {
    await pool.query("SELECT 1");
    console.log("✅ PostgreSQL Connected Successfully");
  } catch (err) {
    console.log("❌ DB Error:", err);
  }
};

module.exports = { pool, connectDB };
