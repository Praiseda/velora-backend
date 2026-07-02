const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { pool } = require("../db");

const router = express.Router();

router.post("/register", async (req, res) => {
  try {
    const { fullName, email, password, referredBy } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    const referralCode =
      "VEL" + Math.floor(Math.random() * 100000);

    await pool.query(`
      INSERT INTO Users (
        fullName,
        email,
        password,
        referralCode,
        referredBy
      )
      VALUES (
        ${fullName},
        ${email},
        ${hashedPassword},
        ${referralCode},
        ${referredBy || null}
      )
    `);

    res.json({
      message: "User registered successfully",
      referralCode
    });

  } catch (err) {
    console.log(err);
    res.status(500).json({
      message: "Registration failed"
    });
  }
});

module.exports = router;