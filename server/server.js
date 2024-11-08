const express = require("express");
const { Pool } = require("pg");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const cors = require("cors");
const app = express();
const PORT = 3000;
dotenv.config();
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: "weblabosbaza",
  password: process.env.DB_PASSWORD,
  port: 5432,
  ssl: true,
});

app.use(cors());
app.use(express.json());

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));

app.get("/", (req, res) => {
  res.render("index");
});

function sanitize(input) {
  if (typeof input !== "string") {
    return null;
  }

  const scriptPattern = /<\s*script.*?>.*?<\s*\/\s*script\s*>/gi;
  let sanitized = input.replace(scriptPattern, "");

  const dangerousTags = /<\/?(iframe|object|embed|style|link)[^>]*>/gi;
  sanitized = sanitized.replace(dangerousTags, "");

  const events = /\s*on\w+="[^"]*"/gi;
  sanitized = sanitized.replace(events, "");

  const jsProtocols = /\s*(href|src)\s*=\s*["']\s*javascript:[^"']*["']/gi;
  sanitized = sanitized.replace(jsProtocols, "");

  sanitized = sanitized
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"');

  const all =
    /<\s*(script|iframe|object|embed|style|link|img|svg|meta)[^>]*>|javascript:/gi;
  if (all.test(sanitized)) {
    return null;
  }

  return sanitized;
}

app.post("/submitXSS", (req, res) => {
  const userInput = req.body.userInput;
  const enableAttack = req.body.attackCheckbox;
  const cleanedInput = sanitize(userInput);

  if (enableAttack == "true") {
    res.render("result", { userInput });
  } else {
    if (userInput != cleanedInput || cleanedInput == null) {
      const alert = `<script>alert("Please make sure your input is correct")</script>`;
      res.render("resultAlert", { alert });
    } else {
      res.render("result", { userInput });
    }
  }
});

async function insertUser(username, password) {
  try {
    const query =
      "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING *";
    const values = [username, password];
    const res = await pool.query(query, values);
    return res.rows[0];
  } catch (err) {
    console.error("Error inserting ticket:", err.message);
    throw err;
  }
}

async function hashPassword(password) {
  const saltRounds = 10;
  const hashedPassword = await bcrypt.hash(password, saltRounds);
  return hashedPassword;
}

app.post("/submitSDE", async (req, res) => {
  const enableAttack = req.body.attackCheckbox;
  const username = req.body.userInputUsername;
  const password = req.body.userInputPassword;
  if (enableAttack == "true") {
    const newUser = await insertUser(username, password);
    const usname = newUser.username;
    const pass = newUser.password;
    res.render("resultSDA", { usname, pass });
  } else {
    const passwordHash = await hashPassword(password);
    const newUser = await insertUser(username, passwordHash);
    const usname = newUser.username;
    const pass = newUser.password;
    res.render("resultSDA", { usname, pass });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
