require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require("body-parser");

const app = express();
const PORT = process.env.PORT || 3001;
const SECRET = process.env.SECRET || "G7gG2s5d4lGcvlVBQk6mmTvSeOXqRaG0xWSN8FlUOrSOX0bPIE4pvaEanz1GMxQs";

app.use(cors());
app.use(bodyParser.json());

// SQLite DB setup
const db = new sqlite3.Database("military.db", (err) => {
  if (err) return console.error(err.message);
  console.log("Connected to SQLite DB.");
});

// Create tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS personnel (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fullName TEXT,
    rank TEXT,
    age INTEGER,
    dob TEXT,
    placeOfWork TEXT,
    diagnosis TEXT,
    hospital TEXT,
    restPeriod INTEGER,
    restStart TEXT,
    estimatedReturn TEXT,
    treatment TEXT
  )`);

  // Check if the "nip" column exists
  db.all("PRAGMA table_info(personnel)", (err, columns) => {
    if (err) {
      console.error("Error fetching table info:", err.message);
      return;
    }

    const columnExists = columns.some((col) => col.name === "nip");
    if (!columnExists) {
      console.log("Changing column name from NIP to nip in personnel table...");

      // Step 1: Create a new table with the correct schema
      db.run(`CREATE TABLE IF NOT EXISTS personnel_new (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nip INTEGER, -- Changed from NIP to nip
        fullName TEXT,
        rank TEXT,
        age INTEGER,
        dob TEXT,
        placeOfWork TEXT,
        diagnosis TEXT,
        hospital TEXT,
        restPeriod INTEGER,
        restStart TEXT,
        estimatedReturn TEXT,
        treatment TEXT
      )`, (err) => {
        if (err) {
          console.error("Error creating new personnel table:", err.message);
          return;
        }

        // Step 2: Copy data from the old table to the new table
        db.run(`INSERT INTO personnel_new (
          id, nip, fullName, rank, age, dob, placeOfWork, diagnosis, hospital, restPeriod, restStart, estimatedReturn, treatment
        )
        SELECT
          id, NIP, fullName, rank, age, dob, placeOfWork, diagnosis, hospital, restPeriod, restStart, estimatedReturn, treatment
        FROM personnel`, (err) => {
          if (err) {
            console.error("Error copying data to new personnel table:", err.message);
            return;
          }

          // Step 3: Drop the old table
          db.run(`DROP TABLE personnel`, (err) => {
            if (err) {
              console.error("Error dropping old personnel table:", err.message);
              return;
            }

            // Step 4: Rename the new table to the original table name
            db.run(`ALTER TABLE personnel_new RENAME TO personnel`, (err) => {
              if (err) {
                console.error("Error renaming new personnel table:", err.message);
              } else {
                console.log("Column name changed from NIP to nip successfully.");
              }
            });
          });
        });
      });
    }
  });

  // Create default admin user if not exists
  db.get("SELECT * FROM users WHERE username = ?", ["admin"], (err, row) => {
    if (!row) {
      const hashed = bcrypt.hashSync("password", 8);
      db.run("INSERT INTO users (username, password) VALUES (?, ?)", ["admin", hashed]);
    }
  });
});

// Middleware to verify token
function verifyToken(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(403).send("No token provided.");
  jwt.verify(token, SECRET, (err, decoded) => {
    if (err) return res.status(500).send("Failed to authenticate token.");
    req.userId = decoded.id;
    next();
  });
}

// Login route
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (err || !user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).send({ message: "Invalid credentials" });
    }
    const token = jwt.sign({ id: user.id }, SECRET, { expiresIn: "1h" });
    res.send({ token });
  });
});

// Get personnel
app.get("/api/personnel", verifyToken, (req, res) => {
  db.all("SELECT * FROM personnel", [], (err, rows) => {
    if (err) return res.status(500).send(err);
    res.json(rows);
  });
});

// Add personnel
app.post("/api/personnel", verifyToken, (req, res) => {
  const p = req.body;
  db.run(`INSERT INTO personnel (nip, fullName, rank, age, dob, placeOfWork, diagnosis, hospital, restPeriod, restStart, estimatedReturn, treatment)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [p.nip, p.fullName, p.rank, p.age, p.dob, p.placeOfWork, p.diagnosis, p.hospital, p.restPeriod, p.restStart, p.estimatedReturn, p.treatment],
    function (err) {
      if (err) return res.status(500).send(err);
      res.send({ id: this.lastID });
    }
  );
});

app.post("/api/signup", (req, res) => {
  const { username, password } = req.body;

  //validate input
  if(!username || !password) {
    return res.status(400).send({ message: "Por favor, insira o utilizador e a palavra-passe" });
  }

  // hash password
  const hashedPassword = bcrypt.hashSync(password, 10);

  // insert user into database
  db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], function(err) {
    if (err) {
      if (err.message.includes("UNIQUE")) {
        return res.status(409).send({ message: "Utilizador já existe" });
      }
      return res.status(500).send(err);
    }
    const token = jwt.sign({ id: this.lastID }, SECRET, { expiresIn: "1h" });
    res.send({ token });
  });
});

// Wipe database
app.delete("/api/wipe-database", (req, res) => {
  db.serialize(() => {
    db.run("DELETE FROM users", (err) => {
      if(err) {
        console.error("Error wiping users table: ", err.message);
        res.setHeader('Content-Type', 'application/json'); 
        return res.status(500).send(JSON.stringify({message: 'Failed to wipe users table.'}));
      }
    });

    db.run("DELETE FROM personnel", (err) => {
      if(err) {
        console.error("Error wiping personnel table: ", err.message);
        res.setHeader('Content-Type', 'application/json'); 
        return res.status(500).send(JSON.stringify({message: 'Failed to wipe personnel table.'}));
      }
    });

    return res.status(200).send(JSON.stringify({message: 'Database successfully wiped.'}));
  });
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
