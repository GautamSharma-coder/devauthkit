// server/server.js
const express = require("express");
const session = require("express-session");
const dotenv = require("dotenv");
dotenv.config()
const cors = require("cors");


const authRoutes = require("./routes/authRoutes");

const app = express();
const PORT = process.env.PORT || 3000;
app.use(cors({
  origin: "http://localhost:3001",  // allow frontend origin
  credentials: true
}));;

app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || "devAuthSecret",
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false },
}));

app.use("/auth", authRoutes);

const requireAuth = require("./middleware/requireAuth");

app.get("/profile", requireAuth, (req, res) => {
  res.json({ message: `Welcome, ${req.session.user.email}` });
});

app.listen(PORT, () => console.log(`DevAuthKit running on port ${PORT}`));





















