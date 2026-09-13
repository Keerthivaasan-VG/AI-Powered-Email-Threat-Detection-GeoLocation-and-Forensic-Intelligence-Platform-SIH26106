require("dotenv").config();

const path = require("path");
const express = require("express");
const cors = require("cors");
const emailRoutes = require("./routes/emailRoutes");

const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json());

// API routes
app.use("/api/email", emailRoutes);

// Serve the frontend as static files, so the whole app can run from one server.
const frontendDir = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendDir));

// Any non-API route falls back to the single-page app shell.
app.get("*", (req, res) => {
  res.sendFile(path.join(frontendDir, "index.html"));
});

app.listen(PORT, () => {
  console.log(`Email Forensics backend running on http://localhost:${PORT}`);
});
