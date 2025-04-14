const express = require("express");
const app = express();

// Enable JSON parsing
app.use(express.json());

app.post("/hello", (req, res) => {
    console.log("Headers:", req.headers);
    console.log("Body:", req.body); // This will now print the actual body
    res.json({ message: "Hello from Node!" });
});

const PORT = 3005;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
