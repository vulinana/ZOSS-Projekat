const express = require("express");
const cors = require("cors");
const app = express();

app.use(cors());
app.use(express.json());

app.post("/", (req, res) => {
  console.log(req.body);
});

app.listen(8001, () => console.log("Listetning on port 8001"));
