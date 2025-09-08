const mongoose = require("mongoose");
const dbConnect = mongoose
  .connect("mongodb://0.0.0.0/newstundetlogin")
  .then(() => {
    console.log("Nimtt Database is ready");
  });
