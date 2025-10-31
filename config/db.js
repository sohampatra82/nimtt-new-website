const mongoose = require("mongoose");

 const dbConnect = mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("Nimtt Database is ready"))
  .catch(err => console.error("MongoDB Connection Error:", err.message));

module.exports = dbConnect;
