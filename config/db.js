const mongoose = require("mongoose");
const dbConnect = mongoose.connect("mongodb://localhost:27017/newstudentlogin").then(() => {
  console.log("Nimtt Database is ready ... ");
});
module.exports = dbConnect;