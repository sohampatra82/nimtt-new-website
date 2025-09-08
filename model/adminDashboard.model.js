// adminDashboardModel.js
const mongoose = require("mongoose");

const adminDashboardSchema = mongoose.Schema({
  studentId: {
    type: String,
    required: true,
    unique: true // Added unique constraint
  },
  name: {
    type: String,
    required: true
  },
  course: {
    type: String,
    required: true
  },
  enrollment: {
    type: String,
    required: true
  },
  university: {
    type: String,
    required: true
  },
  fatherName: { // Consistent naming
    type: String,
    required: true
  },
  dob: {
    type: Date,
    required: true
  },
  mobile: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true
  },
  address: {
    type: String,
    required: true
  },
  photo: {
    type: String,
    required: true
  }
});

const adminDashboardModel = mongoose.model("adminDashboard", adminDashboardSchema);
module.exports = adminDashboardModel;