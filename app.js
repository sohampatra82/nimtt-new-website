require('dotenv').config()


const express = require("express"); //REQUIRE EXPRESS
const app = express();
// const mongoose = require("mongoose"); 
const dbConnect = require("./config/db"); //REQUIRE DB CONNECT
const adminDashboardModel = require("./model/adminDashboard.model");
const UserModel = require("./model/user.model"); //REQUIRE USER MODEL
const CenterModel = require("./model/center.model"); //REQUIRE CENTER MODEL
const StaffModel = require("./model/staff.model"); //REQUIRE STAFF MODEL
const AdminModel = require("./model/admin.model"); //REQUIRE ADMIN MODEL
// const cors = require("cors");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator"); //REQUIRE EXPRESS VALIDATOR
const path = require("path"); //REQUIRE PATH
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const fs = require("fs");
const upload = require("./utils/multer.config"); //REQUIRE MULTER CONFIG
app.set("view engine", "ejs"); //SET VIEW ENGINE TO EJS
app.use(express.json()); //USE JSON
app.use(express.urlencoded({ extended: true })); //USE URL ENCODED
app.use(express.static(path.join(__dirname, "public"))); //USE STATIC FILES
// app.use(
//   cors({
//     origin: "https://www.nimtt.co.in",
//     methods: ["GET", "POST", "PUT", "DELETE"],
//     credentials: true
//   })
// ); //USE CORS
// app.use(cors()); 
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "home.html"));
});
app.get("/home", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "home.html"));
});
app.get("/about", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "about.html"));
});
app.get("/contact-us", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "contact-us.html"));
});
app.get("/autonomous-course", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "autonomous-course.html"));
});
app.get("/facilities", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "facilities.html"));
});
app.get("/foco-model", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "foco-model.html"));
});
app.get("/foreign-university-course", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "foreign-university-course.html")
  );
});
app.get("/indian-university-course", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "indian-university-course.html"));
});

app.get("/rules", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "rules.html"));
});
app.get("/student-loan", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "student-loan.html"));
});
app.get("/terms-and-condition", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "terms-and-condition.html"));
});
app.get("/student-login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "student-login.html"));
});
app.get("/student-signup", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "student-signup.html"));
});
app.get("/refer-and-earn", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "refer-and-earn.html"));
});
app.get("/sign-in", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "sign-in.html"));
});
app.get("/apply-for-job", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "apply-for-job.html"));
});
app.get("/student-dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "student-dashboard.html"));
});
app.get("/admin-dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin-dashboard.html"));
});
app.get("/join-as-phd-supervisior", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "join-as-PhD-supervisor.html"));
});
app.get("/join-faculty", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "join-faculty.html"));
});
app.get("/center-login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "center-login.html"));
});
app.get("/center-signup", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "center-signup.html"));
});
app.get("/staff-signup", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "staff-signup.html"));
});
app.get("/staff-login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "staff-login.html"));
});
app.get("/admin-signup", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin-signup.html"));
});
app.get("/admin-login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin-login.html"));
});
app.get("/payment-section", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "payment-section.html"));
});
app.get("/online-admission", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "online-admission.html"));
});


const bcrypt = require("bcrypt"); //REQUIRE BCRYPT FOR HASHING PASSWORDS
const { get } = require("http");
const { isLength } = require("validator");


// ALL ADMIN DASHBOARD SCHEMAS

const uploadDir = path.join(__dirname, "public/uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Multer error handling
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    console.error("Multer error:", err);
    return res.status(400).json({ error: `Multer error: ${err.message}` });
  } else if (err) {
    console.error("General error:", err);
    return res.status(400).json({ error: err.message });
  }
  next();
});

// POST route to save student data
app.post("/admin-dashboard", upload, async (req, res) => {
  try {
    console.log("Form data:", req.body);
    console.log("File:", req.file);

    const {
      studentId,
      name,
      course,
      enrollment,
      university,
      fatherName,
      dob,
      mobile,
      email,
      address
    } = req.body;

    if (!req.file) {
      return res.status(400).json({ error: "Photo is required" });
    }

    const student = new adminDashboardModel({
      studentId,
      name,
      course,
      enrollment,
      university,
      fatherName,
      dob: new Date(dob),
      mobile,
      email,
      address,
      photo: req.file.path.replace(/\\/g, "/")
    });

    const savedStudent = await student.save();
    console.log("Saved student:", savedStudent);
    res.status(201).json({ message: "Student data saved successfully" });
  } catch (error) {
    console.error("Error saving student data:", error);
    if (error.name === "ValidationError") {
      return res
        .status(400)
        .json({ error: "Validation error", details: error.errors });
    } else if (error.code === 11000) {
      return res
        .status(400)
        .json({ error: "Duplicate student ID or email detected" });
    }
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET route to fetch student data
app.get("/admin-dashboard/:studentId", async (req, res) => {
  try {
    const { studentId } = req.params;
    if (!studentId) {
      return res.status(400).json({ message: "Student ID is required" });
    }

    const student = await adminDashboardModel.findOne({ studentId });
    if (!student) {
      return res.status(404).json({ message: "Student not found" });
    }

    const baseUrl = `${req.protocol}://${req.get("host")}`;
    const photoUrl = student.photo
      ? `${baseUrl}/uploads/${path.basename(student.photo)}`
      : "";

    const studentData = {
      studentId: student.studentId,
      name: student.name,
      course: student.course,
      enrollment: student.enrollment,
      university: student.university,
      fatherName: student.fatherName,
      dob: student.dob.toISOString().split("T")[0],
      mobile: student.mobile,
      email: student.email,
      address: student.address,
      photo: photoUrl
    };

    res.status(200).json(studentData);
  } catch (error) {
    console.error("Error fetching student:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});


// New UPDATE route
app.put("/admin-dashboard/:studentId", upload, async (req, res) => {
  try {
    const { studentId } = req.params;
    const {
      name,
      course,
      enrollment,
      university,
      fatherName,
      dob,
      mobile,
      email,
      address
    } = req.body;

    const updateData = {
      name,
      course,
      enrollment,
      university,
      fatherName,
      dob: new Date(dob),
      mobile,
      email,
      address
    };

    if (req.file) {
      updateData.photo = req.file.path.replace(/\\/g, "/");
    }

    const updatedStudent = await adminDashboardModel.findOneAndUpdate(
      { studentId },
      updateData,
      { new: true, runValidators: true }
    );

    if (!updatedStudent) {
      return res.status(404).json({ message: "Student not found" });
    }

    res.status(200).json({ message: "Student data updated successfully" });
  } catch (error) {
    console.error("Error updating student data:", error);
    if (error.name === "ValidationError") {
      return res
        .status(400)
        .json({ error: "Validation error", details: error.errors });
    } else if (error.code === 11000) {
      return res
        .status(400)
        .json({ error: "Duplicate student ID or email detected" });
    }
    res.status(500).json({ error: "Internal server error" });
  }
});

// New DELETE route
app.delete("/admin-dashboard/:studentId", async (req, res) => {
  try {
    const { studentId } = req.params;
    const deletedStudent = await adminDashboardModel.findOneAndDelete({ studentId });

    if (!deletedStudent) {
      return res.status(404).json({ message: "Student not found" });
    }

    res.status(200).json({ message: "Student data deleted successfully" });
  } catch (error) {
    console.error("Error deleting student:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});



// STUDENT SIGNUP
app.post(
  "/student-signup",
  body("email").isEmail().trim().isLength({ min: 8 }),
  body("username").trim().isLength({ min: 5 }),
  body("password").trim().isLength({ min: 4 }),
  body("confirm-password").custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error("Passwords do not match");
    }
    return true;
  }),
  async (req, res) => {
    try {
      // Validate input fields
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        const errorMessage = errors.array().map(err => err.msg).join(", ");
        return res.send(`
          <html>
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <script src="https://cdn.tailwindcss.com"></script>
              <title>Sign-up Error</title>
            </head>
            <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                <h2 class="text-2xl font-semibold text-red-600 mb-4">Invalid Input</h2>
                <p class="text-gray-700 mb-6">${errorMessage}</p>
                <a href="/student-signup" class="inline-block px-6 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 transition-colors">Try Again</a>
              </div>
            </body>
          </html>
        `);
      }

      const { username, email, password } = req.body;

      // Check if username or email already exists
      const existingUser = await UserModel.findOne({
        $or: [{ username }, { email }]
      });
      if (existingUser) {
        return res.send(`
          <html>
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <script src="https://cdn.tailwindcss.com"></script>
              <title>Sign-up Error</title>
            </head>
            <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                <h2 class="text-2xl font-semibold text-red-600 mb-4">Sign-up Failed</h2>
                <p class="text-gray-700 mb-6">The provided username or email is already in use.</p>
                <a href="/student-signup" class="inline-block px-6 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 transition-colors">Try Again</a>
              </div>
            </body>
          </html>
        `);
      }

      // Hash password and create new user
      const hashPassword = await bcrypt.hash(password, 10);
      await UserModel.create({
        username,
        email,
        password: hashPassword
      });

      // Show success message and redirect to login
      return res.send(`
        <html>
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <script src="https://cdn.tailwindcss.com"></script>
            <title>Sign-up Success</title>
          </head>
          <body class="bg-gray-100 flex items-center justify-center min-h-screen">
            <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
              <h2 class="text-2xl font-semibold text-green-600 mb-4">Sign-up Successful</h2>
              <p class="text-gray-700 mb-4">Your account has been successfully created.</p>
              <p class="text-gray-600">Redirecting to the login page...</p>
              <script>
                setTimeout(() => {
                  window.location.href = "/student-login";
                }, 2000);
              </script>
            </div>
          </body>
        </html>
      `);
    } catch (error) {
      console.error("Sign-up error:", error);
      return res.send(`
        <html>
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <script src="https://cdn.tailwindcss.com"></script>
            <title>Server Error</title>
          </head>
          <body class="bg-gray-100 flex items-center justify-center min-h-screen">
            <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
              <h2 class="text-2xl font-semibold text-red-600 mb-4">Server Error</h2>
              <p class="text-gray-700 mb-6">An unexpected error occurred during sign-up. Please try again later.</p>
              <a href="/student-signup" class="inline-block px-6 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 transition-colors">Try Again</a>
            </div>
          </body>
        </html>
      `);
    }
  }
);

// STUDENT LOGIN
app.post(
  "/student-login",
  body("username").trim().isLength({ min: 5 }),
  body("password").trim().isLength({ min: 4 }),
  async (req, res) => {
    try {
      // Validate input fields
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.send(`
          <html>
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <script src="https://cdn.tailwindcss.com"></script>
              <title>Login Error</title>
            </head>
            <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                <h2 class="text-2xl font-semibold text-red-600 mb-4">Invalid Input</h2>
                <p class="text-gray-700 mb-6">The username must be at least 5 characters, and the password must be at least 4 characters.</p>
                <a href="/student-login" class="inline-block px-6 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 transition-colors">Try Again</a>
              </div>
            </body>
          </html>
        `);
      }

      const { username, password } = req.body;

      // Check if user exists
      const Employeedata = await UserModel.findOne({ username });
      if (!Employeedata) {
        return res.send(`
          <html>
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <script src="https://cdn.tailwindcss.com"></script>
              <title>Login Error</title>
            </head>
            <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                <h2 class="text-2xl font-semibold text-red-600 mb-4">Login Failed</h2>
                <p class="text-gray-700 mb-6">The provided username or password is incorrect.</p>
                <a href="/student-login" class="inline-block px-6 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 transition-colors">Try Again</a>
              </div>
            </body>
          </html>
        `);
      }

      // Verify password
      const loginPassWord = await bcrypt.compare(
        password,
        Employeedata.password
      );
      if (!loginPassWord) {
        return res.send(`
          <html>
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <script src="https://cdn.tailwindcss.com"></script>
              <title>Login Error</title>
            </head>
            <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                <h2 class="text-2xl font-semibold text-red-600 mb-4">Login Failed</h2>
                <p class="text-gray-700 mb-6">The provided username or password is incorrect.</p>
                <a href="/student-login" class="inline-block px-6 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 transition-colors">Try Again</a>
              </div>
            </body>
          </html>
        `);
      }

      // Generate JWT token
      const token = jwt.sign({ UserID: Employeedata._id, username: Employeedata.username, email: Employeedata.email },
        "Max-support"
      );

      // Set token in cookie and show success message
      res.cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict"
      });

      return res.send(`
        <html>
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <script src="https://cdn.tailwindcss.com"></script>
            <title>Login Success</title>
          </head>
          <body class="bg-gray-100 flex items-center justify-center min-h-screen">
            <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
              <h2 class="text-2xl font-semibold text-green-600 mb-4">Login Successful</h2>
              <p class="text-gray-700 mb-4">You have successfully logged in to your account.</p>
              <p class="text-gray-600">Redirecting to the student dashboard...</p>
              <script>
                setTimeout(() => {
                  window.location.href = "/student-dashboard";
                }, 2000);
              </script>
            </div>
          </body>
        </html>
      `);
    } catch (error) {
      console.error("Login error:", error);
      return res.send(`
        <html>
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <script src="https://cdn.tailwindcss.com"></script>
            <title>Server Error</title>
          </head>
          <body class="bg-gray-100 flex items-center justify-center min-h-screen">
            <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
              <h2 class="text-2xl font-semibold text-red-600 mb-4">Server Error</h2>
              <p class="text-gray-700 mb-6">An unexpected error occurred during login. Please try again later.</p>
              <a href="/student-login" class="inline-block px-6 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 transition-colors">Try Again</a>
            </div>
          </body>
        </html>
      `);
    }
  }
);

// CENTER SIGNUP
app.post(
  "/center-signup",
  body("email").isEmail().trim().isLength({ min: 8 }),
  body("username").trim().isLength({ min: 5 }),
  body("password").trim().isLength({ min: 4 }),
  body("confirm-password").custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error("Passwords do not match");
    }
    return true;
  }),
  async (req, res) => {
    try {
      // Validate input fields
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        const errorMessage = errors.array().map(err => err.msg).join(", ");
        return res.send(`
          <html>
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <script src="https://cdn.tailwindcss.com"></script>
              <title>Sign-up Error</title>
            </head>
            <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                <h2 class="text-2xl font-semibold text-red-600 mb-4">Invalid Input</h2>
                <p class="text-gray-700 mb-6">${errorMessage}</p>
                <a href="/center-signup" class="inline-block px-6 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 transition-colors">Try Again</a>
              </div>
            </body>
          </html>
        `);
      }

      const { username, email, password } = req.body;

      // Check if username or email already exists
      const existingUser = await CenterModel.findOne({
        $or: [{ username }, { email }]
      });
      if (existingUser) {
        return res.send(`
          <html>
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <script src="https://cdn.tailwindcss.com"></script>
              <title>Sign-up Error</title>
            </head>
            <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                <h2 class="text-2xl font-semibold text-red-600 mb-4">Sign-up Failed</h2>
                <p class="text-gray-700 mb-6">The provided username or email is already in use.</p>
                <a href="/center-signup" class="inline-block px-6 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 transition-colors">Try Again</a>
              </div>
            </body>
          </html>
        `);
      }

      // Hash password and create new user
      const hashPassword = await bcrypt.hash(password, 10);
      await CenterModel.create({
        username,
        email,
        password: hashPassword
      });

      // Show success message and redirect to login
      return res.send(`
        <html>
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <script src="https://cdn.tailwindcss.com"></script>
            <title>Sign-up Success</title>
          </head>
          <body class="bg-gray-100 flex items-center justify-center min-h-screen">
            <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
              <h2 class="text-2xl font-semibold text-green-600 mb-4">Sign-up Successful</h2>
              <p class="text-gray-700 mb-4">Your account has been successfully created.</p>
              <p class="text-gray-600">Redirecting to the login page...</p>
              <script>
                setTimeout(() => {
                  window.location.href = "/center-login";
                }, 2000);
              </script>
            </div>
          </body>
        </html>
      `);
    } catch (error) {
      console.error("Sign-up error:", error);
      return res.send(`
        <html>
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <script src="https://cdn.tailwindcss.com"></script>
            <title>Server Error</title>
          </head>
          <body class="bg-gray-100 flex items-center justify-center min-h-screen">
            <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
              <h2 class="text-2xl font-semibold text-red-600 mb-4">Server Error</h2>
              <p class="text-gray-700 mb-6">An unexpected error occurred during sign-up. Please try again later.</p>
              <a href="/center-signup" class="inline-block px-6 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 transition-colors">Try Again</a>
            </div>
          </body>
        </html>
      `);
    }
  }
);

// CENTER LOGIN
app.post(
  "/center-login",
  body("username").trim().isLength({ min: 5 }),
  body("password").trim().isLength({ min: 4 }),
  async (req, res) => {
    try {
      // Validate input fields
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.send(`
          <html>
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <script src="https://cdn.tailwindcss.com"></script>
              <title>Login Error</title>
            </head>
            <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                <h2 class="text-2xl font-semibold text-red-600 mb-4">Invalid Input</h2>
                <p class="text-gray-700 mb-6">The username must be at least 5 characters, and the password must be at least 4 characters.</p>
                <a href="/center-login" class="inline-block px-6 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 transition-colors">Try Again</a>
              </div>
            </body>
          </html>
        `);
      }

      const { username, password } = req.body;

      // Check if user exists
      const Employeedata = await CenterModel.findOne({ username });
      if (!Employeedata) {
        return res.send(`
          <html>
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <script src="https://cdn.tailwindcss.com"></script>
              <title>Login Error</title>
            </head>
            <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                <h2 class="text-2xl font-semibold text-red-600 mb-4">Login Failed</h2>
                <p class="text-gray-700 mb-6">The provided username or password is incorrect.</p>
                <a href="/center-login" class="inline-block px-6 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 transition-colors">Try Again</a>
              </div>
            </body>
          </html>
        `);
      }

      // Verify password
      const loginPassWord = await bcrypt.compare(
        password,
        Employeedata.password
      );
      if (!loginPassWord) {
        return res.send(`
          <html>
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <script src="https://cdn.tailwindcss.com"></script>
              <title>Login Error</title>
            </head>
            <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                <h2 class="text-2xl font-semibold text-red-600 mb-4">Login Failed</h2>
                <p class="text-gray-700 mb-6">The provided username or password is incorrect.</p>
                <a href="/center-login" class="inline-block px-6 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 transition-colors">Try Again</a>
              </div>
            </body>
          </html>
        `);
      }

      // Generate JWT token
      const token = jwt.sign(
        {
          UserID: Employeedata._id,
          username: Employeedata.username,
          email: Employeedata.email
        },
        "Max-support"
      );

      // Set token in cookie and show success message
      res.cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict"
      });

      return res.send(`
        <html>
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <script src="https://cdn.tailwindcss.com"></script>
            <title>Login Success</title>
          </head>
          <body class="bg-gray-100 flex items-center justify-center min-h-screen">
            <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
              <h2 class="text-2xl font-semibold text-green-600 mb-4">Login Successful</h2>
              <p class="text-gray-700 mb-4">You have successfully logged in to your account.</p>
              <p class="text-gray-600">Redirecting to the center dashboard...</p>
              <script>
                setTimeout(() => {
                  window.location.href = "/student-dashboard";
                }, 2000);
              </script>
            </div>
          </body>
        </html>
      `);
    } catch (error) {
      console.error("Login error:", error);
      return res.send(`
        <html>
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <script src="https://cdn.tailwindcss.com"></script>
            <title>Server Error</title>
          </head>
          <body class="bg-gray-100 flex items-center justify-center min-h-screen">
            <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
              <h2 class="text-2xl font-semibold text-red-600 mb-4">Server Error</h2>
              <p class="text-gray-700 mb-6">An unexpected error occurred during login. Please try again later.</p>
              <a href="/center-login" class="inline-block px-6 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 transition-colors">Try Again</a>
            </div>
          </body>
        </html>
      `);
    }
  }
);

// STAFF SIGNUP
app.post(
  "/staff-signup",
  body("email").isEmail().trim().isLength({ min: 8 }),
  body("username").trim().isLength({ min: 5 }),
  body("password").trim().isLength({ min: 4 }),
  body("confirm-password").custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error("Passwords do not match");
    }
    return true;
  }),
  async (req, res) => {
    try {
      // Validate input fields
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        const errorMessage = errors.array().map(err => err.msg).join(", ");
        return res.send(`
          <html>
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <script src="https://cdn.tailwindcss.com"></script>
              <title>Sign-up Error</title>
            </head>
            <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                <h2 class="text-2xl font-semibold text-red-600 mb-4">Invalid Input</h2>
                <p class="text-gray-700 mb-6">${errorMessage}</p>
                <a href="/staff-signup" class="inline-block px-6 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 transition-colors">Try Again</a>
              </div>
            </body>
          </html>
        `);
      }

      const { username, email, password } = req.body;

      // Check if username or email already exists
      const existingUser = await StaffModel.findOne({
        $or: [{ username }, { email }]
      });
      if (existingUser) {
        return res.send(`
          <html>
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <script src="https://cdn.tailwindcss.com"></script>
              <title>Sign-up Error</title>
            </head>
            <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                <h2 class="text-2xl font-semibold text-red-600 mb-4">Sign-up Failed</h2>
                <p class="text-gray-700 mb-6">The provided username or email is already in use.</p>
                <a href="/staff-signup" class="inline-block px-6 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 transition-colors">Try Again</a>
              </div>
            </body>
          </html>
        `);
      }

      // Hash password and create new user
      const hashPassword = await bcrypt.hash(password, 10);
      await StaffModel.create({
        username,
        email,
        password: hashPassword
      });

      // Show success message and redirect to login
      return res.send(`
        <html>
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <script src="https://cdn.tailwindcss.com"></script>
            <title>Sign-up Success</title>
          </head>
          <body class="bg-gray-100 flex items-center justify-center min-h-screen">
            <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
              <h2 class="text-2xl font-semibold text-green-600 mb-4">Sign-up Successful</h2>
              <p class="text-gray-700 mb-4">Your account has been successfully created.</p>
              <p class="text-gray-600">Redirecting to the login page...</p>
              <script>
                setTimeout(() => {
                  window.location.href = "/staff-login";
                }, 2000);
              </script>
            </div>
          </body>
        </html>
      `);
    } catch (error) {
      console.error("Sign-up error:", error);
      return res.send(`
        <html>
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <script src="https://cdn.tailwindcss.com"></script>
            <title>Server Error</title>
          </head>
          <body class="bg-gray-100 flex items-center justify-center min-h-screen">
            <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
              <h2 class="text-2xl font-semibold text-red-600 mb-4">Server Error</h2>
              <p class="text-gray-700 mb-6">An unexpected error occurred during sign-up. Please try again later.</p>
              <a href="/center-signup" class="inline-block px-6 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 transition-colors">Try Again</a>
            </div>
          </body>
        </html>
      `);
    }
  }
);

// STAFF LOGIN
app.post(
  "/staff-login",
  body("username").trim().isLength({ min: 5 }),
  body("password").trim().isLength({ min: 4 }),
  async (req, res) => {
    try {
      // Validate input fields
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.send(`
          <html>
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <script src="https://cdn.tailwindcss.com"></script>
              <title>Login Error</title>
            </head>
            <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                <h2 class="text-2xl font-semibold text-red-600 mb-4">Invalid Input</h2>
                <p class="text-gray-700 mb-6">The username must be at least 5 characters, and the password must be at least 4 characters.</p>
                <a href="/staff-login" class="inline-block px-6 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 transition-colors">Try Again</a>
              </div>
            </body>
          </html>
        `);
      }

      const { username, password } = req.body;

      // Check if user exists
      const Employeedata = await StaffModel.findOne({ username });
      if (!Employeedata) {
        return res.send(`
          <html>
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <script src="https://cdn.tailwindcss.com"></script>
              <title>Login Error</title>
            </head>
            <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                <h2 class="text-2xl font-semibold text-red-600 mb-4">Login Failed</h2>
                <p class="text-gray-700 mb-6">The provided username or password is incorrect.</p>
                <a href="/staff-login" class="inline-block px-6 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 transition-colors">Try Again</a>
              </div>
            </body>
          </html>
        `);
      }

      // Verify password
      const loginPassWord = await bcrypt.compare(
        password,
        Employeedata.password
      );
      if (!loginPassWord) {
        return res.send(`
          <html>
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <script src="https://cdn.tailwindcss.com"></script>
              <title>Login Error</title>
            </head>
            <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                <h2 class="text-2xl font-semibold text-red-600 mb-4">Login Failed</h2>
                <p class="text-gray-700 mb-6">The provided username or password is incorrect.</p>
                <a href="/center-login" class="inline-block px-6 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 transition-colors">Try Again</a>
              </div>
            </body>
          </html>
        `);
      }

      // Generate JWT token
      const token = jwt.sign(
        {
          UserID: Employeedata._id,
          username: Employeedata.username,
          email: Employeedata.email
        },
        "Max-support"
      );

      // Set token in cookie and show success message
      res.cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict"
      });

      return res.send(`
        <html>
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <script src="https://cdn.tailwindcss.com"></script>
            <title>Login Success</title>
          </head>
          <body class="bg-gray-100 flex items-center justify-center min-h-screen">
            <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
              <h2 class="text-2xl font-semibold text-green-600 mb-4">Login Successful</h2>
              <p class="text-gray-700 mb-4">You have successfully logged in to your account.</p>
              <p class="text-gray-600">Redirecting to the staff dashboard...</p>
              <script>
                setTimeout(() => {
                  window.location.href = "/student-dashboard";  
                }, 2000);
              </script>
            </div>
          </body>
        </html>
      `);
    } catch (error) {
      console.error("Login error:", error);
      return res.send(`
        <html>
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <script src="https://cdn.tailwindcss.com"></script>
            <title>Server Error</title>
          </head>
          <body class="bg-gray-100 flex items-center justify-center min-h-screen">
            <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
              <h2 class="text-2xl font-semibold text-red-600 mb-4">Server Error</h2>
              <p class="text-gray-700 mb-6">An unexpected error occurred during login. Please try again later.</p>
              <a href="/staff-login" class="inline-block px-6 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 transition-colors">Try Again</a>
            </div>
          </body>
        </html>
      `);
    }
  }
);

// ADMIN SIGNUP
app.post(
  "/admin-signup",
  body("email").isEmail().trim().isLength({ min: 8 }),
  body("username").trim().isLength({ min: 5 }),
  body("password").trim().isLength({ min: 4 }),
  body("confirm-password").custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error("Passwords do not match");
    }
    return true;
  }),
  async (req, res) => {
    try {
      // Validate input fields
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        const errorMessage = errors.array().map(err => err.msg).join(", ");
        return res.send(`
          <html>
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <script src="https://cdn.tailwindcss.com"></script>
              <title>Sign-up Error</title>
            </head>
            <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                <h2 class="text-2xl font-semibold text-red-600 mb-4">Invalid Input</h2>
                <p class="text-gray-700 mb-6">${errorMessage}</p>
                <a href="/admin-signup" class="inline-block px-6 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 transition-colors">Try Again</a>
              </div>
            </body>
          </html>
        `);
      }

      const { username, email, password } = req.body;

      // Check if username or email already exists
      const existingUser = await AdminModel.findOne({
        $or: [{ username }, { email }]
      });
      if (existingUser) {
        return res.send(`
          <html>
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <script src="https://cdn.tailwindcss.com"></script>
              <title>Sign-up Error</title>
            </head>
            <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                <h2 class="text-2xl font-semibold text-red-600 mb-4">Sign-up Failed</h2>
                <p class="text-gray-700 mb-6">The provided username or email is already in use.</p>
                <a href="/admin-signup" class="inline-block px-6 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 transition-colors">Try Again</a>
              </div>
            </body>
          </html>
        `);
      }

      // Hash password and create new user
      const hashPassword = await bcrypt.hash(password, 10);
      await AdminModel.create({
        username,
        email,
        password: hashPassword
      });

      // Show success message and redirect to login
      return res.send(`
        <html>
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <script src="https://cdn.tailwindcss.com"></script>
            <title>Sign-up Success</title>
          </head>
          <body class="bg-gray-100 flex items-center justify-center min-h-screen">
            <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
              <h2 class="text-2xl font-semibold text-green-600 mb-4">Sign-up Successful</h2>
              <p class="text-gray-700 mb-4">Your account has been successfully created.</p>
              <p class="text-gray-600">Redirecting to the login page...</p>
              <script>
                setTimeout(() => {
                  window.location.href = "/admin-login";
                }, 2000);
              </script>
            </div>
          </body>
        </html>
      `);
    } catch (error) {
      console.error("Sign-up error:", error);
      return res.send(`
        <html>
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <script src="https://cdn.tailwindcss.com"></script>
            <title>Server Error</title>
          </head>
          <body class="bg-gray-100 flex items-center justify-center min-h-screen">
            <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
              <h2 class="text-2xl font-semibold text-red-600 mb-4">Server Error</h2>
              <p class="text-gray-700 mb-6">An unexpected error occurred during sign-up. Please try again later.</p>
              <a href="/admin-signup" class="inline-block px-6 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 transition-colors">Try Again</a>
            </div>
          </body>
        </html>
      `);
    }
  }
);

// ADMIN LOGIN
app.post(
  "/admin-login",
  body("username").trim().isLength({ min: 5 }),
  body("password").trim().isLength({ min: 4 }),
  async (req, res) => {
    try {
      // Validate input fields
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.send(`
          <html>
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <script src="https://cdn.tailwindcss.com"></script>
              <title>Login Error</title>
            </head>
            <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                <h2 class="text-2xl font-semibold text-red-600 mb-4">Invalid Input</h2>
                <p class="text-gray-700 mb-6">The username must be at least 5 characters, and the password must be at least 4 characters.</p>
                <a href="/admin-login" class="inline-block px-6 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 transition-colors">Try Again</a>
              </div>
            </body>
          </html>
        `);
      }

      const { username, password } = req.body;

      // Check if user exists
      const Employeedata = await AdminModel.findOne({ username });
      if (!Employeedata) {
        return res.send(`
          <html>
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <script src="https://cdn.tailwindcss.com"></script>
              <title>Login Error</title>
            </head>
            <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                <h2 class="text-2xl font-semibold text-red-600 mb-4">Login Failed</h2>
                <p class="text-gray-700 mb-6">The provided username or password is incorrect.</p>
                <a href="/admin-login" class="inline-block px-6 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 transition-colors">Try Again</a>
              </div>
            </body>
          </html>
        `);
      }

      // Verify password
      const loginPassWord = await bcrypt.compare(
        password,
        Employeedata.password
      );
      if (!loginPassWord) {
        return res.send(`
          <html>
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <script src="https://cdn.tailwindcss.com"></script>
              <title>Login Error</title>
            </head>
            <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                <h2 class="text-2xl font-semibold text-red-600 mb-4">Login Failed</h2>
                <p class="text-gray-700 mb-6">The provided username or password is incorrect.</p>
                <a href="/admin-login" class="inline-block px-6 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 transition-colors">Try Again</a>
              </div>
            </body>
          </html>
        `);
      }

      // Generate JWT token
      const token = jwt.sign(
        {
          UserID: Employeedata._id,
          username: Employeedata.username,
          email: Employeedata.email
        },
        "Max-support"
      );

      // Set token in cookie and show success message
      res.cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict"
      });

      return res.send(`
        <html>
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <script src="https://cdn.tailwindcss.com"></script>
            <title>Login Success</title>
          </head>
          <body class="bg-gray-100 flex items-center justify-center min-h-screen">
            <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
              <h2 class="text-2xl font-semibold text-green-600 mb-4">Login Successful</h2>
              <p class="text-gray-700 mb-4">You have successfully logged in to your account.</p>
              <p class="text-gray-600">Redirecting to the admin dashboard...</p>
              <script>
                setTimeout(() => {
                  window.location.href = "/admin-dashboard";  
                }, 2000);
              </script>
            </div>
          </body>
        </html>
      `);
    } catch (error) {
      console.error("Login error:", error);
      return res.send(`
        <html>
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <script src="https://cdn.tailwindcss.com"></script>
            <title>Server Error</title>
          </head>
          <body class="bg-gray-100 flex items-center justify-center min-h-screen">
            <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
              <h2 class="text-2xl font-semibold text-red-600 mb-4">Server Error</h2>
              <p class="text-gray-700 mb-6">An unexpected error occurred during login. Please try again later.</p>
              <a href="/admin-login" class="inline-block px-6 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 transition-colors">Try Again</a>
            </div>
          </body>
        </html>
      `);
    }
  }
);

// Nodemailer transporter configuration
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Handle form submission
app.post("/send-email", (req, res) => {
  const { firstName, phone, email, message } = req.body;

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: "nimttheadoffice@rediffmail.com",
    subject: `New Contact Form Submission from ${firstName}`,
    text: `
          Name: ${firstName}
          Phone: ${phone}
          Email: ${email}
          Message: ${message}
      `
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error("Error sending email:", error);
      return res.send(`
          <!DOCTYPE html>
          <html lang="en">
          <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Error</title>
              <script src="https://cdn.tailwindcss.com"></script>
              <style>
                  .modal {
                      animation: fadeIn 0.3s ease-in-out;
                  }
                  @keyframes fadeIn {
                      from { opacity: 0; transform: translateY(-10px); }
                      to { opacity: 1; transform: translateY(0); }
                  }
              </style>
          </head>
          <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="modal fixed top-0 left-0 w-full h-full flex items-center justify-center bg-black bg-opacity-50">
                  <div class="bg-white rounded-lg shadow-xl p-6 max-w-md w-full text-center">
                      <div class="flex justify-center mb-4">
                          <svg class="w-12 h-12 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                          </svg>
                      </div>
                      <h2 class="text-2xl font-semibold text-gray-800 mb-2">Error</h2>
                      <p class="text-gray-600 mb-6">Error sending email. Please try again later.</p>
                      <a href="/" class="inline-block px-6 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 transition-colors">Back to Form</a>
                  </div>
              </div>
          </body>
          </html>
      `);
    }
    // console.log('Email sent:', info.response);
    res.send(`
          <!DOCTYPE html>
          <html lang="en">
          <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Success</title>
              <script src="https://cdn.tailwindcss.com"></script>
              <style>
                  .modal {
                      animation: fadeIn 0.3s ease-in-out;
                  }
                  @keyframes fadeIn {
                      from { opacity: 0; transform: translateY(-10px); }
                      to { opacity: 1; transform: translateY(0); }
                  }
              </style>
          </head>
          <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="modal fixed top-0 left-0 w-full h-full flex items-center justify-center bg-black bg-opacity-50">
                  <div class="bg-white rounded-lg shadow-xl p-6 max-w-md w-full text-center">
                      <div class="flex justify-center mb-4">
                          <svg class="w-12 h-12 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                          </svg>
                      </div>
                      <h2 class="text-2xl font-semibold text-gray-800 mb-2">Success</h2>
                      <p class="text-gray-600 mb-6">Form submitted successfully! Email sent.</p>
                      <a href="/" class="inline-block px-6 py-2 bg-green-500 text-white rounded-lg hover:bg-green-600 transition-colors">Back to Form</a>
                  </div>
              </div>
          </body>
          </html>
      `);
  });
});

// Handle form submission for career page
app.post("/submit-career", (req, res) => {
  const {
    fullName,
    dob,
    gender,
    marital,
    nationality,
    phone,
    email,
    address,
    degree,
    university,
    year,
    marks,
    experience,
    designation,
    duration,
    company,
    salary,
    height,
    weight,
    fatherName,
    fatherOccupation,
    motherName,
    motherOccupation,
    languages,
    skills,
    objective,
    resume,
    photo,
    declaration,
    data,
    place
  } = req.body;

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: "nimttheadoffice@rediffmail.com",
    subject: `New Contact Form Submission from ${fullName}`,
    text: `
          Name: ${fullName}
          DOB: ${dob}
          Gender: ${gender}
          Marital Status: ${marital}
          Nationality: ${nationality}
          Phone: ${phone}
          Email: ${email}
          Address: ${address}
          Degree: ${degree}
          University: ${university}
          Year of Passing: ${year}
          Marks Obtained: ${marks}
          Experience: ${experience}
          Designation: ${designation}
          Duration: ${duration}
          Company: ${company}
          Salary: ${salary}
          Height: ${height}
          Weight: ${weight}
          Father's Name: ${fatherName}
          Father's Occupation: ${fatherOccupation}
          Mother's Name: ${motherName}
          Mother's Occupation: ${motherOccupation}
          Languages Known: ${languages}
          Skills: ${skills}
          Career Objective: ${objective}
          Resume: ${resume}
          Photo: ${photo}
          Declaration: ${declaration}
          Data: ${data}
          Place: ${place}
      `
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error("Error sending email:", error);
      return res.send(`
          <!DOCTYPE html>
          <html lang="en">
          <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Error</title>
              <script src="https://cdn.tailwindcss.com"></script>
              <style>
                  .modal {
                      animation: fadeIn 0.3s ease-in-out;
                  }
                  @keyframes fadeIn {
                      from { opacity: 0; transform: translateY(-10px); }
                      to { opacity: 1; transform: translateY(0); }
                  }
              </style>
          </head>
          <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="modal fixed top-0 left-0 w-full h-full flex items-center justify-center bg-black bg-opacity-50">
                  <div class="bg-white rounded-lg shadow-xl p-6 max-w-md w-full text-center">
                      <div class="flex justify-center mb-4">
                          <svg class="w-12 h-12 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                          </svg>
                      </div>
                      <h2 class="text-2xl font-semibold text-gray-800 mb-2">Error</h2>
                      <p class="text-gray-600 mb-6">Error sending email. Please try again later.</p>
                      <a href="/" class="inline-block px-6 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 transition-colors">Back to Home</a>
                  </div>
              </div>
          </body>
          </html>
      `);
    }
    // console.log('Email sent:', info.response);
    res.send(`
          <!DOCTYPE html>
          <html lang="en">
          <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Success</title>
              <script src="https://cdn.tailwindcss.com"></script>
              <style>
                  .modal {
                      animation: fadeIn 0.3s ease-in-out;
                  }
                  @keyframes fadeIn {
                      from { opacity: 0; transform: translateY(-10px); }
                      to { opacity: 1; transform: translateY(0); }
                  }
              </style>
          </head>
          <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="modal fixed top-0 left-0 w-full h-full flex items-center justify-center bg-black bg-opacity-50">
                  <div class="bg-white rounded-lg shadow-xl p-6 max-w-md w-full text-center">
                      <div class="flex justify-center mb-4">
                          <svg class="w-12 h-12 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                          </svg>
                      </div>
                      <h2 class="text-2xl font-semibold text-gray-800 mb-2">Success</h2>
                      <p class="text-gray-600 mb-6">Form submitted successfully! Email sent.</p>
                      <a href="/" class="inline-block px-6 py-2 bg-green-500 text-white rounded-lg hover:bg-green-600 transition-colors">Back to Form</a>
                  </div>
              </div>
          </body>
          </html>
      `);
  });
});

// Handle form submission for phd
app.post("/join-as-phd-supervisior", (req, res) => {
  const {
    firstname,
    lastname,
    email,
    address1,
    address2,
    city,
    state,
    postalcode,
    country,
    phone,
    source,
    resume,
    coverletter,
    photo,
    additional
  } = req.body;

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: "nimttheadoffice@rediffmail.com",
    subject: `New Contact Form Submission from ${firstname + lastname}`,
    text: `
          First Name: ${firstname}
          Last Name: ${lastname}
          Email: ${email}
          Phone: ${phone}
          Addresss 1 : ${address1}
          Addresss 2 : ${address2}
          City : ${city}
          State : ${state}
          Postal Code : ${postalcode}
          Country : ${country}
          Source : ${source}
          Resume : ${resume}
          Cover Letter : ${coverletter}
          Photo : ${photo}
          Additional Info : ${additional}
      `
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error("Error sending email:", error);
      return res.send(`
          <!DOCTYPE html>
          <html lang="en">
          <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Error</title>
              <script src="https://cdn.tailwindcss.com"></script>
              <style>
                  .modal {
                      animation: fadeIn 0.3s ease-in-out;
                  }
                  @keyframes fadeIn {
                      from { opacity: 0; transform: translateY(-10px); }
                      to { opacity: 1; transform: translateY(0); }
                  }
              </style>
          </head>
          <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="modal fixed top-0 left-0 w-full h-full flex items-center justify-center bg-black bg-opacity-50">
                  <div class="bg-white rounded-lg shadow-xl p-6 max-w-md w-full text-center">
                      <div class="flex justify-center mb-4">
                          <svg class="w-12 h-12 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                          </svg>
                      </div>
                      <h2 class="text-2xl font-semibold text-gray-800 mb-2">Error</h2>
                      <p class="text-gray-600 mb-6">Error sending email. Please try again later.</p>
                      <a href="/" class="inline-block px-6 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 transition-colors">Back to Form</a>
                  </div>
              </div>
          </body>
          </html>
      `);
    }
    // console.log('Email sent:', info.response);
    res.send(`
          <!DOCTYPE html>
          <html lang="en">
          <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Success</title>
              <script src="https://cdn.tailwindcss.com"></script>
              <style>
                  .modal {
                      animation: fadeIn 0.3s ease-in-out;
                  }
                  @keyframes fadeIn {
                      from { opacity: 0; transform: translateY(-10px); }
                      to { opacity: 1; transform: translateY(0); }
                  }
              </style>
          </head>
          <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="modal fixed top-0 left-0 w-full h-full flex items-center justify-center bg-black bg-opacity-50">
                  <div class="bg-white rounded-lg shadow-xl p-6 max-w-md w-full text-center">
                      <div class="flex justify-center mb-4">
                          <svg class="w-12 h-12 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                          </svg>
                      </div>
                      <h2 class="text-2xl font-semibold text-gray-800 mb-2">Success</h2>
                      <p class="text-gray-600 mb-6">Form submitted successfully! Email sent.</p>
                      <a href="/" class="inline-block px-6 py-2 bg-green-500 text-white rounded-lg hover:bg-green-600 transition-colors">Back to Form</a>
                  </div>
              </div>
          </body>
          </html>
      `);
  });
});

// Handle form submission for Join facalty
app.post("/join-faculty", (req, res) => {
  const {
    firstname,
    lastname,
    email,
    address1,
    address2,
    city,
    state,
    postalcode,
    country,
    phone,
    source,
    resume,
    coverletter,
    photo,
    additional
  } = req.body;

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: "nimttheadoffice@rediffmail.com",
    subject: `New Contact Form Submission from ${firstname + lastname}`,
    text: `
          First Name: ${firstname}
          Last Name: ${lastname}
          Email: ${email}
          Phone: ${phone}
          Addresss 1 : ${address1}
          Addresss 2 : ${address2}
          City : ${city}
          State : ${state}
          Postal Code : ${postalcode}
          Country : ${country}
          Source : ${source}
          Resume : ${resume}
          Cover Letter : ${coverletter}
          Photo : ${photo}
          Additional Info : ${additional}
      `
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error("Error sending email:", error);
      return res.send(`
          <!DOCTYPE html>
          <html lang="en">
          <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Error</title>
              <script src="https://cdn.tailwindcss.com"></script>
              <style>
                  .modal {
                      animation: fadeIn 0.3s ease-in-out;
                  }
                  @keyframes fadeIn {
                      from { opacity: 0; transform: translateY(-10px); }
                      to { opacity: 1; transform: translateY(0); }
                  }
              </style>
          </head>
          <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="modal fixed top-0 left-0 w-full h-full flex items-center justify-center bg-black bg-opacity-50">
                  <div class="bg-white rounded-lg shadow-xl p-6 max-w-md w-full text-center">
                      <div class="flex justify-center mb-4">
                          <svg class="w-12 h-12 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                          </svg>
                      </div>
                      <h2 class="text-2xl font-semibold text-gray-800 mb-2">Error</h2>
                      <p class="text-gray-600 mb-6">Error sending email. Please try again later.</p>
                      <a href="/" class="inline-block px-6 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 transition-colors">Back to Form</a>
                  </div>
              </div>
          </body>
          </html>
      `);
    }
    // console.log('Email sent:', info.response);
    res.send(`
          <!DOCTYPE html>
          <html lang="en">
          <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Success</title>
              <script src="https://cdn.tailwindcss.com"></script>
              <style>
                  .modal {
                      animation: fadeIn 0.3s ease-in-out;
                  }
                  @keyframes fadeIn {
                      from { opacity: 0; transform: translateY(-10px); }
                      to { opacity: 1; transform: translateY(0); }
                  }
              </style>
          </head>
          <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="modal fixed top-0 left-0 w-full h-full flex items-center justify-center bg-black bg-opacity-50">
                  <div class="bg-white rounded-lg shadow-xl p-6 max-w-md w-full text-center">
                      <div class="flex justify-center mb-4">
                          <svg class="w-12 h-12 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                          </svg>
                      </div>
                      <h2 class="text-2xl font-semibold text-gray-800 mb-2">Success</h2>
                      <p class="text-gray-600 mb-6">Form submitted successfully! Email sent.</p>
                      <a href="/" class="inline-block px-6 py-2 bg-green-500 text-white rounded-lg hover:bg-green-600 transition-colors">Back to Form</a>
                  </div>
              </div>
          </body>
          </html>
      `);
  });
});

// Handle form submission for admission
app.post("/online-admission", (req, res) => {
  const {
    programme,
    session,
    gender,
    dob_month,
    dob_day,
    dob_year,
    applicant_name,
    father_name,
    mother_name,
    aadhar_number,
    email,
    category,
    nationality,
    domicile,
    domicile_others,
    permanent_address,
    city,
    state,
    pin_code,
    mobile_number,
    exam_10th_stream,
    exam_12th_stream,
    exam_graduation_stream,
    exam_postgrad_stream
  } = req.body;

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: "nimttheadoffice@rediffmail.com",
    subject: `New Contact Form Submission from ${applicant_name}`,
    text: `
         programme_name : ${programme} 
         session : ${session}
         gender : ${gender}
         Date of birth day : ${dob_day}
         Date of birth month : ${dob_month}
         Date of birth year : ${dob_year}
         applicant _name : ${applicant_name}
         father_name :${father_name}
         mother_name :${mother_name}
         aadhar_number : ${aadhar_number}
         email : ${email}
         category : ${category}
         nationality : ${nationality}
          domicile :${domicile}
          domicile_others : ${domicile_others}
          permanent_address :${permanent_address}
            city :${city}
            state : ${state}
            pin_cod : ${pin_code}
            mobile_number : ${mobile_number}
            exam_10th_stream : ${exam_10th_stream}
            exam_12th_stream :${exam_12th_stream}
            exam_graduation_stream : ${exam_graduation_stream}
            exam_postgrad_stream : ${exam_postgrad_stream}
`
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error("Error sending email:", error);
      return res.send(`
          <!DOCTYPE html>
          <html lang="en">
          <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Error</title>
              <script src="https://cdn.tailwindcss.com"></script>
              <style>
                  .modal {
                      animation: fadeIn 0.3s ease-in-out;
                  }
                  @keyframes fadeIn {
                      from { opacity: 0; transform: translateY(-10px); }
                      to { opacity: 1; transform: translateY(0); }
                  }
              </style>
          </head>
          <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="modal fixed top-0 left-0 w-full h-full flex items-center justify-center bg-black bg-opacity-50">
                  <div class="bg-white rounded-lg shadow-xl p-6 max-w-md w-full text-center">
                      <div class="flex justify-center mb-4">
                          <svg class="w-12 h-12 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                          </svg>
                      </div>
                      <h2 class="text-2xl font-semibold text-gray-800 mb-2">Error</h2>
                      <p class="text-gray-600 mb-6">Error sending email. Please try again later.</p>
                      <a href="/online-admission" class="inline-block px-6 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 transition-colors">Back to Form</a>
                  </div>
              </div>
          </body>
          </html>
      `);
    }
    // console.log('Email sent:', info.response);
    res.send(`
          <!DOCTYPE html>
          <html lang="en">
          <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Success</title>
              <script src="https://cdn.tailwindcss.com"></script>
              <style>
                  .modal {
                      animation: fadeIn 0.3s ease-in-out;
                  }
                  @keyframes fadeIn {
                      from { opacity: 0; transform: translateY(-10px); }
                      to { opacity: 1; transform: translateY(0); }
                  }
              </style>
          </head>
          <body class="bg-gray-100 flex items-center justify-center min-h-screen">
              <div class="modal fixed top-0 left-0 w-full h-full flex items-center justify-center bg-black bg-opacity-50">
                  <div class="bg-white rounded-lg shadow-xl p-6 max-w-md w-full text-center">
                      <div class="flex justify-center mb-4">
                          <svg class="w-12 h-12 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                          </svg>
                      </div>
                      <h2 class="text-2xl font-semibold text-gray-800 mb-2">Success</h2>
                      <p class="text-gray-600 mb-6">Form submitted successfully! Email sent.</p>
                      <a href="/payment-section" class="inline-block px-6 py-2 bg-green-500 text-white rounded-lg hover:bg-green-600 transition-colors">Go to paymant section</a>
                  </div>
              </div>
          </body>
          </html>
      `);
  });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port number http://localhost:${PORT}`); //LOG PORT
});
