const express = require("express");
const router = express.Router();
const argon2 = require("argon2");
const jwt = require("jsonwebtoken");
const verifyToken = require("../middleware/auth");

const User = require("../models/User");
const { CLIENT_URL } = process.env;

// const createAccessToken = (payload) => {
//     return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' })
// }

// router.get('/', (req, res) => res.send('USER ROUTE'))

// @route GET api/auth
// @desc Check if user is logged in
// @access Public

router.get("/", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    if (!user)
      return res
        .status(400)
        .json({ success: false, message: "User not found!" });
    res.json({ success: true, user });
  } catch (error) {
    console.log(error);
    res.status(500).json({ success: false, message: "Internal server" });
  }
});

// @route POST api/auth/register
// @desc Register User
// @access Public

router.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  // Simple validation
  if (!username || !password || !email) {
    return res
      .status(400)
      .json({ success: false, message: "Please fill the black fields!" });
  }

  try {
    // Check for existing user
    const user = await User.findOne({ username });
    const userEmail = await User.findOne({ email });

    if (user) {
      return res
        .status(400)
        .json({ success: false, message: "The username has been used" });
    } else if (userEmail) {
      return res
        .status(400)
        .json({ success: false, message: "The email has been used" });
    }

    // All good
    const hashedPassword = await argon2.hash(password);
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();

    // Return Token
    const accessToken = jwt.sign(
      { userId: newUser._id },
      process.env.ACCESS_TOKEN_SECRET
    );

    res.json({
      success: true,
      message: "User created successfully",
      accessToken,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ success: false, message: "Internal server" });
  }
});

// @route POST api/auth/login
// @desc login User
// @access Public

router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  // Simple validation
  if (!username || !password) {
    return res.status(400).json({
      success: false,
      message: "Please fill username and/or password field!",
    });
  }

  try {
    // Check for existing user
    const user = await User.findOne({ username });

    if (!user) {
      return res
        .status(400)
        .json({ success: false, message: "Incorrect username or password" });
    }

    // Username found
    const passwordValid = await argon2.verify(user.password, password);

    if (!passwordValid) {
      return res
        .status(400)
        .json({ success: false, message: "Incorrect username or password" });
    }

    // All good
    // Return Token
    const accessToken = jwt.sign(
      { userId: user._id },
      process.env.ACCESS_TOKEN_SECRET
    );

    res.json({ success: true, message: "Loggin successfully", accessToken });
  } catch (error) {
    console.log(error);
    res.status(500).json({ success: false, message: "Internal server" });
  }
});

// Cant know password

// @route POST api/auth/forgot-password
// @desc forgot password
// @access Public

// router.post('/forgot-password', async (req, res) => {
//     const { email } = req.body
//     try {
//         const user = await User.findOne({ email })
//         if (!user) return res.status(400).json({ success: false, message: "This email does not exist!" })

//         const accessToken = createAccessToken({ id: user._id })
//         const url = `${CLIENT_URL}/user/reset/${accessToken}`

//         //Sentmail
//         res.json({ message: "Your password has been re-sent, please check your email." })
//     } catch (error) {
//         return res.status(500).json({ message: error.message })
//     }
// })

// @route POST api/auth/change-password
// @desc change password
// @access Public

router.post("/change-password", verifyToken, async (req, res) => {
  const { password } = req.body;
  //   console.log(req.body);
  //   console.log(password);
  try {
    const passwordHash = await argon2.hash(password);
    await User.findOneAndUpdate(
      { _id: req.userId },
      { password: passwordHash },
      { new: true }
    );
    res.json({ message: "Password successfully changed!" });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

module.exports = router;
