require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

// Config JSON response
app.use(express.json());

const User = require("./models/User");

app.get("/", (req, res) => {
  res.status(200).json({ msg: " welcome to API LOGIN!" });
});

//Register User
app.post("/auth/register", async (req, res) => {
  const { name, email, password, confirmpassword } = req.body;

  if (!name) {
    return res.status(422).json({ msg: "Name is required field." });
  }
  if (!email) {
    return res.status(422).json({ msg: "Email is required field." });
  }
  if (!password) {
    return res.status(422).json({ msg: "Pass is required field." });
  }

  if (password !== confirmpassword) {
    return res.status(422).json({ msg: "passwords do not match." });
  }

  const userEXists = await User.findOne({ email: email });

  if (userEXists) {
    return res.status(422).json({ msg: "E-mail already registered!" });
  }

  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);

  const user = new User({
    name,
    email,
    password: passwordHash,
  });

  try {
    await user.save();
    res.status(201).json({ msg: "User created successfully!" });
  } catch (error) {
    console.log(error);
    res
      .status(500)
      .json({ msg: "erroThere was a server error, please try again later" });
  }
});

// Login User
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email) {
    return res.status(422).json({ msg: "Email is required field." });
  }
  if (!password) {
    return res.status(422).json({ msg: "Pass is required field." });
  }
  //check if user exists
  const user = await User.findOne({ email: email });
  if (!user) {
    return res.status(404).json({ msg: "User not found." });
  }

  const checkPassword = await bcrypt.compare(password, user.password);

  if (!checkPassword) {
    return res.status(422).json({ msg: "Password not found." });
  }

  try {
    const secret = process.env.SECRET;

    const token = jwt.sign(
      {
        id: user._id,
      },

      secret
    );

    res.status(200).json({ msg: "Successful authentication.", token });
  } catch (err) {
    console.log(err);
    res
      .status(500)
      .json({ msg: "erroThere was a server error, please try again later" });
  }
});

// Credencials
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPassword}@cluster0.8uscoab.mongodb.net/?retryWrites=true&w=majority`
  )
  .then(() => {
    app.listen(3000);
    console.log("DB connected!");
  })
  .catch((err) => console.log(err));
