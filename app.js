require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

app.get("/", (req, res) => {
  res.status(200).json({ msg: " welcome to API LOGIN!" });
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
