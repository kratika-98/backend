const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const UserModel = require('./models/user')
const NoticeModel = require('./models/notice')
dotenv.config();

const app = express();
const PORT = process.env.PORT || 8000;

app.use(cors());
app.use(bodyParser.json());


// Authentication Middleware
const authentication = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    res.status(401).json({ error: "Log in first" });
  } else {
    jwt.verify(token, process.env.SECRET_KEY, function (err, decode) {
      if (err) {
        res.status(401).json({ error: "Login first" });
      } else {
        req.userID = decode.userID;
        next();
      }
    });
  }
};

// Register User
app.post("/sign_up", async (req, res) => {
  const { name, email, password, phone, department } = req.body;
  bcrypt.hash(password, 10, async function (err, hash) {
    if (err) {
      res.status(500).json({ error: "Some wrong goes, please recheck" });
    } else {
      try {
        const user = await UserModel.create({
          name,
          email,
          password: hash,
          phone,
          department
        });
        res.status(201).json(user);
      } catch (err) {
        console.error("Something went wrong", err);
        res.status(500).json({ error: "Something went wrong" });
      }
    }
  });
});

// Login User
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await UserModel.findOne({ email });
  if (user) {
    const userPassword = user.password;
    bcrypt.compare(password, userPassword, function (err, result) {
      if (result) {
        const token = jwt.sign({ userID: user._id }, process.env.SECRET_KEY, { expiresIn: '1h' });
        res.json({ msg: "Login successful", token: token });
      } else {
        res.status(401).json({ error: "Login failed, password mismatched" });
      }
    });
  } else {
    res.status(404).json({ error: "User not found" });
  }
});

// Create Notice
app.post('/notices', authentication, async (req, res) => {
  const { title, body, category, date } = req.body;
  try {
    const notice = await NoticeModel.create({
      title,
      body,
      category,
      date,
      user: req.userID 
    });
    res.status(201).json(notice);
  } catch (err) {
    console.error("Something went wrong", err);
    res.status(500).json({ error: "Something went wrong" });
  }
});

//..................................................................
app.get('/notices', authentication, async (req, res) => {
  const { category } = req.query;
  try {
    let notices;
    if (category) {
      notices = await NoticeModel.find({ category, user: req.userID }).populate('user', 'name email');
    } else {
      notices = await NoticeModel.find({ user: req.userID }).populate('user', 'name email');
    }
    res.json(notices);
  } catch (err) {
    console.error("Something went wrong", err);
    res.status(500).json({ error: "Something went wrong" });
  }
});

// Update Notice..............................................................
app.put('/notices/:id', authentication, async (req, res) => {
  const { title, body, category, date } = req.body;
  try {
    const notice = await NoticeModel.findOneAndUpdate({ _id: req.params.id, user: req.userID }, {
      title,
      body,
      category,
      date
    }, { new: true });
    if (notice) {
      res.json(notice);
    } else {
      res.status(404).json({ error: "Notice not found" });
    }
  } catch (err) {
    console.error("Something went wrong", err);
    res.status(500).json({ error: "Something went wrong" });
  }
});

// Delete Notice................................................................
app.delete('/notices/:id', authentication, async (req, res) => {
  try {
    const notice = await NoticeModel.findOneAndDelete({ _id: req.params.id, user: req.userID });
    if (notice) {
      res.json(notice);
    } else {
      res.status(404).json({ error: "Notice not found" });
    }
  } catch (err) {
    console.error("Something went wrong", err);
    res.status(500).json({ error: "Something went wrong" });
  }
});


app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));