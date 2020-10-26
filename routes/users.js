const express = require("express");
const bcrpyt = require("bcryptjs");
const router = express.Router();
const passport = require("passport");
const User = require("../models/User");

// Login page
router.get("/login", (req, res) => {
  res.render("login");
});

// Register Page
router.get("/register", (req, res) => {
  res.render("register");
});

router.post("/register", (req, res) => {
  const { name, email, password, password2 } = req.body;
  let errors = [];

  // check required fields
  if (!name || !email || !password || !password2) {
    errors.push({
      msg: "Please fill in all fields",
    });
  }

  // check password matches
  if (password !== password2) {
    errors.push({
      msg: "Passwords do not match",
    });
  }

  // check password length
  if (password.length < 6) {
    errors.push({
      msg: "Password must be at least 6 characters",
    });
  }

  if (errors.length > 0) {
    res.render("register", {
      errors,
      name,
      email,
      password,
      password2,
    });
  } else {
    // Validation passes
    User.findOne({
      email: email,
    }).then((user) => {
      if (user) {
        // User exists
        errors.push({
          msg: "Email already registered",
        });
        res.render("register", {
          errors,
          name,
          email,
          password,
          password2,
        });
      } else {
        const newUser = new User({
          name,
          email,
          password,
        });

        // Hash the password
        bcrpyt.genSalt(10, (error, salt) => {
          bcrpyt.hash(newUser.password, salt, (err, hash) => {
            if (err) throw err;
            // encrypt the password
            newUser.password = hash;

            newUser
              .save()
              .then((user) => {
                req.flash(
                  "success_msg",
                  "You are now registered and can login"
                );
                res.redirect("/users/login");
              })
              .catch((err) => console.log(err));
          });
        });
      }
    });
  }
});

// Login Handle
router.post("/login", (req, res, next) => {
  passport.authenticate("local", {
    successRedirect: "/dashboard",
    failureRedirect: "/users/login",
    failureFlash: true,
  })(req, res, next);
});

// logout handle

router.get("/logout", (req, res) => {
  req.logOut();
  req.flash("success_msg", "You are logged out");
  res.redirect("/users/login");
});
module.exports = router;
