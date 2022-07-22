

var express = require('express');
var router = express.Router();
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const {body, validationResult } = require("express-validator");
const User = require("./models/User");
const jwt = require("jsonwebtoken");
const validateToken = require("../auth/validateToken");


/* GET users listing. */
router.get('/private', validateToken, (req, res, next) => {
  User.find({}, (err, users) =>{
    if(err) return next(err);
    res.render("users", {users});
  })
  
});

router.get('/login', (req, res, next) => {
  res.render('login');
});

router.post('/user/login', 
  body("email").trim(),
  body("password"),
  (req, res, next) => {
    User.findOne({email: req.body.email}, (err, email) =>{
    if(err) throw err;
    console.log(email);

    if(!email) {
      return res.status(403).json({message: "Login failed"});
    } else {
      bcrypt.compare(req.body.password, email.password, (err, isMatch) => {
        if(err) throw err;
        if(isMatch) {
          const jwtPayload = {
            id: email._id,
            email: email.email
          }
          jwt.sign(
            jwtPayload,
            process.env.SECRET,
            {
              expiresIn: 120
            },
            (err, token) => {
              res.json({success: true, token});
            }
          );
        }
      })
    }

    })

});



router.get('/register', (req, res, next) => {
  res.render('register');
});

router.post('/user/register/', 
  body("email").trim(),
  body("password").isLength({min: 5}),
  (req, res, next) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()) {
      return res.status(400).json({errors: errors.array()});
    }
    User.findOne({email: req.body.email}, (err, email) => {
      if(err) {
        console.log(err);
        throw err
      };
      if(email){
        return res.status(403).json({email: "This email already registered"});
      } else {
        bcrypt.genSalt(10, (err, salt) => {
          bcrypt.hash(req.body.password, salt, (err, hash) => {
            if(err) throw err;
            User.create(
              {
                email: req.body.email,
                password: hash
              },
              (err, ok) => {
                if(err) throw err;
                return res.redirect("/api/user/login");
              }
            );
          });
        });
      }
    });
});



module.exports = router;
