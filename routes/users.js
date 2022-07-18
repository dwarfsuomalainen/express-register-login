var express = require('express');
var router = express.Router();
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const {body, validationResult } = require("express-validator");
const User = require("./models/User");
const jwt = require("jsonwebtoken");
//const validateToken = require("../auth/validateToken.js")



/* GET users listing. */
router.get('/list', (req, res, next) => {
  //res.send('respond with a resource');
    User.find({}, (err, users) =>{
      if(err) return next(err);
    })
    res.render("users", {users});
});


router.get('/register', (req, res, next) => {
  res.render('Register');
});


router.get('/login', (req, res, next) =>{
  res.render('Login');
});

router.post('/register', 
  body("username").isLength({min: 3}).trim().escape(),
  body("password").isLength({min: 5}),
  (req, res, next) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()) {
      return res.status(400).json({errors: errors.array()});
    }
    User.findOne({username: req.body.username}, (err, user) => {
      if(err) {
        console.log(err);
        throw err
      };
      if(user){
        return res.status(403).json({username: "Username already in use."});
      } else {
        bcrypt.genSalt(10, (err, salt) => {
          bcrypt.hash(req.body.password, salt, (err, hash) => {
            if(err) throw err;
            User.create(
              {
                username: req.body.username,
                password: hash
              },
              (err, ok) => {
                if(err) throw err;
                return res.redirect("/users/login");

            }
          )
        })
      })
    }
  })
  
  
});



module.exports = router;

