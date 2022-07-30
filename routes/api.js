

var express = require('express');
var router = express.Router();
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const {body, validationResult } = require("express-validator");
const User = require("../models/User");
const Todos = require("../models/Todo")
const jwt = require("jsonwebtoken");
const validateToken = require("../auth/validateToken");
const extractToken = require("../auth/extractToken");
const { json } = require('express');
//const passport = require('passport');
//const localStrategy = require('passport-local').Strategy;

var emailY = 0;
var EMAILID;
var idTODOS;

/* GET users listing. */
router.get("/private", validateToken, (req, res, next) => {
  const { email } = extractToken(req);
  console.log(emailY);
  res.json({ email });
  
  /*User.find({}, (err, users) =>{
    if(err) return next(err);
    res.render("users", {users}); - list of users 
  })*/
  
});

router.get('/login', (req, res, next) => {
  res.render('login');
});

// todos

router.post("/todos/", validateToken, (req, res, next) => {
  const { id } = extractToken(req);

  Todos.findOne({ user: id }, (err, existingTodo) => {
    if (err) return next(err);
    if (!existingTodo) {
      new Todos({ user: id, items: req.body.items }).save((err) => {
        if (err) return next(err);
        return res.status(200).send("ok");
      });
    } else {
      existingTodo.items = [...existingTodo.items, ...req.body.items];
      existingTodo.save();
      return res.send("ok2");
    }
  });
});

router.post('/user/login', 
  body("email").trim(),
  body("password"),
  (req, res, next) => {
    User.findOne({email: req.body.email}, (err, email) =>{
    if(err) throw err;
    console.log(email);
    emailY = email.email;


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
          let emailX = jwtPayload.email
          console.log(jwtPayload.email);
          EMAILID = jwtPayload.id;
          console.log(EMAILID);
          jwt.sign(jwtPayload,process.env.SECRET,
            {
              expiresIn: 120
            },
            (err, token) => {
              //console.log(idTODOS);
              res.json({success: true, token, emailX, EMAILID});
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
  body("email").isEmail().trim(),
  body("password").isLength({min: 8}),
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
                return res.redirect("/api/login");
              }
            );
          });
        });
      }
    });
});



module.exports = router;
