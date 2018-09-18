//Details with authentication, username, username, and password
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const keys = require('../../config/keys');
const passport = require('passport');

//Load Input Validation 
const validateRegisterInput = require('../../validation/register');
const validateLoginInput = require('../../validation/login');


//Load user model
const User = require('../../models/User');


//Get request to api/users/test
//Tests user route
//Access is public route
router.get('/test', (req, res) => res.json({msg: 'Users Works'}));

//Get api/users/register
//Register User
//Public
router.post('/register', (req, res) => {
    const { errors, isValid } = validateRegisterInput(req.body);
    //Check Validation
    if(!isValid){
        return res.status(400).json(errors);
    }
    User.findOne({ username: req.body.username })
    .then(user => {
        if(user){
            errors.username = 'Username already exists';
            return res.status(400).json(errors);
        } else {
            const newUser = new User({
                username: req.body.username,
                password: req.body.password
            });
             bcrypt.genSalt(10, (err, salt) => {
                 bcrypt.hash(newUser.password, salt, (err, hash) => {
                     if(err) {throw err};
                     newUser.password = hash;
                     newUser.save()
                     .then(user => res.status(200).json(user))
                     .catch(err => errorHandler(res, { err: err }, 400))
                });
             })
         }
     })
     .catch(err => errorHandler(res, {err, err}, 500))
 });

 //Get api/users/login
 //Login User Returning token JWT Token
 //access Public

 router.post('/login', (req, res) => {
    const { errors, isValid } = validateLoginInput(req.body);
    //Check Validation
    if(!isValid){
        return res.status(400).json(errors);
    }
     const username = req.body.username;
     const password = req.body.password;

     //Find the user by username
    User.findOne({username : req.body.username})
    .then(user => {
        //Check for user 
        if(!user) {
            errors.username = 'Username not found';
            return res.status(404).json(errors);
        }
        //Check password
        bcrypt.compare(password, user.password)
        .then(isMatch => {
            if(isMatch) {
                //User Matcher
            const payload = {id: user.id, username: user.username }
            //Sign Token
            jwt.sign(
                payload, 
                keys.secretOrKey, 
                { expiresIn: 3600 },
                (err, token) => {
                    res.json({
                        success: true, 
                        token: 'Bearer' + token 
                    });
            });
            } else {
                errors.password = 'Password incorrect';
                return res.status(400).json(errors);
            }
        })
    });
 })


// @route   GET api/users/current
// @desc    Return current user
// @access  Private
router.get(
    '/current',
    passport.authenticate('jwt', { session: false }),
    (req, res) => {
      res.json({
        id: req.user.id,
      });
    }
);



module.exports = router;