
require("dotenv").config(); // in file '.env' !no spacebar !no semicolon !no define
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
//const encrypt = require("mongoose-encryption");
//const md5 = require("md5"); // hash function
//const bcrypt = require("bcrypt");
//const saltRound = 12; // the more, make safer (for using hash bcrypt)

/* to get session (cookie) when login but 
/ if [1] server restart [2] close browser [3] logout
/ must to login again */
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

//sample: log API_KEY in fil '.env'
//console.log(process.env.API_KEY);

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true}));

// initialized session
app.use(session({
    secret: "Secret eiei.",
    resave: false,
    saveUninitialized: true
}));

// init passport
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//encrypt: encrypt when save / decrypt when find
                                     //SECRET: to encrypt in file 'env' // ใส่เพิ่มได้เช่น "pw", "id"
//userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });

const User = new mongoose.model("User", userSchema);

//createStrategy is responsible to setup passport-local (cookie)
passport.use(User.createStrategy());
//set passport to de and serialize
passport.serializeUser(function(user, done) {
    done(null, user);
});
   
  passport.deserializeUser(function(user, done) {
    done(null, user);
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res){
    res.render("home");
});

app.get("/auth/google", passport.authenticate('google', {
    scope: ['profile']
}));

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect /secrets.
    res.redirect("/secrets");
});

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});

app.get("/secrets", function(req, res){
    // //check there is authenticate?
    // if(req.isAuthenticated()) {
    //     res.render("secrets");
    // } else {
    //     res.redirect("/login");
    // }

    User.find({"secret": {$ne: null}}, function(err, foundUsers){
        if (err) {
            console.log(err);
        } else {
            if (foundUsers) {
                res.render("secrets", { usersWithSecrets: foundUsers});
            }
        }
    });
});

app.get("/submit", function(req, res){
    if(req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.get("/logout", function(req, res){
    req.logout();
    res.redirect("/");
});

//////////////////////////////// POST ///////////////////////////////////////

app.post("/register", function(req, res){

    // bcrypt.hash(req.body.password, saltRound, function(err, hash){
    //     const newUser = new User({
    //         email: req.body.username,
    //         password: hash
    //     });

    //     newUser.save(function(err){
    //         if(err) {
    //             console.log(err);
    //         } else {
    //             res.render("Secrets");
    //         }
    //     });
    // });

    User.register({ username: req.body.username }, req.body.password, function(err, user){
        if(err) {
            console.log(err);
            res.redirect("/register");
        } else {
            // authenticate user
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/login", function(req, res){

    // const username = req.body.username;
    // const password = req.body.password;

    // User.findOne({email: username}, function(err, foundUser){
    //     if(err) {
    //         console.log(err);
    //     } else {
    //         if(foundUser) {
    //             bcrypt.compare(password, foundUser.password, function(err, result) {
    //                 if(result === true){
    //                     res.render("Secrets");
    //                 }
    //             });
    //         }
    //     }
    // });

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function(err){
        if(err) {
            console.log(err);
        } else {
            // authenticate user
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/submit", function(req, res){
    const submitted = req.body.secret;

    User.findById(req.user, function(err, foundUser){
        if(err) {
            console.log(err);
        } else {
            console.log(foundUser);
            if(foundUser) {
                foundUser.secret = submitted;
                foundUser.save(function(){
                    res.redirect("/secrets");
                });
            }
        }
    });
});

app.listen(3000, function(){
    console.log("Server started on port 3000.");
});
