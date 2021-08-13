//jshint esversion:6

require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
// const encrypt = require("mongoose-encryption");
// const md5 = require("md5");
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended: true}));
app.set("view engine" , "ejs");

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());



mongoose.connect("mongodb://localhost:27017/userDB",  { useNewUrlParser: true,  useUnifiedTopology: true });
mongoose.set("useCreateIndex" , true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//encrypt password section
// secret file in -->
//after using md5 i commented all the mongoose-encryption line
// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]});


const User = new mongoose.model("User" , userSchema);

//Simplified Passport/Passport-Local Configuration
passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

/////////////////////Passport Google Auth2.0/////////////////////////////
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

/////////////////////////////Home Page/////////////////////////////////////
app.get("/" , function(req, res){
  res.render("home");
});

////////////////////////////Login through google//////////////////////////
app.get("/auth/google",
  passport.authenticate("google" , {scope: ["profile"]})
);

app.get("/auth/google/secrets",
  passport.authenticate("google", {failureRedirect: "/login"}),
  function(req, res){
    // Succesful authentication, redirect secrets Page
    res.redirect("/secrets");
  }
);



/////////////////////////////Login page////////////////////////////////////
app.get("/login" , function(req, res){
  res.render("login");
});

app.post("/login" , function(req, res){
  // const username = req.body.username;
  // const password = req.body.password;
  //
  // User.findOne({email: username} , function(err , foundUser){
  //   if(err){
  //     console.log(err);
  //   }else {
  //     if(foundUser){
  //       bcrypt.compare(password, foundUser.password, function(err, result) {
  //         if (result === true) {
  //           res.render("secrets");
  //         }
  //       });
  //     }
  //   }
  // });



//using passport
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user , function(err){
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }

  });












});
///////////////////////secrets/////////////////////////////////////////////
//if cookies store then we can direct access secrets page otherwise we need to login
app.get("/secrets" , function(req, res){
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if (err) {
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets" , {usersWithSecrets: foundUsers});
      }
    }
  });
});



/////////////////////Register Page//////////////////////////////////////////
app.get("/register" , function(req, res){
  res.render("register");
});

app.post("/register", function(req, res){

  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  //   // Store hash in your password DB.
  //   const newUser = new User ({
  //     email: req.body.username,
  //     password: hash
  //   });
  //   newUser.save(function(err){
  //     if (err) {
  //       console.log(err);
  //     }else {
  //       res.render("secrets");
  //     }
  //   });
  //
  // });

  User.register({username: req.body.username}, req.body.password, function(err, user){
    if (err) {
      console.log(err);
      res.redirect("/redirect");
    } else {
      passport.authenticate("local")(req , res, function(){
        res.redirect("/secrets");
      });
    }
  });

});

//////////////////////////Submit//////////////////////////////////////
app.get("/submit", function(req, res){
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login")
  }
});

app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;

  User.findById(req.user.id, function(err , foundUser){
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});




///////////////////////////Logout//////////////////////////////////////
app.get("/logout" , function(req, res){
  req.logout();
  res.redirect("/");
});


/////////////////////////////////////////////////////////////////////////////


app.listen(3000 , function(){
  console.log("server started on port 3000.");
});
