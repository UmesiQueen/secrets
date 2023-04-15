require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const { mongoose, Schema } = require("mongoose");
const MongoStore = require("connect-mongo"); //session to mongo

const session = require("express-session");

const passport = require("passport");
const bcrypt = require("bcrypt");

const LocalStrategy = require("passport-local").Strategy;
const passportLocalMongoose = require("passport-local-mongoose");
const { isAuth, isAdmin } = require("./middleware/authMiddleware");

const GoogleStrategy = require("passport-google-oauth20").Strategy; //GOOGLE PASSPORT STRATEGY
const findOrCreate = require("mongoose-findorcreate"); //find, create if doesn't exists

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

const url = "mongodb://127.0.0.1/userDB";

const options = { useNewUrlParser: true, useUnifiedTopology: true };

const ONE_HOUR = 1000 * 60 * 60; //1hr

mongoose
  .connect(url, options)
  .then(() => {
    console.log("Database connected successfully!");
  })
  .catch((err) => {
    console.log("Error while connecting to db");
    console.log(err);
  });

const sessionStore = MongoStore.create({
  mongoUrl: url,
});

app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
    store: sessionStore,
    cookie: {
      maxAge: ONE_HOUR,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

//custom middleware, req.user is populated by passport when a user is authenticated

//DB SCHEMA
const userSchema = new Schema(
  {
    username: String,
    password: String,
    admin: Boolean,
    googleId: String,
    secret: String,
  },
  {
    versionKey: false,
  }
);

//Export Model
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("user", userSchema);

//declare and config strategy
passport.use(User.createStrategy());

// To maintain login session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((userId, done) => {
  User.findById(userId)
    .then((user) => {
      done(null, user);
    })
    .catch((err) => {
      done(err);
    });
});

// Passport Local Strategy
passport.use(
  new LocalStrategy((username, password, done) => {
    User.findOne({ username: username }, (err, user) => {
      if (err) {
        return done(err);
      }

      if (!user) {
        return done(null, false);
      }

      bcrypt.compare(password, user.password, function (err, result) {
        if (err) {
          console.log(err);
        }

        if (!result) {
          return done(null, false);
        }
        return done(null, user);
      });
    });
  })
);

//PASSPORT GOOGLE STRATEGY
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
    },
    function (accessToken, refreshToken, profile, cb) {
      // console.log(profile);

      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

//HOME ROUTE
app.get("/", (req, res) => {
  res.render("home");
});

//RESISTER ROUTE
app
  .route("/register")
  .get((req, res) => {
    res.render("register");
  })
  .post((req, res) => {
    bcrypt.genSalt(10, function (err, salt) {
      if (!err) {
        bcrypt.hash(req.body.password, salt, (err, hash) => {
          if (!err) {
            const newUser = new User({
              username: req.body.username,
              password: hash,
            });
            newUser.save().then(() => {
              res.redirect("/login");
            });
          }
        });
      } else {
        console.log(err);
      }
    });
  });

//LOGIN ROUTE
app
  .route("/login")
  .get((req, res) => {
    res.render("login");
  })
  .post(
    passport.authenticate("local", {
      failureRedirect: "/login",
      failureMessage: true,
    }),
    (req, res) => {
      res.redirect("/secrets");
    }
  );

//SECRETS ROUTE
//the secrets route checks if the user with current session id is authenticated with the isAuth middleware
app.get("/secrets", (req, res) => {
  User.find({ secret: { $ne: null } },(err, result) => {
    if (err) {
      console.log(err);
    } else {
      if (result) {
        // console.log(result);
        res.render("secrets", { usersWithSecrets: result });
      }
    }
  });
});

//GOOGLE AUTHENTICATE ROUTE
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    // Successful authentication, redirect to secrets
    res.redirect("/secrets");
  }
);


//ADMIN ROUTE
app.get("/admin", isAdmin, (req, res) => {
  res.send("You are now in the admin route!");
});

// SUBMIT ROUTE
app
  .route("/submit")
  .get(isAuth, (req, res) => {
    res.render("submit");
  })
  .post((req, res) => {
    const submittedSecret = req.body.secret;

    User.findById(req.user.id, (err, foundUser) => {
      if (err) {
        console.log(err);
      } else {
        if (foundUser) {
          foundUser.secret = submittedSecret;
          foundUser.save().then(() => {
            res.redirect("/secrets");
          });
        }
      }
    });
  });

//LOGOUT ROUTE
app.get("/logout", (req, res) => {
  //logs out users at this point, clearing authentication
  req.logout((err) => {
    if (!err) {
      res.redirect("/");
    }
  });
});

app.listen(process.env.PORT || 3000, function () {
  console.log("Server started on port 3000.");
});
