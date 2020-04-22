const express = require('express');
const app= express()
const bcrypt= require("bcrypt")
const PORT= process.env.PORT || 4000;//referencing environment variable in which it will use env port for production, but port 4000 when developing
const session= require("express-session");
const flash= require("express-flash");
const passport= require("passport");

const initializePassport= require("./passportConfig");

initializePassport(passport);

const { pool }= require('./dbConfig');

app.set("view engine", "ejs");
app.use(express.urlencoded({extended: false}));//alllows us to send details from the frontend

app.use(session({
  secret: "secret", //change this to environment variable later on

  resave: false,//save session details

  saveUnitialized: false
}));

app.use(flash());

app.use(passport.initialize());
app.use(passport.session());

app.get('/', (req, res)=>{
  res.render("index");
});//elements are root directory, and request response elements

app.get('/users/register', checkAuthenticated, (req, res) => {
  res.render("register");
});

app.get('/users/login', checkAuthenticated, (req, res) => {
  res.render("login");
});

app.get('/users/dashboard', checkNotAuthenticated, (req, res) => {//checks to see if user is authenticated, if it is, continues response, otherwise goes to login page
  res.render("dashboard", {user:req.user.name});
});

app.get("/users/logout", (req, res) => {
  req.logOut();
  req.flash("success_msg", "You have successfully signed out");
  res.redirect('/users/login');
})

app.post('/users/register', async (req, res) =>{
  let {name, email, password, password2, name1}= req.body;
  console.log(
    {
      name,
      email,
      password,
      password2,
      name1
    });

    let errors= [];//form validation

    if(!name || !email || !password || !password2 ||!name1){
      errors.push({message:"Please ensure all fields are filled"});
    }
    if(password.length < 6){
      errors.push({message:"Please ensure password is greater than 6 characters"});
    }
    if(password != password2){
      errors.push({message:"Please ensure your passwords match"});
    }
    if(errors.length > 0){
      res.render('register', {errors});
    }
    else {
      //form validation has passed
      let hashedPassword = await bcrypt.hash(password, 10);//the 10 is the rounds of encryption for the password: 10 is default
      console.log(hashedPassword);

      pool.query(
        `SELECT * FROM users
        WHERE email= $1`, [email], (err, results)=> {
          if(err){
            throw err;
          }
          // process.on('uncaughtException', function (err) {
          //     console.log(err);
          // });
          console.log("reaches here");
          console.log(results.rows);
          if(results.rows.length > 0){
            errors.push({message:"Email already exists"});
            res.render("register", {errors});
          }
          else{
            pool.query(
              `INSERT INTO users (name, email, password, displayName)
              VALUES ($1, $2, $3, $4)
              RETURNING id, password, displayName`, [name, email, hashedPassword, name1], (err, results) =>{
                if(err){
                  throw err;
                }
                console.log(results.rows);
                req.flash('success_msg', "You are now registered to Concurrent! Please Login! Enjoy!");
                res.redirect("/users/login");
              }
            )
          }
        }
      );
    }
});

app.post("/users/login", passport.authenticate('local', {
  successRedirect: "/users/dashboard",
  failureRedirect: "users/login",
  failureFlash: true//if we can't authenticate, express will render one of the previous failure messages
}));

function checkAuthenticated(req, res, next){
  if(req.isAuthenticated()){
    return res.redirect("/users/dashboard");
  }
  next();
}

function checkNotAuthenticated(req, res, next){
  if(req.isAuthenticated()){
    return next();
  }

  res.redirect("/users/login");
}

app.listen(PORT, () => {
  console.log(`Server Running on Port ${PORT}`);
});
