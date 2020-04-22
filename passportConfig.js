const LocalStrategy= require("passport-local").Strategy;
const { pool }= require("./dbConfig");
const bcrypt= require("bcrypt");

function initialize(passport){
  const authenticateUser = (email, password, done)=>{
    pool.query(
      `SELECT * FROM users WHERE email = $1`, [email], (err, results)=>{
        if(err){
          throw err;
        }
        console.log(results.rows);

        if(results.rows.length > 0){
          const user= results.rows[0];

          bcrypt.compare(password, user.password, (err, isMatch)=>{
            if(err){
              throw err;
            }

            if(isMatch){
              return done(null, user);//if first paramater is the error, which is true, it will be null, and since they match we will return the user
            }
            else {
              return done(null, false, {message:"Password is incorrect"});
            }
          });
        }
        else{
          return done(null, false, {message:"Email is not Registered to Concurrent"});
        }
      }
    );
  };
  passport.use(new LocalStrategy({
    usernameField:"email",
    passwordField:"password"
  },
  authenticateUser
));

passport.serializeUser((user, done) => done(null, user.id));//stores userid in the session to keep track of user's session (stores in the user cookie)

passport.deserializeUser((id, done)=> {//uses passport id to obtain user details from the database and store the full object into the session like navigation
  pool.query(
    `SELECT * FROM users WHERE id = $1`, [id], (err, results)=> {
      if(err){
        throw err;
      }
      return done(null, results.rows[0]);//stores user object in the session
    });
});
}

module.exports= initialize;
