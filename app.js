const dotenv = require('dotenv');
const express = require("express");
const app = express();
const userModel = require("./models/user");
const postModel = require("./models/post");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const post = require("./models/post");
const crypto = require("crypto");
const path = require("path");
const multer = require("multer");
const upload = require("./config/multerconfig");
const mongoose = require('mongoose');

app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(cookieParser());


dotenv.config({ path: './config.env' });

const DB = process.env.DATABASE;

mongoose.connect(DB, { 
    useNewUrlParser: true, 
    useUnifiedTopology: true 
})
.then(() => {
    console.log("Connected to the database");
})
.catch((err) => {
    console.log("Failed to connect to the database", err);
});

// multer local storage

// const storage = multer.diskStorage({
//     destination: function (req, file, cb) {
//       cb(null, './public/images/uploads')
//     },
//     filename: function (req, file, cb) {
//       crypto.randomBytes(12,function(err,bytes){
//        const fn = bytes.toString("hex") + path.extname(file.originalname)
//         cb(null, fn);
//       })
//     }
//   })
  
//   const upload = multer({ storage: storage })

//   app.get("/test", (req, res) => {
//     res.render("test");
//   });

//   app.post("/upload",upload.single('image'), (req, res) => {
//      console.log(req.file);
//   });  


app.get("/", (req, res) => {
  res.render("front");
});

app.get("/register", (req, res) => {
  res.render("index");
});

app.get("/profile/upload", (req, res) => {
    res.render("profileupload");
  });

  app.post("/upload",isLoggedIn,upload.single("image"), async (req, res) => {
    let user = await userModel.findOne({email:req.user.email});
    user.profilepic = req.file.filename;
    await user.save();
    res.redirect("/profile");  
});
  



app.get("/login", (req, res) => {
    res.render("login");
  });



  app.get("/profile",isLoggedIn, async (req, res) => {
    let user = await userModel.findOne({email:req.user.email}).populate("posts");
    res.render("profile",{user});
  });


  app.get("/like/:id",isLoggedIn, async (req, res) => {
    let post = await postModel.findOne({_id:req.params.id}).populate("user");
  
    if(post.likes.indexOf(req.user.userid)===-1){
    post.likes.push(req.user.userid);
   }else{
     post.likes.splice(post.likes.indexOf(req.user.userid),1);
   }
    
    await post.save();
    res.redirect("/profile");
  });


  app.get("/edit/:id",isLoggedIn, async (req, res) => {
    let post = await postModel.findOne({_id:req.params.id}).populate("user");
    res.render("edit",{post});
  });


  app.post("/update/:id",isLoggedIn, async (req, res) => {
    let post = await postModel.findOneAndUpdate({_id:req.params.id},{content:req.body.content});
    res.redirect("/profile");
  });


  app.post("/post",isLoggedIn, async (req, res) => {
    let user = await userModel.findOne({email:req.user.email}) 
    let {content} = req.body;
    let post = await postModel.create({
        user:user._id,
        content
    })
    user.posts.push(post._id);
    await user.save();
    res.redirect("/profile");
  });


app.post("/register", async (req, res) => {
  let { email, password, username, name, age } = req.body;

  // Check if user already exists
  let user = await userModel.findOne({ email });
  if (user) return res.status(500).send("User already registered");

  // Hash the password and save the new user
  bcrypt.genSalt(10, (err, salt) => {
    if (err) return res.status(500).send("Error generating salt");
    
    bcrypt.hash(password, salt, async (err, hash) => {
      if (err) return res.status(500).send("Error hashing password");

      try {
        let newUser = await userModel.create({
          username,
          name,
          age,
          email,
          password: hash,
        });

        // Generate a token for the user
        let token = jwt.sign(
          { email: email, userid: newUser._id },
          "shhhhhhhhhh"
        );

        // Send the token as a cookie
        res.cookie("token", token);
        res.render("login");
      } catch (error) {
        res.status(500).send("Error creating user");
      }
    });
  });
});


app.post("/login", async (req, res) => {
    let { email, password } = req.body;

    // Check if user exists
    let user = await userModel.findOne({ email });
    if (!user) return res.status(400).send("User not found");

    // Compare password with stored hash
    bcrypt.compare(password, user.password, function(err, result) {
        if (err) return res.status(500).send("Error comparing passwords");

        if (result) {
            // Password is correct, generate JWT token
            let token = jwt.sign(
                { email: email, userid: user._id },
                "shhhhhhhhhh"
            );

            // Send the token as a cookie
            res.cookie("token", token);
            res.status(200).redirect("/profile");
        } else {
            // Incorrect password, send error message
            res.status(401).send("Incorrect password");
        }
    });
});


app.get("/logout", (req, res) => {
    res.cookie("token","");
    res.redirect("/");
  });

  function isLoggedIn(req,res,next){
    if(req.cookies.token === "") res.redirect("/login");
    else{
        let data = jwt.verify(req.cookies.token,"shhhhhhhhhh");
        req.user = data;
        next();
    }
  }


app.listen(3000, () => {
  console.log("Server is running on port 3000");
});




