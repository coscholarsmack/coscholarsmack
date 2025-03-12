require("dotenv").config()
const jwt = require("jsonwebtoken")
const sanitizeHTML =require('sanitize-html')
const marked = require("marked")
const cookieParser= require('cookie-parser')
const bcrypt =require ("bcrypt")
const express =require("express")
const db = require("better-sqlite3")("ourApp.db")
db.pragma("journal_mode =WAL")
// database setup here
const createTables =db.transaction(()=>{
    db.prepare(  
        `
        CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username STRING NOT NULL UNIQUE,
      password STRING NOT NULL ,
      email STRING NOT NULL,
      typeofuser ENUM(teacher,learner) NOT NULL)`
    ).run()
    db.prepare(`
        CREATE TABLE IF NOT EXISTS posts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        createdDate TEXT,
        title STRING NOT NULL,
        body TEXT NOT NULL,
        authorid INTEGER,
        FOREIGN KEY (authorid) REFERENCES users (id)
        `).run;
            // Create categories table for notes
    db.prepare(`
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )
    `).run();

    // Create notes table
    db.prepare(`
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            category_name TEXT NOT NULL,
            teacher_id INTEGER NOT NULL,
            createdDate TEXT,
            FOREIGN KEY (category_name) REFERENCES categories(name),
            FOREIGN KEY (teacher_id) REFERENCES users(id)
        )
    `).run();
      
})
createTables()
const app= express() 

app.set("view engine", "ejs")
app.use(express.static("public"))
app.use(express.urlencoded({extended:false}))
app.use(cookieParser())
app.use(function (req,res,next){
    //utilising markdown logic
    res.locals.filterUserHTML = function(content){
        return sanitizeHTML(marked.parse(content),{
            allowedTags:["p","br","ul","li","bold","i","strong","ol","em","h1","h2","h3","h4","h5","h6"],
            allowedAttributes:{}
        })
    }
    //making errors variable available to the view files
    res.locals.errors =[]
    //try to decode incoming cookie
    try{
   const decoded =jwt.verify(req.cookies.ourSimplecookie,process.env.JWTSECRET)// this is an object with content like username,id,so on
   req.user=decoded//this is creating a property in the request instance that has the values for the object created my the key
} catch(err){
   req.user=false
    }
    res.locals.user=req.user
    console.log(req.user)
    next()
 })
app.get("/",(req,res)=>{
    if(req.user){
        const postsStatement = db.prepare("SELECT* FROM posts WHERE authorid= ?")
        const posts = postsStatement.all(req.user.userid)
        if(Usertype=="teacher")
            return res.render("dashboard-trs",{posts})
        if(Usertype=="learner")
            return res.render("dashboard",{posts})
    }
    res.render("homepage")
})
app.get("/logout",(req,res)=>{
    res.clearCookie("ourSimplecookie")
    res.redirect("/")
})
app.get("/login",(req,res)=>{
    res.render("login")
})
//database satement for categories
const ourStatement= db.prepare("INSERT INTO categories (Categoryname) VALUES (?)")
const Categories1=[Math,Physics,Chemistry,Biology,Literature&English,History&PoliticalScience, Geography,Ict]
 Categories1.forEach(category => {
    let result = ourStatement.run(Categories1)
 });

app.post("/register",(req,res)=>{
    const errors =[]
 if(typeof req.body.username !== "string") req.body.username= ""
 if(typeof req.body.password !== "string") req.body.password= ""
 
 req.body.username = req.body.username.trim()

 if(!req.body.username) errors.push("You must provide a username.")
 if(req.body.username && req.body.username.length< 3) errors.push("Username must be atleast 3 characters")   
 if(req.body.username && req.body.username.length>10) errors.push("Username must be less than 10 characters")
 if(req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("Username can only contain letters and numbers")
 //check if username exists already
const usernameStatement=db.prepare("SELECT* FROM users WHERE username = ?")
const usernameCheck =usernameStatement.get(req.body.username)
 if(usernameCheck) errors.push("That username is already taken")
 if(!req.body.password) errors.push("You must provide a password.")
 if(req.body.password && req.body.password.length<10) errors.push("Password must be atleast 10 characters")   
 if(req.body.password && req.body.password.length> 40) errors.push("Password must be less than 40 characters") 
    if(errors.length) {
        return res.render("homepage",{errors})
    } 
    //to hash our password when logging for not even the backend to know
    const salt= bcrypt.genSaltSync(10)
    req.body.password = bcrypt.hashSync(req.body.password,salt)
        //save the new user into the database
        const ourStatement= db.prepare("INSERT INTO users (username,password,email,typeofuser) VALUES (?,?,?,?)")
        const result = ourStatement.run(req.body.username, req.body.password, req.body.email, req.body.typeofuser)    
        //log the user in by giving them a cookie
        const lookupStatement = db.prepare("SELECT*FROM USERS WHERE ROWID=?")
        const ourUser= lookupStatement.get(result.lastInsertRowid)
        const ourTokenValue =jwt.sign({exp:Math.floor(Date.now()/1000)+60*60*24, skyColor:"blue",userid:ourUser.id,username:ourUser.username},process.env.JWTSECRET)
    res.cookie("ourSimplecookie",ourTokenValue,{
        httpOnly:true,
        secure: true,
        sameSite:"strict",
        maxAge:1000*60*60*24
    }) 
    const Usertype=req.body.typeofuser
    res.redirect("/")
})
app .post("/login",(req, res)=>{
    //logic for the login section 
    let errors =[]
    if(typeof req.body.username !== "string") req.body.username= ""
    if(typeof req.body.password !== "string") req.body.password= ""
    
    if(req.body.username.trim()=="") errors=["Invalid username / password."]
    if(req.body.password =="") errors=["Invalid username/password"]
      
        if (errors.length){
            return res.render("login",{errors})
        }
       const userInQuestionStatement = db.prepare("SELECT* FROM users WHERE USERNAME=?")
       const userInQuestion = userInQuestionStatement.get(req.body.username)
  
       if(!userInQuestion){
        errors=["Invalid username/ password"]
        return res.render("login",{errors})
       }
     const matchOrNot = bcrypt.compareSync(req.body.password, userInQuestion.password)
    if(!matchOrNot){
        errors=["Invalid username/ password"]
        return res.render("login",{errors})
    }
    // give them a cookie
    const ourTokenValue =jwt.sign({exp:Math.floor(Date.now()/1000)+60*60*24, skyColor:"blue",userid:userInQuestion.id,username:userInQuestion.username},process.env.JWTSECRET)
    res.cookie("ourSimplecookie",ourTokenValue,{
        httpOnly:true,
        secure: true,
        sameSite:"strict",
        maxAge:1000*60*60*24
    }) 
    res.redirect("/")
    //redirect them

})

function mustBeLoggedIn(req, res, next){//middleware to ensure that the user is logged in 
 if(req.user) {
    return next()
 }
 return res.redirect("/")
}
app.get("/post/:id",(req,res)=>{
const statement =db.prepare("SELECT posts.*,users.username FROM posts INNER JOIN users ON posts.authorid = users.id  WHERE posts.id =?")
const post = statement.get(req.params.id)

if(!post){
    return res.redirect("/")
}
const isAuthor= post.authorid === req.user.userid

res.render("single-post",{post,isAuthor})
})
app.get("/create-post",mustBeLoggedIn, (req,res)=>{
    res.render("create-post")
})
function sharedPostValidation(req) {//for verifying that posts are not malicious& are correct 
    const errors =[]
    if(typeof req.body.title !=="string") req.body.title =""
    if(typeof req.body.body !=="string") req.body.body =""
    //trim - sanitize or strip out html
     req.body.title= sanitizeHTML(req.body.title.trim(),{allowedTags:[], allowedAttributes: {}})
     req.body.body= sanitizeHTML(req.body.body.trim(),{allowedTags:[], allowedAttributes: {}})

     if(!req.body.title) errors.push("You must provide a title.")
     if(!req.body.body)  errors.push("You must provide content")
     
        return errors
}
app.get('/edit-post/:id',mustBeLoggedIn,(req,res)=>{
    //try to look up the post in question
    const statement = db.prepare("SELECT * FROM posts WHERE id = ?")
    const post = statement.get(req.params.id)
       // if the user doesnt exist
   
    if(!post){
        return res.redirect("/")
    }
    //if you're not the auther, redirect to homepage
      if(post.authorid !== req.user.userid){
        return res.redirect("/")
      }
 
    // otherwise, render the edit post template
 res.render('edit-post',{post})
})

app.post('/edit-post/:id', mustBeLoggedIn,(req,res)=>{
    //try to look up the post in question
   const statement = db.prepare("SELECT * FROM posts WHERE id = ?")
    const post = statement.get(req.params.id)

    if(!post){
        return res.redirect("/")
    }
    //if you're not the author, redirect to homepage
      if(post.authorid !== req.user.userid){
        return res.redirect("/")
      }
    // if the user doesnt exist
   
    const errors= sharedPostValidation(req)

    if(errors.length>0){
        return res.render("/edit-post", {errors})
    }
    const updateStatement= db.prepare("UPDATE posts SET title=?, body=? WHERE id=?")
    updateStatement.run(req.body.title,req.body.body,req.params.id)

    res.redirect(`/post/${req.params.id}`)
})
app.post("/create-post",(req, res)=>{
    //first goes through the sharedPostValidation() to make sure post is okay
    const errors= sharedPostValidation(req)

    if(errors.length>0){
        return res.render("/create-post", {errors})
    }
   //save into database
   const ourStatement1 =db.prepare("INSERT INTO notes (title,content, category_name, teacher_id) VALUES(?,?,?,?)")
   const result1 = ourStatement.run(req.body.title, req. body.body,req.body.category, req.user.userid, new Date().toISOString())

  //const ourStatement =db.prepare("INSERT INTO posts (title, body, authorid, createdDate) VALUES(?,?,?,?)")
//const result = ourStatement.run(req.body.title, req. body.body, req.user.userid, new Date().toISOString()) 

   const getPostStatement =db.prepare("SELECT * FROM posts WHERE ROWID = ?")
   const realPost = getPostStatement.get(result1.lastInsertRowid)

   res.redirect(`/post/${realPost.id}`)
})

app.post("/delete-post/:id",mustBeLoggedIn,(req,res)=>{
 // try to look up the post in question
 const statement =db.prepare("SELECT * FROM posts WHERE id =?")
 const post = statement.get(req.params.id)

 if(!post) {
    return res.redirect("/")
 }
 //if you're not the author ,redirect to homepage
 if (post.authorid !== req.user.userid) {
    return res.redirect("/")
 }
  const deleteStatement= db.prepare("DELETE FROM posts WHERE id = ?")
  deleteStatement.run(req.params.id)
  res.redirect("/")
})
app.get("/library",(req,res)=>{
    if(req.user) {

       return  res.render("library.html")
     }
     errors.push("Sign in to use Library")  ;
     res.redirect("/",{errors})
})
app.get("/advancedlib",(req,res)=>{
    if(req.user) {
        return  res.render("advancedlib")
       /* if(req.user.paid){
          return  res.render("advancedlib")}
        else{
            errors.push("User must have subscribed to use PrimeLibrary")  
            return  res.render("library.html",{errors})   
        }*/
     }
     errors.push("Sign in to use Library")  ;
     res.redirect("/",{errors})
})
app.listen(3000)