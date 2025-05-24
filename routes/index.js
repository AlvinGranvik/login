import express from "express"
import db from "../db-sqlite.js"
import bcrypt from "bcrypt"

const router = express.Router()

// Root route
router.get("/", (req, res) => {
  if (req.session.userId) {
    res.redirect("/loggedin")
  } else {
    res.redirect("/login")
  }
})

// Logout route
router.post("/", (req, res) => {
  req.session.username = undefined
  req.session.userId = undefined
  req.session.destroy()
  res.redirect("/")
})

// Login GET
router.get("/login", (req, res) => {
  const views = req.session.views || 0
  req.session.views = views + 1

  const msg = views > 0 ? "Either your username and/or password is incorrect, or maybe you just refreshed this page" : "Log into an existing account, or make a new one"
  res.render("login.njk", { title: "Log in", message: msg, views })
})

// Login POST
router.post("/login", async (req, res) => {
  const name = req.body.username;
  const password = req.body.password;
  const user = await db.get(`SELECT * FROM user WHERE name = ?`, [name])

  if (user) {
    const isValid = await bcrypt.compare(password, user.password)
    if (isValid) {
      req.session.userId = user.id
      req.session.username = user.name
      return res.redirect("/loggedin")
    }
  }

  req.session.views = (req.session.views || 0) + 1
  return res.redirect("/login")
})

// Account creation GET
router.get("/user/new", (req, res) => {
  const views = req.session.views || 0
  req.session.views = views + 1

  const msg = views > 0 ? "Username already exists" : "Register account"
  res.render("user.create.njk", { title: "User creation", message: msg, views })
})

// Account creation POST
router.post("/user/new", async (req, res) => {
  const { name, password } = req.body

  const existingUser = await db.get(`SELECT * FROM user WHERE name = ?`, [name])
  if (existingUser) {
    req.session.views = (req.session.views || 0) + 1
    return res.redirect("/user/new")
  }

  const hashedPassword = await bcrypt.hash(password, 10)
  await db.run(`INSERT INTO user (name, password) VALUES (?, ?)`, [name, hashedPassword])

  console.log(`ACCOUNT CREATED FOR ${name}`)
  res.redirect("/")
})

// Home route
router.get("/loggedin", async (req, res) => {
  if (req.session.userId) {
    res.render("index.njk", {
      title: "Home",
      username: req.session.username,
    })
  } else {
    console.log("NOT LOGGED IN!!!!")
    res.redirect("/")
  }
})

export default router



