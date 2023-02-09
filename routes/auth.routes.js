const express = require('express')
const bcrypt = require('bcryptjs')
const User = require('../models/User.model')
const { isLoggedIn, isLoggedOut } = require('../middleware/route-guard')
const router = express.Router()

// Because of how we registered this router in app.js, we already have /auth in front of every routes

/* GET signup page */
router.get('/signup', isLoggedOut, (req, res) => {
  res.render('auth/signup', { user: undefined })
})

/* POST to receive data from the signup form */
router.post('/signup', isLoggedOut, async (req, res) => {
  const credentials = { ...req.body }

  const salt = bcrypt.genSaltSync(13)
  const passwordHash = bcrypt.hashSync(credentials.password, salt)

  delete credentials.password
  credentials.passwordHash = passwordHash

  try {
    await User.create(credentials)
    res.redirect('/auth/login')
  } catch (error) {
    console.log(error)
  }
})

/* GET login page */
router.get('/login', isLoggedOut, (req, res) => {
  res.render('auth/login', { user: undefined })
})

/* POST to receive data from the login form */
router.post('/login', isLoggedOut, async (req, res) => {
  try {
    const userMatch = await User.find({ username: req.body.username })
    if (userMatch.length) {
      // We have a user
      const currentUser = userMatch[0]
      if (bcrypt.compareSync(req.body.password, currentUser.passwordHash)) {
        // Correct password
        req.session.user = currentUser
        res.redirect('/auth/profile')
      } else {
        // Incorrect password
        // Render the login page with an error
        res.send('Incorrect password')
      }
    } else {
      // We don't have a user
      // Render the login page with an error
      res.send('User not found')
    }
  } catch (error) {
    console.log(error)
  }
})

// Get to display the profile page

router.get('/profile', isLoggedIn, (req, res) => {
  console.log(req.session)
  res.render('auth/profile', { user: req.session.user })
})

router.get('/logout', isLoggedIn, (req, res) => {
  req.session.destroy(err => {
    if (err) next(err)
    res.redirect('/')
  })
})

module.exports = router
