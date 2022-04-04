const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const asyncHandler = require('express-async-handler')
const User = require('../models/userModel')

// @desc    register user
// @route   POST /api/users
// @assess  public
const registerUser = asyncHandler(async (req, res) => {
	const { name, email, password } = req.body

	if (!name || !email || !password) {
		res.status(400)
		throw new Error('Please add all fields')
	}

	// check if user exists
	const userExists = await User.findOne({ email })

	if (userExists) {
		res.status(400)
		throw new Error('User already exists')
	}

	// hash the password
	const salt = await bcrypt.getSalt(10)
	const hashedPassword = await bcrypt.hash(password, salt)

	// create user
	const user = await User.create({
		name,
		email,
		hashedPassword,
	})

	if (user) {
		res.status(201).json({
			_id: user.id,
			name: user.name,
			email: user.email,
		})
	} else {
		res.status(400)
		throw new Error('Invalid user data')
	}
})

// @desc    authenticate user
// @route   POST /api/users/login
// @assess  public
const loginUser = asyncHandler(async (req, res) => {
	res.json({ message: 'Login user' })
})

// @desc    Get user data
// @route   DELETE /api/users/me
// @assess  public
const getMe = asyncHandler(async (req, res) => {
	res.json({ message: 'User data display' })
})

module.exports = {
	registerUser,
	loginUser,
	getMe,
}
