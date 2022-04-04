const asyncHandler = require('express-async-handler')

const Goal = require('../models/goalModel')
const User = require('../models/userModel')

// @desc    Get goals
// @route   GET /api/goals
// @assess  private
const getGoals = asyncHandler(async (req, res) => {
	const goals = await Goal.find({ user: req.user.id })
	res.status(200).json(goals)
})

// @desc    Set goals
// @route   POST /api/goals
// @assess  private
const setGoal = asyncHandler(async (req, res) => {
	if (!req.body.text) {
		res.status(400)
		throw new Error('Please add a text field')
	}

	const goal = await Goal.create({
		text: req.body.text,
		user: req.user.id,
	})

	res.status(200).json(goal)
})

// @desc    Update goal
// @route   PUT /api/goals/:id
// @assess  private
const updateGoal = asyncHandler(async (req, res) => {
	const goal = await Goal.findById(req.params.id)

	if (!goal) {
		res.status(400)
		throw new Error('Goal not found')
	}

	const user = await User.findById(req.user.id)

	// check for user
	if (!user) {
		res.status(401)
		throw new Error('User not found')
	}

	// make sure the logged in user matchers the goal user
	if (goal.user.toString() !== user.id) {
		res.status(401)
		throw new Error('User not authorized')
	}

	const updatedGoal = await Goal.findByIdAndUpdate(req.params.id, req.body, {
		new: true,
	})

	res.status(200).json(updatedGoal)
})

// @desc    Delete goals
// @route   DELETE /api/goals/:id
// @assess  private
const deleteGoal = asyncHandler(async (req, res) => {
	const goal = await Goal.findById(req.params.id)

	if (!goal) {
		res.status(400)
		throw new Error('Goal not found')
	}

	const user = await User.findById(req.user.id)

	// check for user
	if (!user) {
		res.status(401)
		throw new Error('User not found')
	}

	// make sure the logged in user matchers the goal user
	if (goal.user.toString() !== user.id) {
		res.status(401)
		throw new Error('User not authorized')
	}

	await goal.remove()

	res.status(200).json({ id: req.params.id })
})

module.exports = {
	getGoals,
	setGoal,
	updateGoal,
	deleteGoal,
}
