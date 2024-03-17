const User = require("../models/user");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const { validationResult } = require("express-validator");
const crypto = require("crypto");

exports.signup = (req, res, next) => {
	const errors = validationResult(req);
	if (!errors.isEmpty()) {
		return res
			.status(422)
			.json({ message: "This user is already signed up" });
	}

	const email = req.body.email;
	const password = req.body.password;
	const name = req.body.name;
	const role = req.body.role;
	const token = crypto.randomBytes(32).toString("hex");
	const tokenExpire = Date.now() + 3600000;
	// const tokenExpire = Date.now() + 5000;

	bcrypt
		.hash(password, 12)
		.then((hashedPassword) => {
			const user = new User({
				email: email,
				password: hashedPassword,
				name: name,
				role: role,
				verificationToken: token,
				verificationTokenExpire: tokenExpire,
			});
			return user.save();
		})
		.then((result) => {
			res.status(201).json({
				message: "User created successfully",
				userId: result._id.toString(),
				verifyLink: `http://localhost:3000/auth/verify/${result._id.toString()}/${token}`,
			});
		})
		.catch((error) => {
			next(error);
		});
};

exports.login = (req, res, next) => {
	const email = req.body.email;
	const password = req.body.password;
	let loadedUser;
	let dateNow = new Date();

	User.findOne({ email: email })
		.then((user) => {
			if (!user) {
				const error = new Error(
					"User with this email could not found."
				);
				error.statusCode = 404;
				throw error;
			}
			if (!user.verified && user.verificationTokenExpire < dateNow) {
				const verificationToken = crypto
					.randomBytes(32)
					.toString("hex");
				const verificationTokenExpire = Date.now() + 3600000;

				user.verificationToken = verificationToken;
				user.verificationTokenExpire = verificationTokenExpire;
				user.save();

				const data = {
					userId: user._id.toString(),
					verifyLink: `http://localhost:3000/auth/verify/${user._id.toString()}/${verificationToken}`,
				};
				const error = new Error("Verification link has expired");
				error.statusCode = 401;
				error.data = data;
				throw error;
			}
			if (!user.verified && user.verificationTokenExpire > dateNow) {
				const error = new Error(
					"User not verified, please check your email"
				);
				error.statusCode = 401;
				throw error;
			}
			loadedUser = user;
			return bcrypt.compare(password, loadedUser.password);
		})
		.then((isEqual) => {
			if (!isEqual) {
				const error = new Error("Wrong password");
				error.statusCode = 401;
				throw error;
			}
			const token = jwt.sign(
				{
					user: {
						id: loadedUser._id.toString(),
						name: loadedUser.name,
						email: loadedUser.email,
						role: loadedUser.role,
					},
				},
				process.env.SECRET_KEY,
				{
					expiresIn: "1d",
				}
			);
			return res.status(200).json({
				user: {
					id: loadedUser._id.toString(),
					name: loadedUser.name,
					email: loadedUser.email,
					role: loadedUser.role,
				},
				token,
			});
		})
		.catch((error) => {
			return res
				.status(error.statusCode || 500)
				.json({ message: error.message, data: error.data });
			// next(error);
		});
};

exports.updateRole = (req, res, next) => {
	const userId = req.params.userId;
	const role = req.body.role;
	User.findById(userId)
		.then((user) => {
			if (!user) {
				const error = new Error("User not found");
				error.statusCode = 404;
				throw error;
			}
			user.role = role;
			return user.save();
		})
		.then((result) => {
			res.status(200).json({ message: "User role updated successfully" });
		})
		.catch((error) => {
			next(error);
		});
};

exports.verifyUser = (req, res, next) => {
	const userId = req.params.userId;
	const token = req.params.token;
	User.findById(userId)
		.then((user) => {
			if (!user) {
				const error = new Error("User not found");
				error.statusCode = 404;
				throw error;
			}
			let dateNow = new Date();
			if (user.verificationTokenExpire < dateNow) {
				const error = new Error(
					"Verification token expired. Please login to system and we will send you another verification link."
				);
				error.statusCode = 403;
				throw error;
			}
			user.verified = true;
			return user.save();
		})
		.then((result) => {
			res.status(200).json({ message: "Email verified" });
		})
		.catch((error) => {
			next(error);
		});
};

exports.resetPassword = (req, res, next) => {
	const currentPassword = req.body.currentPassword;
	const newPassword = req.body.newPassword;
	const confirmNewPassword = req.body.confirmNewPassword;
	const userId = req.params.userId;
	let loadedUser;
	User.findById(userId)
		.then((user) => {
			if (!user) {
				return res.status(404).json({
					message: "User not found",
				});
			}
			loadedUser = user;
			return bcrypt.compare(currentPassword, user.password);
		})
		.then((isEqual) => {
			if (!isEqual) {
				return res.status(401).json({
					message: "Wrong password",
				});
			}
			if (newPassword !== confirmNewPassword) {
				return res.status(401).json({
					message: "New password and confirm password do not match",
				});
			}
			return bcrypt.hash(newPassword, 12).then((hashedPassword) => {
				loadedUser.password = hashedPassword;
				return loadedUser.save();
			});
		})
		.then((result) => {
			return res
				.status(200)
				.json({ message: "Password successfully updated" });
		})
		.catch((error) => {
			next(error);
		});
};
