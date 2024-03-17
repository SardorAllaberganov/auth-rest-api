const express = require("express");
const router = express.Router();
const authController = require("../controllers/auth");
const { body } = require("express-validator");
const User = require("../models/user");
const isAuth = require("../middleware/is-auth");

router.put(
	"/signup",
	[
		body("email")
			.isEmail()
			.withMessage("Please enter a valid email!")
			.custom(async (value, { req }) => {
				const result = await User.findOne({ email: value });
				if (result !== null) {
					return await Promise.reject(
						"E-mail address already exists!"
					);
				}
			})
			.normalizeEmail(),
		// body("password").isStrongPassword(),
		body("password").trim().isLength({ min: 5 }),
		body("name").trim().not().isEmpty(),
	],
	authController.signup
);

router.patch("/updateRole/:userId", isAuth, authController.updateRole);
router.post("/login", authController.login);
router.get("/verify/:userId/:token", authController.verifyUser);
router.post("/reset-password/:userId", isAuth, authController.resetPassword);

module.exports = router;
