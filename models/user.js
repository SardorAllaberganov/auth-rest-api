const mongoose = require("mongoose");

const userSchema = mongoose.Schema({
	email: {
		type: "string",
		required: true,
	},
	name: {
		type: "string",
		required: true,
	},
	password: {
		type: "string",
		required: true,
	},
	role: {
		type: "string",
		default: "basic",
	},
	verified: {
		type: "boolean",
		default: false,
	},
	verificationToken: String,
	verificationTokenExpire: Date,
});

module.exports = mongoose.model("User", userSchema);
