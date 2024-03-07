const express = require("express");
const app = express();
require("dotenv").config();
const mongoose = require("mongoose");
const bodyParser = require("body-parser");

app.use(bodyParser.json());

//error handler
app.use((err, req, res, next) => {
	if (err) {
		// console.error(err.message);
		if (!err.statusCode) {
			err.statusCode = 500;
		} // Set 500 server code error if statuscode not set
		return res.status(err.statusCode).json({
			statusCode: err.statusCode,
			message: err.message,
		});
	}
	next();
});

app.use((req, res, next) => {
	res.setHeader("Access-Control-Allow-Origin", "*");
	res.setHeader(
		"Access-Control-Allow-Methods",
		"OPTIONS, GET, POST, PUT, PATCH, DELETE"
	);
	res.setHeader(
		"Access-Control-Allow-Headers",
		"Content-Type, Authorization"
	);
	next();
});

const authRoutes = require("./routes/auth");
const isAuth = require("./middleware/is-auth");

app.use("/auth", authRoutes);

app.post("/dashboard", isAuth, (req, res) => {
	if (req.user.user.role === "admin") {
		res.json({ message: "Welcome to dashboard" });
	} else {
		res.json({ message: "User not an Admin" });
	}
});

mongoose
	.connect(process.env.DB_CONNECTION_LINK)
	.then((result) => {
		app.listen(process.env.PORT);
		console.log(
			`Connected to Database\nRunning on Port: ${process.env.PORT}`
		);
	})
	.catch((error) => {
		res.status(500).json({ message: error.message });
	});
