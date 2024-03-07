const jwt = require("jsonwebtoken");
require("dotenv").config();

module.exports = (req, res, next) => {
	const token = req.headers["authorization"].split(" ")[1];
	if (!token) {
		return res
			.status(401)
			.json({ message: "Access Denied. No token provided." });
	}
	try {
		const decodedToken = jwt.verify(token, process.env.SECRET_KEY);
		req.user = decodedToken;
		if (!decodedToken) {
			return res.status(401).json({ message: "Not authorized." });
		}
		next();
	} catch (error) {
		return res.status(400).json({ message: "Invalid token." });
	}
};
