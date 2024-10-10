const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// Replace this with your actual user data storage (like a database)
const users = [];

// Secret key for JWT
const JWT_SECRET = 'your_jwt_secret'; // Change this to a strong secret in production

// Function to register a new user
const registerUser = async (username, password) => {
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });
    return { message: 'User registered successfully' };
};

// Function to login a user
const loginUser = async (username, password) => {
    const user = users.find(user => user.username === username);
    if (!user) {
        throw new Error('User not found');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        throw new Error('Invalid password');
    }

    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
    return { token };
};

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) {
        return res.sendStatus(401);
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
};

module.exports = {
    registerUser,
    loginUser,
    authenticateToken,
};
