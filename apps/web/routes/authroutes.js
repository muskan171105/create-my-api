const express = require('express');
const { registerUser, loginUser, authenticateToken } = require('./lib/auth');

const router = express.Router();

// Register route
router.post('/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        const response = await registerUser(username, password);
        res.status(201).json(response);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Login route
router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const response = await loginUser(username, password);
        res.json(response);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Protected route example
router.get('/protected', authenticateToken, (req, res) => {
    res.json({ message: 'This is a protected route', user: req.user });
});

module.exports = router;
