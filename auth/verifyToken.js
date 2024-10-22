const jwt = require('jsonwebtoken');
require('dotenv').config();

const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    console.log('Authorization Header:', authHeader);
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ msg: 'Access Denied: No Token Provided!' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.log('Invalid Token:', err);
            return res.status(403).json({ msg: 'Invalid Token!' });
        }
        req.user = user;
        next();
    });
};


module.exports = verifyToken;

