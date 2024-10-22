const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const { check, validationResult } = require('express-validator');
require('dotenv').config(); 



const User = require('./models/user');
const userForm = require('./models/userForm');
const verifyToken = require('./auth/verifyToken');


const app = express();
const JWT_SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET;
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


app.use(express.json());
app.use(cors());


const uploadsDir = path.join(__dirname, 'uploads');

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadsDir); 
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });



mongoose.connect(process.env.MOONGO_URL)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

  app.post('/register',async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { username, password } = req.body;
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ msg: "User already exists" });
        }

        const role = (username === process.env.ADMIN_1) ? 'admin' : 'user';
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({ username, password: hashedPassword, role });
        await newUser.save();

        res.status(200).json({
            success: true,
            msg: "User registration successful"
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
}
);

app.post('/login', async (req, res) => {
try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user) {
        return res.status(400).json({ msg: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(400).json({ msg: "Invalid credentials" });
    }

    const token = jwt.sign({ userId: user.id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    const refreshToken = jwt.sign({ userId: user._id }, REFRESH_SECRET, { expiresIn: '7d' });

    res.status(200).json({
        success: true,
        token,
        refreshToken,
        data: {
            userId: user.id,
            username: user.username,
            role: user.role
        },
        msg: "Login successful"
    });
} catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
}
});


app.post('/refresh-token', (req, res) => {
const { refreshToken } = req.body;

if (!refreshToken) {
    return res.status(403).json({ msg: 'Refresh token not provided' });
}

jwt.verify(refreshToken, REFRESH_SECRET, (err, user) => {
    if (err) {
        return res.status(403).json({ msg: 'Invalid refresh token' });
    }

    const newAccessToken = jwt.sign(
        { userId: user.userId, role: user.role },
        JWT_SECRET,
        { expiresIn: '15m' }  
    );

    res.json({ accessToken: newAccessToken });
});
});


app.get('/get-user', verifyToken, async (req, res) => {
try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) {
        return res.status(404).json({ success: false, msg: 'User not found' });
    }
    res.status(200).json({
        success: true,
        data: {
            userId: user.id,
            username: user.username,
            role: user.role
        }
    });
} catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
}
});

app.post('/user-form',verifyToken,upload.array('images',999),async(req,res)=>{
    try {
        const { username, socialMedia } = req.body;
        const imageFilenames = req.files.map(file => file.filename);

        const newForm = new userForm({
            username,
            socialMedia,
            images: imageFilenames
        });
        await newForm.save();
        res.status(200).json({ message: 'User submitted successfully!' });
    } catch (error) {
        res.status(500).json({ message: 'Error submitting user data' });
    } 
});


app.get('/details', verifyToken, async (req, res) => {
    try {
        const forms = await userForm.find(); 
        res.status(200).json({ success: true, data: forms });
    } catch (error) {
        res.status(500).json({ message: 'Error fetching user data' });
    }
});

app.delete('/delete/:id', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        const deletedForm = await userForm.findByIdAndDelete(id);

        if (!deletedForm) {
            return res.status(404).json({ message: 'User form not found' });
        }

        res.status(200).json({ message: 'User form deleted successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error deleting user form' });
    }
});



app.listen(process.env.PORT, () => {
    console.log("Server is running on port");
});