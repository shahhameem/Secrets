import express from 'express';
import ejs from 'ejs';
import mongoose from 'mongoose';
import session from 'express-session';
import bcrypt from 'bcrypt';

const saltRounds = 12;

const app = express();


// Middleware
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: "secret-key",
    resave: true,
    saveUninitialized: true,
}))

// Session middleware
const authCheck = (req, res, next) => {
    if (!req.session.user) {
        return res.redirect('/login')
    }
    next()
}

// MongoDB Connection
mongoose.set('strictQuery', false);

mongoose
    .connect('mongodb://127.0.0.1:27017/userDB')
    .then(() => console.log('MongoDB Connected'))
    .catch((err) => console.log(err));

// Schemas
const userSchema = new mongoose.Schema({
    email: String,
    password: String
});

const secretSchema = new mongoose.Schema({
    secret: String
});

// Models
const User = mongoose.model('User', userSchema);
const Secret = mongoose.model('Secret', secretSchema);

// Routes
app.get('/', (req, res) => {
    if (req.session.user)
        return res.redirect('/secrets')
    res.render('home');
});

app.get('/login', (req, res) => {
    if (req.session.user)
        return res.redirect('/secrets')
    res.render('login');
});

app.get('/register', (req, res) => {
    if (req.session.user)
        return res.redirect('/secrets')
    res.render('register');
});

// Show submit page + secrets
app.get('/submit', authCheck, async (req, res) => {
    res.render('submit')
});

// Save secret
app.post('/submit', authCheck, async (req, res) => {
    try {
        const newSecret = new Secret({
            secret: req.body.secret
        });
        await newSecret.save();

        res.redirect('/secrets');
    } catch (err) {
        console.log(err);
        res.status(500).send('Error saving secret');
    }
});

// Register user
app.post('/register', async (req, res) => {
    if (req.session.user)
        return res.redirect('/secrets')
    try {
        const hashedPassword = await bcrypt.hash(
            req.body.password,
            saltRounds
        );

        const newUser = new User({
            email: req.body.username,
            password: hashedPassword
        });

        await newUser.save();
        req.session.user = newUser
        res.redirect('secrets');
    } catch (err) {
        console.log(err);
        res.status(500).send('Registration failed');
    }
});

// Login user
app.post('/login', async (req, res) => {
    if (req.session.user)
        return res.redirect('/secrets')
    try {
        const user = await User.findOne({
            email: req.body.username
        });

        if (!user) {
            return res.send('User not found');
        }

        const result = await bcrypt.compare(
            req.body.password,
            user.password
        );

        if (result) {
            req.session.user = user
            res.redirect('secrets');
        } else {
            res.send("Username and Password don't match.");
        }
    } catch (err) {
        console.log(err);
        res.status(500).send('Login failed');
    }
});

app.get('/secrets', authCheck, async (req, res) => {
    try {
        const secrets = await Secret.find({});
        res.render('secrets', { secrets });
    } catch (err) {
        res.status(500).err(err)
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) res.send(err)
    })
    res.render('login')
})

// Start server
app.listen(3000, () => {
    console.log('Server started at http://localhost:3000');
});
