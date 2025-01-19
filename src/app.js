const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session'); // Import express-session
const dotenv = require('dotenv');

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

// Configure session middleware
app.use(session({
    secret: 'your-secret-key', // Replace with a secure, randomly generated secret
    resave: false,             // Avoid resaving session if it hasn't been modified
    saveUninitialized: true,   // Save uninitialized sessions (set to false for stricter handling)
    cookie: { secure: false }  // Use true if your app runs over HTTPS
}));

app.use(bodyParser.json());
app.use(express.static('public'));

app.use('/api', require('./routes'));


app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
