const express = require('express');
const { generateRegistrationOptions, registerCredential } = require('../controllers/registrationController');
const { generateAuthenticationOptions, verifyAuthentication  } = require('../controllers/authenticationController');

// const { registerCredential } = require('../controllers/registrationController');

const router = express.Router();

router.get('/health', (req, res) => {
    res.send({ status: 'Server is healthy' });
});

router.get('/register/options', generateRegistrationOptions);
router.get('/auth/options', generateAuthenticationOptions);
router.post('/auth/verify', verifyAuthentication);
router.post('/register', registerCredential);


module.exports = router;
