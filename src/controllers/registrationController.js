const { Fido2Lib } = require("fido2-lib");

// Initialize Fido2Lib with default options
const f2l = new Fido2Lib({
    timeout: 60000,
    rpId: "localhost", // Replace with your Relying Party ID
    rpName: "Anonymous Service", // Replace with your service name
    rpIcon: "https://example.com/logo.png", // Optional
    challengeSize: 128,
    attestation: "direct",
    cryptoParams: [-7, -257],
    authenticatorAttachment: "cross-platform",
    authenticatorRequireResidentKey: false,
    authenticatorUserVerification: "preferred"
});

// Generate registration options (attestation)
const generateRegistrationOptions = async (req, res) => {
    try {
        const registrationOptions = await f2l.attestationOptions();

        // Add user information
        registrationOptions.user = {
            id: Buffer.from("user1234").toString("base64"), // Replace with unique user ID
            name: "testuser@example.com",                  // User's email or username
            displayName: "Test User"                       // User's display name
        };

        registrationOptions.challenge = Buffer.from(registrationOptions.challenge).toString("base64");


        // Store the challenge in the session
        req.session = req.session || {};
        req.session.challenge = {
            value: registrationOptions.challenge,
            expiresAt: Date.now() + 60000 // 1-minute validity
        };
        req.session.userHandle = registrationOptions.user.id;

        console.log("Generated Registration Options:", registrationOptions);

        // Send registration options to the client
        res.json(registrationOptions);
    } catch (error) {
        console.error("Error generating registration options:", error);
        res.status(500).json({ error: "Failed to generate registration options" });
    }
};

// Verify client attestation response
const registerCredential = async (req, res) => {
    
    console.log("Received attestation response:", req.body);

    const { id, rawId, response, type } = req.body;

    console.log("Received attestationObject:", response.attestationObject);


    try {
        // Check if the challenge exists and is valid
        if (!req.session.challenge || Date.now() > req.session.challenge.expiresAt) {
            return res.status(400).json({ error: "Challenge is missing or has expired" });
        }

        // Define attestation expectations
        const attestationExpectations = {
            challenge: req.session.challenge.value, // Challenge stored in the session
            origin: "http://localhost:3000",        // Your application origin
            factor: "either"                        // Authentication factor
        };

        console.log("Challenge from session:", req.session.challenge);
        console.log("Attestation Expectations:", attestationExpectations);
        // console.log("Received rawId:", req.body.rawId);
        // console.log("Received id:", req.body.id);
        // console.log("Decoded rawId (ArrayBuffer):", Buffer.from(req.body.rawId, 'base64'));


        // Verify the client attestation response
        const regResult = await f2l.attestationResult(
            {
                id: req.body.id,
                rawId: new Uint8Array(Buffer.from(req.body.rawId, "base64")).buffer,
                response: {
                    clientDataJSON: new Uint8Array(Buffer.from(req.body.response.clientDataJSON, "base64")).buffer,
                    attestationObject: new Uint8Array(Buffer.from(req.body.response.attestationObject, "base64")).buffer,
                },
                type: req.body.type,
            },
            attestationExpectations
        );

        console.log("Authnr Data:", regResult.authnrData);

        // Extract and store credential information
        const publicKey = regResult.authnrData.get("credentialPublicKeyPem");
        const signCount = regResult.authnrData.get("counter") || 0; // Use counter as signCount
        const credentialId = id;
        const userHandle = req.session.userHandle; // Retrieve the userHandle

        console.log(`Storing Credential: ${credentialId} with Sign Count: ${signCount}`);

        // Store credential in the session
        req.session.credentials = req.session.credentials || {};
        // req.session.credentials[credentialId] = { publicKey, signCount };
        req.session.credentials[credentialId] = { publicKey, signCount, userHandle };

        // Clear the challenge after successful verification
        delete req.session.challenge;

        res.json({ success: true, credentialId, publicKey });
    } catch (error) {
        console.error("Error during credential registration:", error);
        res.status(500).json({ error: "Failed to register credential" });
    }
};

module.exports = { generateRegistrationOptions, registerCredential };
