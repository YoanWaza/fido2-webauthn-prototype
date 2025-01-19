// const { Fido2Lib } = require('fido2-lib');
// const fido2 = new Fido2Lib();

// // Generate authentication options
// const generateAuthenticationOptions = async (req, res) => {
//     try {
//         // Fetch the stored credential ID and user information
//         const credentialId = "stored-credential-id"; // Retrieve from your database
//         const user = {
//             id: "user1234", // Replace with the user ID from your database
//             name: "testuser@example.com",
//         };

//         // Generate options for WebAuthn assertion
//         const authOptions = await fido2.assertionOptions({
//             timeout: 60000,
//             rpId: "localhost", // Replace with your domain
//             challenge: Buffer.from(fido2.randomChallenge(), 'base64').toString('base64'),
//             allowCredentials: [
//                 {
//                     id: Buffer.from(credentialId, 'base64'), // Base64-decoded credential ID
//                     type: "public-key",
//                     transports: ["usb", "ble", "nfc", "internal"], // Authenticator transports
//                 },
//             ],
//             userVerification: "preferred",
//         });

//         // Base64-encode the challenge for transport
//         authOptions.challenge = Buffer.from(authOptions.challenge).toString("base64");

//         // Store the challenge temporarily
//         req.session = req.session || {};
//         req.session.challenge = authOptions.challenge;

//         res.json(authOptions);
//     } catch (error) {
//         console.error("Error generating authentication options:", error); // Log the error
//         res.status(500).json({ error: "Failed to generate authentication options" });
//     }
// };


// const verifyAuthentication = async (req, res) => {
//     try {
//         const { id, rawId, response, type } = req.body;

//         // Verify the response
//         const assertionResult = await fido2.assertionResult(
//             {
//                 id,
//                 rawId: Buffer.from(rawId, "base64"),
//                 response: {
//                     clientDataJSON: Buffer.from(response.clientDataJSON, "base64"),
//                     authenticatorData: Buffer.from(response.authenticatorData, "base64"),
//                     signature: Buffer.from(response.signature, "base64"),
//                 },
//                 type,
//             },
//             {
//                 challenge: req.session.challenge, // Fetch stored challenge
//                 origin: "http://localhost:3000", // Replace with your domain
//                 factor: "either",
//             }
//         );

//         // Example: Use assertionResult to verify the user
//         console.log("Authentication Successful:", assertionResult);
//         res.json({ success: true });
//     } catch (error) {
//         console.error("Authentication Failed:", error);
//         res.status(400).json({ error: "Authentication failed" });
//     }
// };

// module.exports = { generateAuthenticationOptions, verifyAuthentication };

const { Fido2Lib } = require("fido2-lib");

// Initialize Fido2Lib with default options (same as in registrationController.js)
const f2l = new Fido2Lib({
    timeout: 60000,
    rpId: "localhost", // Replace with your Relying Party ID
    rpName: "Anonymous Service", // Replace with your service name
    rpIcon: "https://example.com/logo.png", // Optional
    challengeSize: 128,
    cryptoParams: [-7, -257],
    authenticatorUserVerification: "preferred",
});

const generateAuthenticationOptions = async (req, res) => {
    try {
        // Retrieve the stored credential ID (example assumes one credential per user)
        const storedCredential = req.session.credentials; // Session-based storage
        if (!storedCredential) {
            return res.status(400).json({ error: "No registered credentials found" });
        }

        const credentialId = Object.keys(storedCredential)[0]; // Assuming one credential per user

        // Generate authentication options
        const authenticationOptions = await f2l.assertionOptions();
        authenticationOptions.challenge = Buffer.from(authenticationOptions.challenge).toString("base64");
        authenticationOptions.allowCredentials = [
            {
                id: Buffer.from(credentialId, "base64").toString("base64"), // Credential ID from storage
                type: "public-key",
            },
        ];

        // Store the challenge temporarily (session or memory)
        req.session = req.session || {};
        req.session.challenge = {
            value: authenticationOptions.challenge,
            expiresAt: Date.now() + 60000, // 1-minute validity
        };

        console.log("Generated Authentication Options:", authenticationOptions);

        // Send authentication options to the client
        res.json(authenticationOptions);
    } catch (error) {
        console.error("Error generating authentication options:", error);
        res.status(500).json({ error: "Failed to generate authentication options" });
    }
};

const verifyAuthentication = async (req, res) => {
    console.log("Received authentication response:", req.body);

    const { id, rawId, response, type } = req.body;

    try {
        // Check if the challenge exists and is valid
        if (!req.session.challenge || Date.now() > req.session.challenge.expiresAt) {
            return res.status(400).json({ error: "Challenge is missing or has expired" });
        }

        // Retrieve stored credential
        const storedCredential = req.session.credentials[id];
        if (!storedCredential) {
            return res.status(400).json({ error: "Credential not found" });
        }

        // Define assertion expectations
        const assertionExpectations = {
            challenge: req.session.challenge.value, // Challenge stored in the session
            origin: "http://localhost:3000",        // Your application origin
            factor: "either",                       // Authentication factor
            publicKey: storedCredential.publicKey,  // Public key for signature verification
            prevCounter: storedCredential.signCount, // Use stored signCount as prevCounter
            userHandle: storedCredential.userHandle,
        };

        console.log("Assertion Expectations:", assertionExpectations);

        // Verify the client assertion response
        const authnResult = await f2l.assertionResult(
            {
                id: req.body.id,
                rawId: new Uint8Array(Buffer.from(req.body.rawId, "base64")).buffer,
                response: {
                    clientDataJSON: new Uint8Array(Buffer.from(req.body.response.clientDataJSON, "base64")).buffer,
                    authenticatorData: new Uint8Array(Buffer.from(req.body.response.authenticatorData, "base64")).buffer,
                    signature: new Uint8Array(Buffer.from(req.body.response.signature, "base64")).buffer,
                },
                type: req.body.type,
            },
            assertionExpectations
        );

        console.log("Authentication result:", authnResult);

        // Update the stored signCount with the new counter
        const newSignCount = authnResult.authnrData.get("signCount");
        console.log(`Updated Sign Count: ${newSignCount}`);
        storedCredential.signCount = newSignCount;

        // Clear the challenge after successful verification
        delete req.session.challenge;

        res.json({ success: true });
    } catch (error) {
        console.error("Error during authentication verification:", error);
        res.status(500).json({ error: "Failed to verify authentication" });
    }
};

module.exports = {
    generateAuthenticationOptions,
    verifyAuthentication,
};
