document.getElementById('register-btn').addEventListener('click', async () => {
    try {
        // Fetch registration options from the backend
        const response = await fetch('/api/register/options');
        const options = await response.json();

        // Log the options for debugging
        console.log("Registration Options:", options);

        // Validate required fields
        if (!options.challenge || !options.user || !options.user.id) {
            throw new Error("Invalid options received from the server");
        }

        // Convert challenge and user ID to ArrayBuffers
        options.challenge = Uint8Array.from(atob(options.challenge), c => c.charCodeAt(0)).buffer;
        options.user.id = Uint8Array.from(atob(options.user.id), c => c.charCodeAt(0)).buffer;

        // Call WebAuthn API to create credentials
        const credential = await navigator.credentials.create({ publicKey: options });

        // Log the credential to verify `rawId` and `id`
        console.log("Generated Credential:", credential);

        // Send credential to the server
        const credentialResponse = {
            id: credential.id,
            rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
            response: {
                clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                attestationObject: btoa(String.fromCharCode(...new Uint8Array(credential.response.attestationObject))),
            },
            type: credential.type,
        };

        // Log the prepared data for debugging
        console.log("Prepared Credential Response:", credentialResponse);


        const result = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(credentialResponse),
        });

        console.log(await result.json());
    } catch (error) {
        console.error("Registration failed", error);
    }
});


document.getElementById('login-btn').addEventListener('click', async () => {
    try {
        // Fetch authentication options from the server
        const response = await fetch('/api/auth/options');
        const options = await response.json();

        // Log the options for debugging
        console.log("Authentication Options from Server:", options);

        // // Decode Base64-encoded fields into ArrayBuffer
        // options.challenge = Uint8Array.from(atob(options.challenge), c => c.charCodeAt(0)).buffer;
        // options.allowCredentials.forEach((cred) => {
        //     cred.id = Uint8Array.from(atob(cred.id), c => c.charCodeAt(0)).buffer;
        // });
        // Decode Base64-encoded fields into ArrayBuffer
        try {
            options.challenge = Uint8Array.from(atob(options.challenge), c => c.charCodeAt(0)).buffer;
            options.allowCredentials.forEach((cred) => {
                cred.id = Uint8Array.from(atob(cred.id), c => c.charCodeAt(0)).buffer;
            });
        } catch (error) {
            console.error("Base64 decoding failed", error);
            throw new Error("Failed to decode Base64 fields from authentication options.");
        }

        // Call WebAuthn API to request assertion
        const assertion = await navigator.credentials.get({ publicKey: options });

        // Prepare assertion data to send to the server
        const assertionResponse = {
            id: assertion.id,
            rawId: btoa(String.fromCharCode(...new Uint8Array(assertion.rawId))),
            response: {
                clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(assertion.response.clientDataJSON))),
                authenticatorData: btoa(String.fromCharCode(...new Uint8Array(assertion.response.authenticatorData))),
                signature: btoa(String.fromCharCode(...new Uint8Array(assertion.response.signature))),
            },
            type: assertion.type,
        };

        // Send assertion to the server for verification
        const verifyResponse = await fetch('/api/auth/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(assertionResponse),
        });

        const result = await verifyResponse.json();
        if (result.success) {
            alert("Login successful!");
        } else {
            alert("Login failed.");
        }
    } catch (error) {
        console.error("Authentication failed", error);
    }
});

