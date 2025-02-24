document.addEventListener('DOMContentLoaded', () => {
    const registerButton = document.getElementById('registerButton');
    const authenticateButton = document.getElementById('authenticateButton');
    const statusDisplay = document.getElementById('status');

    function showStatus(message, isError = false) {
        statusDisplay.textContent = message;
        statusDisplay.style.display = 'block';
        statusDisplay.className = 'status-message ' + (isError ? 'error' : 'success');
    }

    function hideStatus() {
        statusDisplay.style.display = 'none';
    }

    if (!window.PublicKeyCredential) {
        console.error('WebAuthn is not supported by this browser');
        showStatus('WebAuthn is not supported by this browser', true);
        registerButton.disabled = true;
        authenticateButton.disabled = true;
    }

    console.log('Scripts loaded');
    console.log('Register button:', registerButton);
    console.log('Authenticate button:', authenticateButton);

    // Debug event handlers
    registerButton.onclick = () => {
        console.log('Register button clicked');
        showStatus('Registration attempt...');
    };

    authenticateButton.onclick = () => {
        console.log('Authenticate button clicked');
        showStatus('Authentication attempt...');
    };

    function bufferToBase64(buffer) {
        return btoa(String.fromCharCode(...new Uint8Array(buffer)));
    }

    function base64ToBuffer(base64) {
        const binary = window.atob(base64);
        const buffer = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            buffer[i] = binary.charCodeAt(i);
        }
        return buffer.buffer;
    }

    registerButton.addEventListener('click', async () => {
        try {
            hideStatus();
            
            const optionsResponse = await fetch('/api/register/options');
            const options = await optionsResponse.json();

            if (options.error) {
                throw new Error(options.error);
            }

            options.challenge = base64ToBuffer(options.challenge);
            options.user.id = base64ToBuffer(options.user.id);

            const credential = await navigator.credentials.create({
                publicKey: options
            });

            const registrationData = {
                id: credential.id,
                rawId: bufferToBase64(credential.rawId),
                response: {
                    clientDataJSON: bufferToBase64(credential.response.clientDataJSON),
                    attestationObject: bufferToBase64(credential.response.attestationObject)
                },
                type: credential.type
            };

            const registerResponse = await fetch('/api/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(registrationData)
            });

            const registerResult = await registerResponse.json();

            if (registerResult.error) {
                throw new Error(registerResult.error);
            }

            showStatus('Registration successful!');
        } catch (error) {
            console.error('Registration error:', error);
            showStatus(error.message || 'Registration failed', true);
        }
    });

    authenticateButton.addEventListener('click', async () => {
        try {
            hideStatus();

            const optionsResponse = await fetch('/api/auth/options');
            const options = await optionsResponse.json();

            if (options.error) {
                throw new Error(options.error);
            }

            options.challenge = base64ToBuffer(options.challenge);
            if (options.allowCredentials) {
                options.allowCredentials = options.allowCredentials.map(credential => ({
                    ...credential,
                    id: base64ToBuffer(credential.id)
                }));
            }

            const assertion = await navigator.credentials.get({
                publicKey: options
            });

            const authData = {
                id: assertion.id,
                rawId: bufferToBase64(assertion.rawId),
                response: {
                    clientDataJSON: bufferToBase64(assertion.response.clientDataJSON),
                    authenticatorData: bufferToBase64(assertion.response.authenticatorData),
                    signature: bufferToBase64(assertion.response.signature),
                    userHandle: assertion.response.userHandle ? bufferToBase64(assertion.response.userHandle) : null
                },
                type: assertion.type
            };

            const verifyResponse = await fetch('/api/auth/verify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(authData)
            });

            const verifyResult = await verifyResponse.json();

            if (verifyResult.error) {
                throw new Error(verifyResult.error);
            }

            showStatus('Authentication successful!');
        } catch (error) {
            console.error('Authentication error:', error);
            showStatus(error.message || 'Authentication failed', true);
        }
    });
});

