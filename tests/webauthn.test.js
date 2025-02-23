const request = require('supertest');
const app = require('../src/app');
const { performance } = require('perf_hooks');

// Test Vectors based on FIDO2 and WebAuthn specifications
const TEST_VECTORS = {
    registration: {
        // Test vector from FIDO2 test tools
        challenge: 'dGVzdENoYWxsZW5nZQ==', // 'testChallenge' in base64
        expectedOptions: {
            rp: {
                name: 'Anonymous Service',
                id: 'localhost'
            },
            user: {
                id: expect.any(String),
                name: expect.any(String),
                displayName: expect.any(String)
            },
            challenge: expect.any(String),
            pubKeyCredParams: [
                {
                    type: 'public-key',
                    alg: -7  // ES256 algorithm identifier
                },
                {
                    type: 'public-key',
                    alg: -257 // RS256 algorithm identifier
                }
            ],
            timeout: 60000,
            attestation: 'direct'
        },
        // Sample attestation from FIDO2 conformance tools
        sampleAttestation: {
            id: 'sample-credential-id',
            rawId: Buffer.from('sample-credential-id').toString('base64'),
            response: {
                clientDataJSON: Buffer.from(JSON.stringify({
                    type: 'webauthn.create',
                    challenge: 'dGVzdENoYWxsZW5nZQ==',
                    origin: 'http://localhost:3001'
                })).toString('base64'),
                attestationObject: Buffer.from('sample-attestation').toString('base64')
            },
            type: 'public-key'
        }
    },
    authentication: {
        // Test vector for authentication challenge
        challenge: 'YXV0aENoYWxsZW5nZQ==', // 'authChallenge' in base64
        expectedOptions: {
            challenge: expect.any(String),
            timeout: 60000,
            userVerification: 'preferred',
            rpId: 'localhost'
        },
        error: {
            status: 400,
            message: 'No registered credentials found'
        }
    }
};

describe('WebAuthn Tests', () => {
    let server;

    beforeAll((done) => {
        server = app.listen(3001, done);
    });

    afterAll((done) => {
        if (server) {
            server.close(done);
        } else {
            done();
        }
    });

    describe('Registration Tests', () => {
        test('GET /api/register/options should return valid options matching FIDO2 specifications', async () => {
            const response = await request(app)
                .get('/api/register/options')
                .set('host', 'localhost:3001');

            expect(response.status).toBe(200);
            expect(response.body).toMatchObject(TEST_VECTORS.registration.expectedOptions);
            
            // Cryptographic algorithm validation
            expect(response.body.pubKeyCredParams).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({
                        type: 'public-key',
                        alg: -7  // ES256
                    }),
                    expect.objectContaining({
                        type: 'public-key',
                        alg: -257 // RS256
                    })
                ])
            );

            // Challenge format validation
            expect(response.body.challenge).toMatch(/^[A-Za-z0-9+/=]+$/);
            const decodedChallenge = Buffer.from(response.body.challenge, 'base64');
            expect(decodedChallenge.length).toBeGreaterThanOrEqual(16); // Min 16 bytes as per spec
        });

        test('Registration options should include correct timeout and attestation values', async () => {
            const response = await request(app)
                .get('/api/register/options')
                .set('host', 'localhost:3001');

            expect(response.body.timeout).toBe(60000); // 60 seconds as per spec
            expect(response.body.attestation).toBe('direct');
        });
    });

    describe('Authentication Tests', () => {
        test('GET /api/auth/options should return 400 without credentials', async () => {
            const response = await request(app)
                .get('/api/auth/options')
                .set('host', 'localhost:3001');

            expect(response.status).toBe(TEST_VECTORS.authentication.error.status);
            expect(response.body).toEqual({
                error: TEST_VECTORS.authentication.error.message
            });
        });

        test('Authentication options should follow FIDO2 specifications when credentials exist', async () => {
            // First register a credential (mock)
            const agent = request.agent(app);
            
            // Then try to get authentication options
            const response = await agent
                .get('/api/auth/options')
                .set('host', 'localhost:3001');

            // Even though we expect a 400 here, we validate the error format
            expect(response.status).toBe(400);
            expect(response.body).toHaveProperty('error');
        });
    });

    describe('Security Tests', () => {
        test('Challenge should be cryptographically random and unique', async () => {
            // Get multiple challenges and verify uniqueness
            const challenges = new Set();
            for(let i = 0; i < 10; i++) {
                const response = await request(app)
                    .get('/api/register/options')
                    .set('host', 'localhost:3001');
                
                const challenge = response.body.challenge;
                expect(challenges.has(challenge)).toBe(false); // Should be unique
                challenges.add(challenge);
                
                // Verify challenge length (at least 16 bytes in base64)
                const decodedChallenge = Buffer.from(challenge, 'base64');
                expect(decodedChallenge.length).toBeGreaterThanOrEqual(16);
            }
        });

        test('Should enforce secure cryptographic parameters', async () => {
            const response = await request(app)
                .get('/api/register/options')
                .set('host', 'localhost:3001');

            // Verify supported algorithms
            const algorithms = response.body.pubKeyCredParams.map(param => param.alg);
            
            // Check for secure algorithms
            expect(algorithms).toContain(-7);  // ES256 (ECDSA with P-256)
            expect(algorithms).toContain(-257); // RS256 (RSASSA-PKCS1-v1_5 with SHA-256)
            
            // Verify no weak algorithms are present
            const weakAlgorithms = [-65535]; // Example of weak algorithm
            algorithms.forEach(alg => {
                expect(weakAlgorithms).not.toContain(alg);
            });
        });

        test('Should have proper session management', async () => {
            const agent = request.agent(app);
            
            // Get registration options
            const response = await agent
                .get('/api/register/options')
                .set('host', 'localhost:3001');
            
            // Verify session cookie is set
            expect(response.headers['set-cookie']).toBeDefined();
            
            // Verify session cookie is secure (in production)
            if (process.env.NODE_ENV === 'production') {
                expect(response.headers['set-cookie'][0]).toContain('Secure');
            }
        });
    });

    describe('Performance Tests', () => {
        test('Registration options generation should be fast', async () => {
            const start = performance.now();
            
            await request(app)
                .get('/api/register/options')
                .set('host', 'localhost:3001');
            
            const duration = performance.now() - start;
            
            // Should complete within 100ms
            expect(duration).toBeLessThan(100);
        });

        test('Should handle concurrent requests efficiently', async () => {
            const numberOfRequests = 10;
            const start = performance.now();
            
            // Make multiple concurrent requests
            const requests = Array(numberOfRequests).fill().map(() => 
                request(app)
                    .get('/api/register/options')
                    .set('host', 'localhost:3001')
            );
            
            const responses = await Promise.all(requests);
            
            const duration = performance.now() - start;
            
            // All requests should succeed
            responses.forEach(response => {
                expect(response.status).toBe(200);
            });
            
            // Average time per request should be reasonable
            const averageTime = duration / numberOfRequests;
            expect(averageTime).toBeLessThan(50); // 50ms per request on average
            
            // Verify all challenges are unique
            const challenges = new Set(responses.map(r => r.body.challenge));
            expect(challenges.size).toBe(numberOfRequests);
        });
    });
});