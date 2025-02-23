const request = require('supertest');
const app = require('../src/app');

// Test Vectors based on WebAuthn specifications
const TEST_VECTORS = {
    registration: {
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
            pubKeyCredParams: expect.any(Array),
            timeout: expect.any(Number),
            attestation: expect.any(String)
        }
    },
    authentication: {
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
        test('GET /api/register/options should return valid options', async () => {
            const response = await request(app)
                .get('/api/register/options')
                .set('host', 'localhost:3001');

            expect(response.status).toBe(200);
            expect(response.body).toMatchObject(TEST_VECTORS.registration.expectedOptions);
            
            // Specific validations
            expect(response.body.challenge).toMatch(/^[A-Za-z0-9+/=]+$/); // Valid base64
            expect(response.body.pubKeyCredParams).toContainEqual(
                expect.objectContaining({
                    type: 'public-key',
                    alg: expect.any(Number)
                })
            );
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
    });
});