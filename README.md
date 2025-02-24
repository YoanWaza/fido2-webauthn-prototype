# FIDO2/WebAuthn Authentication Project

This project implements a password-less authentication system using the FIDO2/WebAuthn standard. By leveraging modern web technologies and public-key cryptography, the system offers secure, phishing-resistant authentication.

## Prerequisites
Node.js (v12 or later)
npm
## Installation
Clone the repository, install the dependencies, and start the server:

```
git clone <repository-url>
cd <repository-directory>
npm install
npm start
```
By default, the server will run on port 3000. You can change this by setting the appropriate environment variable.

## Running Tests
To run the test suite, use:
```
npm test
```
This command executes all the tests defined in the project, ensuring that registration, authentication, and other functionalities work as expected.

## Usage
Once the server is running, navigate to the application URL in your web browser. Note: It is recommended to use Google Chrome for the best experience, as some users have reported issues with Safari.

## Project Structure
app.js: Main entry point of the backend application.
routes/: Contains API endpoints for authentication and registration.
controllers/: Implements logic for handling registration and authentication.
public/: Frontend assets and JavaScript files for interacting with the WebAuthn API.
