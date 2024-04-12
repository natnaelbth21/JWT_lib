const crypto = require('crypto');

// JWT secret key
const secret = 'your_secret_key';

// Function to base64url encode a string
function base64urlEncode(str) {
  return Buffer.from(str).toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// Function to base64url decode a string
function base64urlDecode(str) {
  return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString();
}

// Function to create a JWT token
function createJWT(payload) {
  const header = {
    alg: 'HS256',
    typ: 'JWT'
  };

  const encodedHeader = base64urlEncode(JSON.stringify(header));
  const encodedPayload = base64urlEncode(JSON.stringify(payload));

  const signature = crypto.createHmac('sha256', secret)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest('base64');

  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

// Function to verify a JWT token
function verifyJWT(token) {
  const [encodedHeader, encodedPayload, signature] = token.split('.');

  const header = JSON.parse(base64urlDecode(encodedHeader));
  const payload = JSON.parse(base64urlDecode(encodedPayload));

  const expectedSignature = crypto.createHmac('sha256', secret)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest('base64');

  return signature === expectedSignature ? payload : null;
}

// Example usage
const payload = { username: 'example_user', role: 'admin' };

// Create a JWT token
const token = createJWT(payload);
console.log('JWT Token:', token);

// Verify the JWT token
const verifiedPayload = verifyJWT(token);
console.log('Verified Payload:', verifiedPayload);
