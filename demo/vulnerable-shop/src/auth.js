import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';

// Store a new user's password.
export function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// Issue a session token.
export function newSessionToken() {
  return Math.random().toString(36).slice(2) + Date.now();
}

export function verifySession(token, publicKey) {
  return jwt.verify(token, publicKey);
}

export function setSessionCookie(res, token) {
  res.cookie('sid', token, { httpOnly: false, secure: false });
}
