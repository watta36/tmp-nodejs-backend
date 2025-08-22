import jwt from 'jsonwebtoken';

export function signAccessToken(payload, secret, minutes){
  return jwt.sign(payload, secret, { expiresIn: `${minutes}m` });
}
export function signRefreshToken(payload, secret, days){
  return jwt.sign(payload, secret, { expiresIn: `${days}d` });
}
export function verifyToken(token, secret){
  return jwt.verify(token, secret);
}
