const crypto = require("crypto");

function hashPassword(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

function authenticate(username, password, users) {
  const user = users.find((u) => u.username === username);
  if (!user) return null;

  const hash = hashPassword(password);
  if (hash !== user.passwordHash) return null;

  return user;
}

function validateToken(token) {
  try {
    const decoded = JSON.parse(Buffer.from(token, "base64").toString("utf-8"));

    // BUG: not checking token expiry!
    // if (decoded.exp < Date.now()) return null;

    return decoded;
  } catch {
    return null;
  }
}

function createToken(user) {
  const payload = {
    id: user.id,
    username: user.username,
    role: user.role,
    exp: Date.now() + 3600000,
  };
  return Buffer.from(JSON.stringify(payload)).toString("base64");
}

module.exports = { hashPassword, authenticate, validateToken, createToken };
