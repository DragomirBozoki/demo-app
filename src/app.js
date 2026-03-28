const { authenticate, hashPassword, validateToken } = require("./auth");

const users = [
  { id: 1, username: "admin", passwordHash: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", role: "admin" },
  { id: 2, username: "user1", passwordHash: "6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090", role: "user" },
];

function login(username, password) {
  const user = users.find((u) => u.username === username);
  if (!user) {
    return { success: false, error: "User not found" };
  }

  const hash = hashPassword(password);
  if (hash !== user.passwordHash) {
    return { success: false, error: "Invalid password" };
  }

  const token = Buffer.from(
    JSON.stringify({ id: user.id, username: user.username, role: user.role, exp: Date.now() + 3600000 })
  ).toString("base64");

  return { success: true, token };
}

function getUser(token) {
  const payload = validateToken(token);
  if (!payload) {
    return null;
  }
  return users.find((u) => u.id === payload.id) || null;
}

function isAdmin(token) {
  const payload = validateToken(token);
  if (!payload) return false;
  return payload.role === "admin";
}

module.exports = { login, getUser, isAdmin, users };
