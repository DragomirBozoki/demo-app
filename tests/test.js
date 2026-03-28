const { hashPassword, authenticate, validateToken, createToken } = require("../src/auth");
const { login, getUser, isAdmin } = require("../src/app");

let passed = 0;
let failed = 0;
const failures = [];

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  ✅ ${name}`);
  } catch (err) {
    failed++;
    failures.push({ name, error: err.message });
    console.log(`  ❌ ${name}`);
    console.log(`     Error: ${err.message}`);
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || "Assertion failed");
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(message || `Expected "${expected}" but got "${actual}"`);
  }
}

// ─── Auth Module Tests ───

console.log("\n🔐 Auth Module Tests\n");

test("hashPassword returns consistent SHA-256 hash", () => {
  const hash1 = hashPassword("password");
  const hash2 = hashPassword("password");
  assertEqual(hash1, hash2, "Same input should produce same hash");
  assertEqual(hash1.length, 64, "SHA-256 hash should be 64 hex chars");
});

test("hashPassword returns different hashes for different inputs", () => {
  const hash1 = hashPassword("password1");
  const hash2 = hashPassword("password2");
  assert(hash1 !== hash2, "Different passwords should produce different hashes");
});

test("authenticate returns user for valid credentials", () => {
  const users = [
    { id: 1, username: "admin", passwordHash: hashPassword("secret"), role: "admin" },
  ];
  const result = authenticate("admin", "secret", users);
  assert(result !== null, "Should return user");
  assertEqual(result.username, "admin");
});

test("authenticate returns null for wrong password", () => {
  const users = [
    { id: 1, username: "admin", passwordHash: hashPassword("secret"), role: "admin" },
  ];
  const result = authenticate("admin", "wrong", users);
  assertEqual(result, null, "Should return null for wrong password");
});

test("authenticate returns null for non-existent user", () => {
  const users = [
    { id: 1, username: "admin", passwordHash: hashPassword("secret"), role: "admin" },
  ];
  const result = authenticate("nobody", "secret", users);
  assertEqual(result, null, "Should return null for unknown user");
});

test("createToken returns a base64 string", () => {
  const token = createToken({ id: 1, username: "test", role: "user" });
  assert(typeof token === "string", "Token should be a string");
  const decoded = JSON.parse(Buffer.from(token, "base64").toString("utf-8"));
  assertEqual(decoded.username, "test");
  assert(decoded.exp > Date.now(), "Token should expire in the future");
});

test("validateToken decodes a valid token", () => {
  const token = createToken({ id: 1, username: "test", role: "user" });
  const payload = validateToken(token);
  assert(payload !== null, "Should decode valid token");
  assertEqual(payload.username, "test");
});

test("validateToken returns null for garbage input", () => {
  const result = validateToken("not-a-valid-token!!!");
  assertEqual(result, null, "Should return null for invalid token");
});

// ─── THIS TEST WILL FAIL ───
// It catches the bug: expired tokens are still accepted

test("validateToken rejects expired tokens", () => {
  // Create a token that expired 1 hour ago
  const expiredPayload = {
    id: 1,
    username: "test",
    role: "user",
    exp: Date.now() - 3600000, // 1 hour in the past
  };
  const expiredToken = Buffer.from(JSON.stringify(expiredPayload)).toString("base64");

  const result = validateToken(expiredToken);
  assertEqual(result, null, "Expired token should be rejected, but validateToken accepted it — expiry check is missing!");
});

// ─── App Module Tests ───

console.log("\n📱 App Module Tests\n");

test("login succeeds with correct credentials", () => {
  const result = login("admin", "password");
  assert(result.success === true, "Login should succeed");
  assert(typeof result.token === "string", "Should return a token");
});

test("login fails with wrong password", () => {
  const result = login("admin", "wrongpassword");
  assert(result.success === false, "Login should fail");
  assertEqual(result.error, "Invalid password");
});

test("login fails with non-existent user", () => {
  const result = login("nobody", "password");
  assert(result.success === false, "Login should fail");
  assertEqual(result.error, "User not found");
});

test("getUser returns user for valid token", () => {
  const result = login("admin", "password");
  const user = getUser(result.token);
  assert(user !== null, "Should return user");
  assertEqual(user.username, "admin");
});

test("getUser returns null for invalid token", () => {
  const user = getUser("garbage");
  assertEqual(user, null, "Should return null");
});

test("isAdmin returns true for admin user", () => {
  const result = login("admin", "password");
  assert(isAdmin(result.token) === true, "Admin should be admin");
});

test("isAdmin returns false for regular user", () => {
  const result = login("user1", "abc123");
  assert(isAdmin(result.token) === false, "Regular user should not be admin");
});

// ─── Summary ───

console.log(`\n${"─".repeat(40)}`);
console.log(`Results: ${passed} passed, ${failed} failed out of ${passed + failed} tests`);

if (failures.length > 0) {
  console.log(`\n💥 FAILURES:\n`);
  failures.forEach((f, i) => {
    console.log(`  ${i + 1}. ${f.name}`);
    console.log(`     ${f.error}\n`);
  });
  process.exit(1);
}

console.log("\n✅ All tests passed!\n");
process.exit(0);
