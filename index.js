const express = require("express");
const { debug } = require("ps-logger");
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");
const crypto = require("node:crypto");

if (!globalThis.crypto) {
  globalThis.crypto = crypto;
}

const app = express();
const PORT = 3001;

app.use(express.static("./public"));
app.use(express.json());

// store

const userStore = {};
const challengeStore = {};

app.post("/register", (req, res) => {
  const { username, password } = req.body;
  const id = `user_${Date.now()}`;
  console.log("req==>", req.body);
  const user = {
    username,
    password,
    id,
  };

  userStore[id] = user;
  console.log("user======>", user);
  res.json({ id, message: "user registered successfully" });
});

app.post("/register-challenge", async (req, res) => {
  const { userId } = req.body;

  if (!userStore[userId])
    return res.status(404).json({ error: "user not found!" });

  const user = userStore[userId];

  const challengePayload = await generateRegistrationOptions({
    rpID: "localhost",
    rpName: "My Localhost Machine",
    attestationType: "none",
    userName: user.username,
    timeout: 30_000,
  });

  challengeStore[userId] = challengePayload.challenge;

  return res.json({ options: challengePayload });
});

app.post("/register-verify", async (req, res) => {
  const { userId, cred } = req.body;

  if (!userStore[userId])
    return res.status(404).json({ error: "user not found!" });
  const user = userStore[userId];
  const challenge = challengeStore[userId];

  const verificationResult = await verifyRegistrationResponse({
    expectedChallenge: challenge,
    expectedOrigin: "http://localhost:3001",
    expectedRPID: "localhost",
    response: cred,
  });

  if (!verificationResult.verified)
    return res.json({ error: "could not verify" });
  userStore[userId].passkey = verificationResult.registrationInfo;

  return res.json({ verified: true });
});

app.post("/login-challenge", async (req, res) => {
  const { userId } = req.body;
  if (!userStore[userId])
    return res.status(404).json({ error: "user not found!" });

  const opts = await generateAuthenticationOptions({
    rpID: "localhost",
  });

  challengeStore[userId] = opts.challenge;

  return res.json({ options: opts });
});

app.post("/login-verify", async (req, res) => {
  const { userId, cred } = req.body;

  if (!userStore[userId])
    return res.status(404).json({ error: "user not found!" });
  const user = userStore[userId];
  const challenge = challengeStore[userId];

  const result = await verifyAuthenticationResponse({
    expectedChallenge: challenge,
    expectedOrigin: "http://localhost:3001",
    expectedRPID: "localhost",
    response: cred,
    authenticator: user.passkey,
  });

  if (!result.verified) return res.json({ error: "something went wrong" });

  // Login the user: Session, Cookies, JWT
  return res.json({ success: true, userId });
});

console.log("store====>", userStore);
console.log("challenge store===>", challengeStore);

app.listen(PORT, () => {
  debug(`SERVER IS RUNNING ON PORT ${PORT}`);
});
