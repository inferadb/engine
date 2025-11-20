#!/usr/bin/env node
/**
 * InferaDB Authentication Example (Node.js)
 *
 * This example demonstrates how to:
 * 1. Generate Ed25519 key pairs
 * 2. Register client credentials with the management API
 * 3. Generate JWT tokens
 * 4. Call the InferaDB server with authentication
 *
 * Requirements:
 *     npm install jose node-fetch uuid
 *
 * Environment Variables:
 *     MANAGEMENT_API_URL - Management API URL (default: http://localhost:8081)
 *     SERVER_URL - InferaDB server URL (default: http://localhost:8080)
 *     USER_EMAIL - User email for login
 *     USER_PASSWORD - User password for login
 */

const { generateKeyPair, SignJWT, exportSPKI, importPKCS8 } = require('jose');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

// Configuration
const MANAGEMENT_API_URL = process.env.MANAGEMENT_API_URL || 'http://localhost:8081';
const SERVER_URL = process.env.SERVER_URL || 'http://localhost:8080';

class InferaDBAuth {
  constructor(managementApiUrl, serverUrl) {
    this.managementApiUrl = managementApiUrl.replace(/\/$/, '');
    this.serverUrl = serverUrl.replace(/\/$/, '');
    this.sessionId = null;
    this.userId = null;
    this.orgId = null;
    this.vaultId = null;
    this.accountId = null;
    this.clientId = null;
    this.certKid = null;
    this.privateKey = null;
  }

  async registerUser(name, email, password) {
    const response = await fetch(`${this.managementApiUrl}/v1/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name,
        email,
        password,
        accept_tos: true,
      }),
    });

    if (!response.ok) {
      throw new Error(`Registration failed: ${response.statusText}`);
    }

    const data = await response.json();
    this.userId = data.id;
    this.orgId = data.organization_id;

    console.log(`✓ User registered: ${email}`);
    console.log(`  User ID: ${this.userId}`);
    console.log(`  Org ID: ${this.orgId}`);

    return data;
  }

  async login(email, password) {
    const response = await fetch(`${this.managementApiUrl}/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    if (!response.ok) {
      throw new Error(`Login failed: ${response.statusText}`);
    }

    const data = await response.json();
    this.sessionId = data.session_id;
    this.userId = data.user_id;

    console.log(`✓ Logged in: ${email}`);
    console.log(`  Session ID: ${this.sessionId}`);

    // Get organization ID
    const userResponse = await fetch(`${this.managementApiUrl}/v1/users/${this.userId}`, {
      headers: { Authorization: `Bearer ${this.sessionId}` },
    });

    if (!userResponse.ok) {
      throw new Error(`Failed to get user info: ${userResponse.statusText}`);
    }

    const userData = await userResponse.json();
    this.orgId = userData.organization_id;

    return data;
  }

  async createVault(name) {
    const response = await fetch(`${this.managementApiUrl}/v1/vaults`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.sessionId}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name,
        organization_id: this.orgId,
      }),
    });

    if (!response.ok) {
      throw new Error(`Vault creation failed: ${response.statusText}`);
    }

    const data = await response.json();
    this.vaultId = data.id;
    this.accountId = data.account_id;

    console.log(`✓ Vault created: ${name}`);
    console.log(`  Vault ID: ${this.vaultId}`);
    console.log(`  Account ID: ${this.accountId}`);

    return data;
  }

  async generateEd25519KeyPair() {
    // Generate Ed25519 key pair
    const { publicKey, privateKey } = await generateKeyPair('EdDSA', {
      crv: 'Ed25519',
    });

    this.privateKey = privateKey;

    // Export public key for certificate registration
    const publicKeySpki = await exportSPKI(publicKey);
    // Extract raw public key bytes from SPKI
    const publicKeyDer = Buffer.from(publicKeySpki.replace(/-+(BEGIN|END) PUBLIC KEY-+/g, ''), 'base64');
    // Ed25519 public key is last 32 bytes of SPKI
    const publicKeyRaw = publicKeyDer.slice(-32);
    const publicKeyB64 = publicKeyRaw.toString('base64');

    console.log('✓ Ed25519 key pair generated');
    console.log(`  Public key (base64): ${publicKeyB64.substring(0, 32)}...`);

    return { privateKey, publicKeyB64 };
  }

  async createClient(name) {
    const response = await fetch(
      `${this.managementApiUrl}/v1/organizations/${this.orgId}/clients`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.sessionId}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name }),
      }
    );

    if (!response.ok) {
      throw new Error(`Client creation failed: ${response.statusText}`);
    }

    const data = await response.json();
    this.clientId = data.id;

    console.log(`✓ Client created: ${name}`);
    console.log(`  Client ID: ${this.clientId}`);

    return data;
  }

  async registerCertificate(name, publicKeyB64) {
    const response = await fetch(
      `${this.managementApiUrl}/v1/organizations/${this.orgId}/clients/${this.clientId}/certificates`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.sessionId}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name,
          public_key: publicKeyB64,
        }),
      }
    );

    if (!response.ok) {
      throw new Error(`Certificate registration failed: ${response.statusText}`);
    }

    const data = await response.json();
    this.certKid = data.kid;

    console.log(`✓ Certificate registered: ${name}`);
    console.log(`  Certificate ID: ${data.id}`);
    console.log(`  KID: ${this.certKid}`);

    return data;
  }

  async generateJWT(scopes = ['read', 'write'], ttlMinutes = 5) {
    if (!this.privateKey) {
      throw new Error('Private key not set. Call generateEd25519KeyPair() first.');
    }

    const token = await new SignJWT({
      vault: this.vaultId,
      account: this.accountId,
      scope: scopes.join(' '),
      jti: uuidv4(),
    })
      .setProtectedHeader({ alg: 'EdDSA', kid: this.certKid })
      .setIssuer(`${this.managementApiUrl}/v1`)
      .setSubject(`client:${this.clientId}`)
      .setAudience(this.serverUrl)
      .setIssuedAt()
      .setExpirationTime(`${ttlMinutes}m`)
      .sign(this.privateKey);

    console.log(`✓ JWT generated (expires in ${ttlMinutes} minutes)`);
    console.log(`  Scopes: ${scopes.join(', ')}`);

    return token;
  }

  async callServer(token, endpoint, method = 'POST', data = null) {
    const url = `${this.serverUrl}${endpoint}`;
    const options = {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    };

    if (data) {
      options.body = JSON.stringify(data);
    }

    const response = await fetch(url, options);

    console.log(`✓ Server call: ${method} ${endpoint}`);
    console.log(`  Status: ${response.status}`);

    return response;
  }
}

async function main() {
  console.log('='.repeat(60));
  console.log('InferaDB Authentication Example (Node.js)');
  console.log('='.repeat(60));
  console.log();

  // Initialize auth helper
  const auth = new InferaDBAuth(MANAGEMENT_API_URL, SERVER_URL);

  // Get user credentials from environment or use defaults
  const email = process.env.USER_EMAIL || 'test@example.com';
  const password = process.env.USER_PASSWORD || 'TestPassword123!';

  // Login or register
  try {
    await auth.login(email, password);
  } catch (error) {
    console.log('Login failed. Registering new user...');
    await auth.registerUser('Test User', email, password);
    await auth.login(email, password);
  }

  // Create vault
  const vaultName = `Example Vault ${crypto.randomBytes(4).toString('hex')}`;
  await auth.createVault(vaultName);

  // Generate Ed25519 key pair
  const { publicKeyB64 } = await auth.generateEd25519KeyPair();

  // Create client
  const clientName = `Example Client ${crypto.randomBytes(4).toString('hex')}`;
  await auth.createClient(clientName);

  // Register certificate
  const certName = `Example Certificate ${crypto.randomBytes(4).toString('hex')}`;
  await auth.registerCertificate(certName, publicKeyB64);

  console.log();
  console.log('='.repeat(60));
  console.log('Authentication Setup Complete!');
  console.log('='.repeat(60));
  console.log();

  // Generate JWT
  const token = await auth.generateJWT(['read', 'write'], 5);

  console.log();
  console.log('JWT Token (first 100 chars):');
  console.log(token.substring(0, 100) + '...');
  console.log();

  // Example: Evaluate permission
  console.log('='.repeat(60));
  console.log('Example: Evaluate Permission');
  console.log('='.repeat(60));
  console.log();

  const evaluationData = {
    evaluations: [
      {
        subject: 'user:alice',
        resource: 'document:readme',
        permission: 'viewer',
      },
    ],
  };

  try {
    const response = await auth.callServer(token, '/v1/evaluate', 'POST', evaluationData);
    const result = await response.json();
    console.log(`Response: ${JSON.stringify(result, null, 2)}`);
  } catch (error) {
    console.error(`Error: ${error.message}`);
  }

  console.log();

  // Example: Write relationship
  console.log('='.repeat(60));
  console.log('Example: Write Relationship');
  console.log('='.repeat(60));
  console.log();

  const writeData = {
    relationships: [
      {
        resource: 'document:readme',
        relation: 'viewer',
        subject: 'user:alice',
      },
    ],
  };

  try {
    const response = await auth.callServer(token, '/v1/relationships/write', 'POST', writeData);
    const result = response.status === 200 ? await response.json() : await response.text();
    console.log(`Response: ${JSON.stringify(result, null, 2)}`);
  } catch (error) {
    console.error(`Error: ${error.message}`);
  }

  console.log();
  console.log('='.repeat(60));
  console.log('Example Complete!');
  console.log('='.repeat(60));
}

// Run main function
main().catch((error) => {
  console.error(`\nError: ${error.message}`);
  process.exit(1);
});
