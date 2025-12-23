import { KeyExchangeFactory } from '../crypto/keyExchangeFactory.js';
import { SignatureFactory } from '../crypto/signatureFactory.js';
import { JWTManager } from '../utils/jwt.js';

export class SessionManager {
  constructor(secretKey) {
    this.keyExchangeFactory = new KeyExchangeFactory();
    this.signatureFactory = new SignatureFactory();
    this.jwtManager = new JWTManager(secretKey);
    this.SESSION_TIMEOUT = 300;
    this.jwtSecret = secretKey;
    
    console.log("SessionManager initialized - EPHEMERAL signature keys mode");
  }

  // ✅ Generate FRESH random signature keypair for each operation
  async generateEphemeralSignatureKeyPair(algorithm, algorithmParams = null) {
    const signatureInstance = this.signatureFactory.create(algorithm, algorithmParams);
    
    // ✅ Generate FRESH keypair using signature algorithm's random generation
    const keyPair = signatureInstance.generateSignatureKeyPair();
    
    console.log(`✅ Generated EPHEMERAL signature keypair for ${algorithm}`);
    console.log(`   Public key: x=${keyPair.publicKey.x.substring(0, 16)}..., y=${keyPair.publicKey.y.substring(0, 16)}...`);
    
    return {
      instance: signatureInstance,
      keyPair
    };
  }

  // ✅ Sign message with EPHEMERAL keypair
  async signMessage(message, keyExchangeAlgorithm, algorithmParams = null) {
    if (!this.signatureFactory.isSupported(keyExchangeAlgorithm)) {
      throw new Error(`No signature algorithm available for ${keyExchangeAlgorithm}`);
    }
    
    // ✅ Generate FRESH ephemeral keypair for THIS signature
    const signatureInfo = await this.generateEphemeralSignatureKeyPair(
      keyExchangeAlgorithm,
      algorithmParams
    );
    
    // Sign with ephemeral private key
    const signature = await signatureInfo.instance.signMessage(
      message,
      signatureInfo.keyPair.privateKey
    );
    
    console.log(`✅ Message signed with EPHEMERAL key`);
    
    // ✅ Return BOTH signature AND public key
    return {
      signature,
      publicKey: signatureInfo.keyPair.publicKey
    };
  }

  // ✅ Verify signature with provided public key
  async verifySignature(message, signature, publicKey, keyExchangeAlgorithm, algorithmParams = null) {
    if (!this.signatureFactory.isSupported(keyExchangeAlgorithm)) {
      throw new Error(`No signature algorithm available for ${keyExchangeAlgorithm}`);
    }
    
    // Create signature instance for verification
    const signatureInstance = this.signatureFactory.create(keyExchangeAlgorithm, algorithmParams);
    
    // Verify with provided public key
    return await signatureInstance.verifySignature(message, signature, publicKey);
  }

  // ✅ Create session with EPHEMERAL signature
  async createSession(algorithm = 'ecdh', algorithmParams = null, userId = 'system') {
  console.log(`📝 Creating session for user: ${userId}, algorithm: ${algorithm}`);
  
  if (!this.keyExchangeFactory.isSupported(algorithm)) {
    console.error(`❌ Unsupported algorithm: ${algorithm}`);
    throw new Error(`Unsupported key exchange algorithm: ${algorithm}`);
  }

  const sessionId = this.generateSessionId();
  const keyExchange = this.keyExchangeFactory.create(algorithm, algorithmParams);
  
  console.log(`✅ KeyExchange created: ${keyExchange.getAlgorithmName()}`);
  
  // Generate keys
  const privateKey = keyExchange.generatePrivateKey();
  console.log(`✅ Private key generated (type: ${typeof privateKey})`);
  
  const publicKey = keyExchange.generatePublicKey(privateKey);
  console.log(`✅ Public key generated`);

  const sessionData = {
    sessionId,
    userId,
    algorithm,
    privateKey: privateKey.toString(),
    publicKey: keyExchange.serializePublicKey(publicKey),
    sharedSecret: null,
    algorithmParams,
    createdAt: Date.now()
  };

  // ✅ Check signature support
  if (!this.signatureFactory.isSupported(algorithm)) {
    console.error(`❌ Signature not supported for algorithm: ${algorithm}`);
    throw new Error(`Signature not supported for algorithm: ${algorithm}`);
  }

  let sessionSignature = null;
  let serverSignaturePublicKey = null;
  let signatureAlgorithm = null;

  try {
    const sessionDataString = JSON.stringify({
      sessionId,
      algorithm,
      userId,
      createdAt: sessionData.createdAt
    });

    console.log(`✅ Signing session data...`);
    const signatureResult = await this.signMessage(
      sessionDataString,
      algorithm,
      algorithmParams
    );

    sessionSignature = signatureResult.signature;
    serverSignaturePublicKey = signatureResult.publicKey;

    const tempInstance = this.signatureFactory.create(algorithm, algorithmParams);
    signatureAlgorithm = tempInstance.getAlgorithmName();

    console.log(`✅ Session signed with ${signatureAlgorithm}`);
  } catch (error) {
    console.error('❌ Failed to sign session:', error);
    throw new Error(`Failed to create session signature: ${error.message}`);
  }

  // ✅ Create encrypted JWT
  console.log(`🔐 Creating encrypted JWT...`);
  const jwtToken = await this.createEncryptedJWT(sessionData);
  console.log(`✅ JWT created (length: ${jwtToken.length})`);

  console.log(`✅ Session created successfully for ${userId} with ${algorithm.toUpperCase()}`);

  return {
    sessionToken: jwtToken,
    publicKey: keyExchange.serializePublicKey(publicKey),
    algorithm,
    serverSignaturePublicKey,
    sessionSignature,
    signatureAlgorithm,
    signatureSupported: true,
    createdAt: sessionData.createdAt
  };
}

  // Generate session ID
  generateSessionId() {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  // ... (all other methods remain the same: createEncryptedJWT, decryptSession, getSession, etc.)
  
  async deriveEncryptionKey(userId) {
    const encoder = new TextEncoder();
    const keyMaterial = encoder.encode(this.jwtManager.secretKey + userId);
    const keyHash = await crypto.subtle.digest("SHA-256", keyMaterial);
    return new Uint8Array(keyHash).slice(0, 32);
  }

  async createEncryptedJWT(sessionData) {
    const encryptionKey = await this.deriveEncryptionKey(sessionData.userId);

    const sensitiveData = {
      privateKey: sessionData.privateKey,
      sharedSecret: sessionData.sharedSecret,
      algorithmParams: sessionData.algorithmParams
    };

    const encryptedData = await this.jwtManager.encryptPayload(
      sensitiveData,
      encryptionKey
    );

    const payload = {
      sub: sessionData.userId,
      sid: sessionData.sessionId,
      algorithm: sessionData.algorithm,
      publicKey: sessionData.publicKey,
      encryptedData: encryptedData,
      createdAt: sessionData.createdAt,
      lastActivity: sessionData.lastActivity || sessionData.createdAt
    };

    return await this.jwtManager.createToken(payload, this.SESSION_TIMEOUT);
  }

  async decryptSession(jwtToken, userId) {
    try {
      const payload = await this.jwtManager.verifyToken(jwtToken);

      if (payload.sub !== userId) {
        throw new Error("Token userId mismatch");
      }

      const encryptionKey = await this.deriveEncryptionKey(userId);
      const sensitiveData = await this.jwtManager.decryptPayload(
        payload.encryptedData,
        encryptionKey
      );

      return {
        sessionId: payload.sid,
        userId: payload.sub,
        algorithm: payload.algorithm,
        publicKey: payload.publicKey,
        privateKey: sensitiveData.privateKey,
        sharedSecret: sensitiveData.sharedSecret,
        algorithmParams: sensitiveData.algorithmParams,
        createdAt: payload.createdAt,
        lastActivity: payload.lastActivity,
        issuedAt: payload.iat,
        expiresAt: payload.exp
      };

    } catch (error) {
      console.log("Session decryption failed:", error.message);
      return null;
    }
  }

  async getSession(jwtToken, userId = "system") {
    const sessionData = await this.decryptSession(jwtToken, userId);
    if (!sessionData) {
      return null;
    }

    const keyExchange = this.keyExchangeFactory.create(
      sessionData.algorithm,
      sessionData.algorithmParams
    );

    return {
      sessionId: sessionData.sessionId,
      algorithm: sessionData.algorithm,
      algorithmParams: sessionData.algorithmParams,
      privateKey: BigInt(sessionData.privateKey),
      publicKey: keyExchange.deserializePublicKey(sessionData.publicKey),
      sharedSecret: sessionData.sharedSecret ? BigInt(sessionData.sharedSecret) : null,
      createdAt: sessionData.createdAt,
      lastActivity: sessionData.lastActivity,
      keyExchange,
      issuedAt: sessionData.issuedAt,
      expiresAt: sessionData.expiresAt
    };
  }

  async updateSession(jwtToken, sharedSecret, userId = "system") {
    try {
      const sessionData = await this.decryptSession(jwtToken, userId);
      if (!sessionData) {
        return null;
      }

      const updatedSessionData = {
        sessionId: sessionData.sessionId,
        userId: sessionData.userId,
        algorithm: sessionData.algorithm,
        privateKey: sessionData.privateKey,
        publicKey: sessionData.publicKey,
        sharedSecret: sharedSecret.toString(),
        algorithmParams: sessionData.algorithmParams,
        createdAt: sessionData.createdAt,
        lastActivity: Date.now()
      };

      const newJwtToken = await this.createEncryptedJWT(updatedSessionData);

      console.log("Session updated with shared secret");
      return newJwtToken;

    } catch (error) {
      console.log("Session update failed:", error.message);
      return null;
    }
  }

  async refreshSession(jwtToken, userId = "system") {
    try {
      const sessionData = await this.decryptSession(jwtToken, userId);
      if (!sessionData) {
        return null;
      }

      const refreshedSessionData = {
        sessionId: sessionData.sessionId,
        userId: sessionData.userId,
        algorithm: sessionData.algorithm,
        privateKey: sessionData.privateKey,
        publicKey: sessionData.publicKey,
        sharedSecret: sessionData.sharedSecret,
        algorithmParams: sessionData.algorithmParams,
        createdAt: sessionData.createdAt,
        lastActivity: Date.now()
      };

      const newJwtToken = await this.createEncryptedJWT(refreshedSessionData);

      console.log("Session refreshed");
      return newJwtToken;

    } catch (error) {
      console.log("Session refresh failed:", error.message);
      return null;
    }
  }

  async deleteSession(jwtToken, userId = "system") {
    try {
      const payload = await this.jwtManager.verifyToken(jwtToken);

      if (payload.sub !== userId) {
        return false;
      }

      console.log(`Session deleted: ${payload.sid.substring(0, 8)}...`);
      return true;

    } catch (error) {
      console.log("Session deletion failed:", error.message);
      return false;
    }
  }

  async hasSession(jwtToken, userId = "system") {
    const session = await this.getSession(jwtToken, userId);
    return session !== null;
  }

  getSignatureAlgorithmName(keyExchangeAlgorithm) {
    return this.signatureFactory.getSignatureAlgorithmName(keyExchangeAlgorithm);
  }

  getSupportedSignatures() {
    return this.signatureFactory.getSupportedSignatures();
  }

  getSupportedAlgorithms() {
    return this.keyExchangeFactory.getSupportedAlgorithms();
  }
}