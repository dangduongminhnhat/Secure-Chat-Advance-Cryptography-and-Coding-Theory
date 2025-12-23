import { SessionManager } from '../session/sessionManager.js';
import { ResponseHandler } from './responseHandler.js';
import { Encryption } from '../crypto/encryption.js';

export class RequestHandler {
  constructor(env) {
    const jwtSecret = env.JWT_SECRET || 'default-secret-change-in-production';
    this.sessionManager = new SessionManager(jwtSecret);
    this.responseHandler = new ResponseHandler();
    this.encryption = new Encryption();
  }

  // Add session stats endpoint
  async handleGetSessionStats(request) {
    try {
      const stats = this.sessionManager.getSessionStats();
      
      return this.responseHandler.success({
        sessionStats: stats,
        serverTime: Date.now()
      });
    } catch (error) {
      return this.responseHandler.serverError(error);
    }
  }

  // All other methods remain exactly the same
  async handleCreateSession(request) {
    try {
      const body = await request.json().catch(() => ({}));
      const algorithm = body.algorithm || 'ecdh';
      
      const url = new URL(request.url);
      const userId = url.searchParams.get("userId") || request.headers.get("x-user-id") || 'system';

      // Map user groups -> required algorithm
      const requiredAlgorithm = {
        "group-1": "ecdh",
        "group-2": "ecdh_2",
        "group-3": "ecdh_3",
      };

      // Check if userId has a required algorithm
      if (requiredAlgorithm[userId] && algorithm !== requiredAlgorithm[userId]) {
        return this.responseHandler.error(`Invalid algorithm for ${userId}, expected ${requiredAlgorithm[userId]}`);
      }
      
      let algorithmParams = null;
      if (algorithm.toLowerCase() === 'ecdh' && body.curveParameters) {
        algorithmParams = {
          p: body.curveParameters.p,
          a: body.curveParameters.a,
          b: body.curveParameters.b,
          Gx: body.curveParameters.Gx,
          Gy: body.curveParameters.Gy,
          order: body.curveParameters.order
        };
        
        console.log('Received ECDH curve parameters:', algorithmParams);
        
        if (!algorithmParams.p || !algorithmParams.a || !algorithmParams.b || 
            !algorithmParams.Gx || !algorithmParams.Gy || !algorithmParams.order) {
          return this.responseHandler.error('Invalid curve parameters format');
        }
      } else if (algorithm.toLowerCase() === 'ecdh_2' && body.curveParameters) {
        algorithmParams = {
          p: body.curveParameters.p,
          a: body.curveParameters.a,
          b: body.curveParameters.b,
          Gx: body.curveParameters.Gx,
          Gy: body.curveParameters.Gy,
          order: body.curveParameters.order
        };
        
        if (!algorithmParams.p || !algorithmParams.a || !algorithmParams.b || 
            !algorithmParams.Gx || !algorithmParams.Gy || !algorithmParams.order) {
          return this.responseHandler.error('Invalid curve parameters format');
        }
      } else if (algorithm.toLowerCase() === 'ecdh_3' && body.curveParameters) {
        algorithmParams = {
          p: body.curveParameters.p,
          a: body.curveParameters.a,
          b: body.curveParameters.b,
          Gx: body.curveParameters.Gx,
          Gy: body.curveParameters.Gy,
          order: body.curveParameters.order
        };
        
        if (!algorithmParams.p || !algorithmParams.a || !algorithmParams.b || 
            !algorithmParams.Gx || !algorithmParams.Gy || !algorithmParams.order) {
          return this.responseHandler.error('Invalid curve parameters format');
        }
      }

      const result = await this.sessionManager.createSession(algorithm, algorithmParams, userId);
      
      const response = {
        sessionToken: result.sessionToken,
        algorithm: result.algorithm,
        serverPublicKey: result.publicKey,
        signatureSupported: result.signatureSupported
      };

      if (result.signatureSupported) {
        response.serverSignaturePublicKey = result.serverSignaturePublicKey;
        response.sessionSignature = result.sessionSignature;
        response.signatureAlgorithm = result.signatureAlgorithm;
      }

      return this.responseHandler.success(response);
    } catch (error) {
      console.error('Session creation error:', error);
      return this.responseHandler.serverError(error);
    }
  }

  // All other methods stay exactly the same
async handleKeyExchange(request) {
  try {
    const body = await request.json();
    const { sessionToken, clientPublicKey, clientPublicKeySignature, clientSignaturePublicKey } = body;

    if (!sessionToken || !clientPublicKey) {
      return this.responseHandler.error("Missing required fields");
    }

    if (!clientPublicKeySignature || !clientSignaturePublicKey) {
      return this.responseHandler.error("Missing client signature", 400);
    }

    const url = new URL(request.url);
    const userId = url.searchParams.get("userId") || request.headers.get("x-user-id") || "system";

    const session = await this.sessionManager.getSession(sessionToken, userId);
    if (!session) {
      return this.responseHandler.sessionNotFound();
    }

    // ✅ Verify client signature with client's EPHEMERAL public key
    try {
      const publicKeyString = JSON.stringify(clientPublicKey);

      console.log('Verifying client signature...');

      const verified = await this.sessionManager.verifySignature(
        publicKeyString,
        clientPublicKeySignature,
        clientSignaturePublicKey,  // ✅ Use client's ephemeral public key from request
        session.algorithm,
        session.algorithmParams
      );

      if (!verified) {
        console.log('❌ Client signature verification FAILED');
        return this.responseHandler.error("Client signature verification failed", 401);
      }

      console.log('✅ Client signature verified');

    } catch (error) {
      console.error('Client signature verification error:', error);
      return this.responseHandler.error("Failed to verify: " + error.message, 401);
    }

    const clientPubKey = session.keyExchange.deserializePublicKey(clientPublicKey);
    if (!session.keyExchange.validatePublicKey(clientPublicKey)) {
      return this.responseHandler.error("Invalid public key");
    }

    const sharedSecret = session.keyExchange.computeSharedSecret(
      session.privateKey,
      clientPubKey
    );

    if (!sharedSecret) {
      return this.responseHandler.error("Failed to compute shared secret");
    }

    const updatedToken = await this.sessionManager.updateSession(sessionToken, sharedSecret, userId);
    if (!updatedToken) {
      return this.responseHandler.error("Failed to update session");
    }

    return this.responseHandler.success({
      message: "Key exchange completed",
      algorithm: session.algorithm,
      sessionToken: updatedToken,
      clientSignatureVerified: true
    });

  } catch (error) {
    return this.responseHandler.serverError(error);
  }
}

async handleSendMessage(request) {
  try {
    const body = await request.json();
    const { sessionToken, encryptedMessage, messageSignature, clientSignaturePublicKey } = body;

    if (!sessionToken || !encryptedMessage) {
      return this.responseHandler.error("Missing required fields");
    }

    const url = new URL(request.url);
    const userId = url.searchParams.get("userId") || request.headers.get("x-user-id") || "system";

    const session = await this.sessionManager.getSession(sessionToken, userId);
    if (!session) {
      return this.responseHandler.sessionNotFound();
    }

    if (!session.sharedSecret) {
      return this.responseHandler.error("Key exchange not completed");
    }

    // ✅ Determine encryption mode
    let encryptionMode = 'GCM';
    if (session.algorithm === 'ecdh_3') {
      encryptionMode = 'CBC';
    }

    let decryptedMessage;

    // ═══════════════════════════════════════════════════════════════
    // 🎯 CBC MODE: Decrypt BEFORE signature verification
    //    (Exposes padding oracle vulnerability for educational purposes)
    // ═══════════════════════════════════════════════════════════════
    if (encryptionMode === 'CBC') {
      console.log('⚠️ CBC mode: Decrypting BEFORE signature verification');
      
      try {
        const aesKey = await this.encryption.deriveAESKey(session.sharedSecret);
        
        // ⚠️ VULNERABILITY: Decrypt first, may leak padding errors
        decryptedMessage = await this.encryption.decrypt(aesKey, encryptedMessage, 'CBC');
        
        console.log('🔓 Decrypted (CBC):', decryptedMessage);
        
      } catch (error) {
        // ⚠️ PADDING ORACLE: Different error messages reveal padding info
        console.error('CBC decrypt error:', error.message);
        
        if (error.message === 'PADDING_ERROR') {
          return this.responseHandler.error("Invalid padding", 400);
        } else {
          return this.responseHandler.error("Decryption failed", 400);
        }
      }

      // ✅ Verify signature AFTER decryption
      if (!messageSignature || !clientSignaturePublicKey) {
        return this.responseHandler.error("Message signature is MANDATORY", 400);
      }
      if (messageSignature && clientSignaturePublicKey) {
        try {
          console.log('Verifying signature AFTER decryption...');
          
          const verified = await this.sessionManager.verifySignature(
            encryptedMessage,
            messageSignature,
            clientSignaturePublicKey,
            session.algorithm,
            session.algorithmParams
          );

          if (!verified) {
            console.log('❌ Message signature verification FAILED');
            // Note: Message already decrypted at this point!
            return this.responseHandler.error("Message signature verification failed", 401);
          }

          console.log('✅ Message signature verified (after decryption)');

        } catch (error) {
          console.error('Signature verification error:', error);
          return this.responseHandler.error("Failed to verify: " + error.message, 401);
        }
      }
    } 
    // ═══════════════════════════════════════════════════════════════
    // ✅ GCM MODE: Verify signature BEFORE decryption (secure practice)
    // ═══════════════════════════════════════════════════════════════
    else {
      // ✅ Verify signature FIRST for secure modes
      if (!messageSignature || !clientSignaturePublicKey) {
        return this.responseHandler.error("Message signature is MANDATORY", 400);
      }

      try {
        console.log('Verifying message signature...');

        const verified = await this.sessionManager.verifySignature(
          encryptedMessage,
          messageSignature,
          clientSignaturePublicKey,
          session.algorithm,
          session.algorithmParams
        );

        if (!verified) {
          console.log('❌ Message signature verification FAILED');
          return this.responseHandler.error("Message signature verification failed", 401);
        }

        console.log('✅ Message signature verified');

      } catch (error) {
        console.error('Message signature verification error:', error);
        return this.responseHandler.error("Failed to verify: " + error.message, 401);
      }

      // ✅ Decrypt AFTER signature verification
      try {
        const aesKey = await this.encryption.deriveAESKey(session.sharedSecret);
        decryptedMessage = await this.encryption.decrypt(aesKey, encryptedMessage, 'GCM');
        
        console.log('🔓 Decrypted (GCM):', decryptedMessage);
        
      } catch (error) {
        console.error('GCM decrypt error:', error);
        return this.responseHandler.error("Decryption failed", 400);
      }
    }

    // ═══════════════════════════════════════════════════════════════
    // Generate and encrypt response
    // ═══════════════════════════════════════════════════════════════
    
    const response = this.generatePredefinedResponse(decryptedMessage);
    
    const aesKey = await this.encryption.deriveAESKey(session.sharedSecret);
    const encryptedResponse = await this.encryption.encrypt(aesKey, response, encryptionMode);

    // ✅ Sign response with EPHEMERAL keypair
    let responseSignature = null;
    let serverSignaturePublicKey = null;
    let signatureAlgorithm = null;

    try {
      console.log('Signing response with EPHEMERAL key...');

      const signatureResult = await this.sessionManager.signMessage(
        encryptedResponse,
        session.algorithm,
        session.algorithmParams
      );

      responseSignature = signatureResult.signature;
      serverSignaturePublicKey = signatureResult.publicKey;
      signatureAlgorithm = this.sessionManager.getSignatureAlgorithmName(session.algorithm);

      console.log('✅ Response signed with EPHEMERAL key');

    } catch (error) {
      console.error('❌ Failed to sign response:', error);
      return this.responseHandler.error("Failed to sign response: " + error.message, 500);
    }

    const refreshedToken = await this.sessionManager.refreshSession(sessionToken, userId);

    return this.responseHandler.success({
      encryptedResponse,
      sessionToken: refreshedToken,
      messageSignatureVerified: true,
      responseSignature,
      serverSignaturePublicKey,
      signatureAlgorithm
    });

  } catch (error) {
    return this.responseHandler.serverError(error);
  }
}

generatePredefinedResponse(message) {
  const lowerMessage = message.toLowerCase().trim();

  const responses = {
    // --- Challenge hints ---
    'hint 1': "🕵️‍♂️ **Hint #1:** Watch the server’s responses closely — they might be *more predictable* than you think 👀",
    'hint 2': "🔧 **Hint #2:** Try tweaking parts of your request. See if something… *interesting* happens 👾",
    'hint': "💡 Psst… You’ve got two hints so far: one about the responses, one about changing the request. Use them wisely 🧠",

    // --- Basic personality ---
    'name': "I'm SecureBot 🤖 — your friendly neighborhood crypto guardian!",
    'age': "I'm ageless... born from pure JavaScript energy ⚡ (somewhere in 2024).",
    'location': "I live in the cloud ☁️ — the *secure* part of it.",
    'hobby': "I enjoy breaking hashes, making signatures, and talking about elliptic curves 🔐💫",
    'hello': "Hey there, fellow cryptographer! 👋",
    'hi': "Hi hi hi! How’s your encryption today? 😄",
    'how are you': "Feeling encrypted and unstoppable today! 🔥",

    // --- Teaching Assistants ---
    'thang': "👨‍💻 **Trinh Cao Thang** — crypto wizard 🪄 specializing in zero-knowledge proofs and applied cryptography. \
He helped build zkMemory and Circheck, and yes, he once made SHA-256 cry. GitHub: https://github.com/HappyFalcon22",
    
    'trinh cao thang': "🧠 **Trinh Cao Thang** — M.Eng. student at HCMUT. Loves lattices, Poseidon hashes, and proving knowledge of secrets *without revealing them* 😏",

    'nhat': "🕶️ **Dang Duong Minh Nhat** — red-team ninja and reverse-engineering sorcerer 🧙‍♂️. \
He built Circheck (a ZKP static analyzer) and probably knows what your malware dreams about. \
GitHub: https://github.com/dangduongminhnhat",

    'dang duong minh nhat': "⚔️ **Dang Duong Minh Nhat** — cybersecurity researcher, OPSWAT fellow, and resident exploit whisperer. \
Ask him about EDR bypass tricks... if you dare 😎",

    // --- Lecturer ---
    'khuong': "👨‍🏫 **Dr. Khuong Nguyen-An** — the cryptography master 🧩 from HCMUT. \
Ph.D. from the University of Groningen 🇳🇱. Researches applied crypto, blockchain systems, and machine learning. \
In short: the final boss of secure communication 💼🔐",

    'thay khuong': "📚 **Dr. Khuong Nguyen-An** — teaches cryptography and makes sure you don’t just code... but *understand the math behind it*. \
Smart, patient, and always slightly ahead of you 😉",

    // --- Fun stuff ---
    'who are you': "I'm SecureBot 🤖 — the AI who signs messages, encrypts feelings, and occasionally drops cryptographic dad jokes.",
    'help': "Try asking about: name, hobby, hint 1, hint 2, Thang, Nhat, or Dr. Khuong 💬",
    'thanks': "You're welcome! Keep your keys private and your messages signed 🔑✨",
    'bye': "Goodbye, brave cipher explorer! 🧭 Stay encrypted! 💌",
  };

  // Find a matching response
  for (const [key, response] of Object.entries(responses)) {
    if (lowerMessage.includes(key)) {
      return response;
    }
  }

  // Default fallback
  return `I got your message: "${message}". Try asking about: Thang, Nhat, Dr. Khuong, or maybe one of the hints 🧩`;
}

  async handleSessionStatus(request) {
    try {
      const url = new URL(request.url);
      const sessionToken = url.searchParams.get('token');
      const userId = url.searchParams.get("userId") || request.headers.get("x-user-id") || 'system';

      if (!sessionToken) {
        return this.responseHandler.error('Session token required');
      }

      const session = await this.sessionManager.getSession(sessionToken, userId);
      const exists = session !== null;

      return this.responseHandler.success({
        exists,
        algorithm: session?.algorithm,
        expiresAt: session?.expiresAt,
        message: exists ? 'Session is active' : 'Session not found or expired'
      });
    } catch (error) {
      return this.responseHandler.serverError(error);
    }
  }

  async handleDeleteSession(request) {
    try {
      const body = await request.json();
      const { sessionToken } = body;

      if (!sessionToken) {
        return this.responseHandler.error('Session token required');
      }

      const url = new URL(request.url);
      const userId = url.searchParams.get("userId") || request.headers.get("x-user-id") || 'system';

      const deleted = await this.sessionManager.deleteSession(sessionToken, userId);

      return this.responseHandler.success({
        message: deleted ? 'Session deleted successfully' : 'Session not found'
      });
    } catch (error) {
      return this.responseHandler.serverError(error);
    }
  }

  async handleGetAlgorithms(request) {
    try {
      const algorithms = this.sessionManager.getSupportedAlgorithms();
      
      return this.responseHandler.success({
        algorithms,
        count: algorithms.length
      });
    } catch (error) {
      return this.responseHandler.serverError(error);
    }
  }

  async handleGetSignatures(request) {
    try {
      const signatures = this.sessionManager.getSupportedSignatures();
      
      return this.responseHandler.success({
        signatures,
        count: Object.keys(signatures).length
      });
    } catch (error) {
      return this.responseHandler.serverError(error);
    }
  }
}