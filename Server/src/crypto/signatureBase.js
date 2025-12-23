// ============================================
// File: src/crypto/signatureBase.js
// ============================================

export class SignatureBase {
  constructor(algorithmName) {
    if (new.target === SignatureBase) {
      throw new TypeError("Cannot construct SignatureBase instances directly");
    }
    this.algorithmName = algorithmName;
  }

  // Abstract methods - must be implemented by subclasses
  generateSignatureKeyPair() {
    throw new Error("Method 'generateSignatureKeyPair()' must be implemented");
  }

  async signMessage(message, privateKey) {
    throw new Error("Method 'signMessage()' must be implemented");
  }

  async verifySignature(message, signature, publicKey) {
    throw new Error("Method 'verifySignature()' must be implemented");
  }

  // Serialize signature to JSON-friendly format
  serializeSignature(signature) {
    throw new Error("Method 'serializeSignature()' must be implemented");
  }

  // Deserialize signature from JSON format
  deserializeSignature(data) {
    throw new Error("Method 'deserializeSignature()' must be implemented");
  }

  // Serialize public key to JSON-friendly format
  serializePublicKey(publicKey) {
    throw new Error("Method 'serializePublicKey()' must be implemented");
  }

  // Deserialize public key from JSON format
  deserializePublicKey(data) {
    throw new Error("Method 'deserializePublicKey()' must be implemented");
  }

  // Optional: Validate signature parameters
  validateSignature(signature) {
    return true; // Default implementation
  }

  // Get algorithm name
  getAlgorithmName() {
    return this.algorithmName;
  }

  // Get signature size in bits
  getSignatureSize() {
    throw new Error("Method 'getSignatureSize()' must be implemented");
  }

  // Get signature parameters as JSON
  getParameters() {
    throw new Error("Method 'getParameters()' must be implemented");
  }
}