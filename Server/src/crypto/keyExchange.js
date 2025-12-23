export class KeyExchange {
  constructor(algorithmName) {
    if (new.target === KeyExchange) {
      throw new TypeError("Cannot construct KeyExchange instances directly");
    }
    this.algorithmName = algorithmName;
  }

  // Abstract methods - must be implemented by subclasses
  generatePrivateKey() {
    throw new Error("Method 'generatePrivateKey()' must be implemented");
  }

  generatePublicKey(privateKey) {
    throw new Error("Method 'generatePublicKey()' must be implemented");
  }

  computeSharedSecret(privateKey, publicKey) {
    throw new Error("Method 'computeSharedSecret()' must be implemented");
  }

  // Serialize public key to JSON-friendly format
  serializePublicKey(publicKey) {
    throw new Error("Method 'serializePublicKey()' must be implemented");
  }

  // Deserialize public key from JSON format
  deserializePublicKey(data) {
    throw new Error("Method 'deserializePublicKey()' must be implemented");
  }

  // Optional: Validate public key
  validatePublicKey(publicKey) {
    return true; // Default implementation
  }

  // Get algorithm name
  getAlgorithmName() {
    return this.algorithmName;
  }

  // Get key size in bits
  getKeySize() {
    throw new Error("Method 'getKeySize()' must be implemented");
  }

  // Get algorithm parameters as JSON
  getParameters() {
    throw new Error("Method 'getParameters()' must be implemented");
  }
}