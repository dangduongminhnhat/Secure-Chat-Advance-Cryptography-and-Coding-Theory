// ============================================
// File: src/crypto/signatureFactory.js
// ============================================

import { SignatureBase } from './signatureBase.js';
import { ECDSASignature } from './ecdsaSignature.js';
import { ECDSABug } from './ecdsaBug.js';
import { ECDSASignature_3 } from './ecdsaSignature_3.js';
// import { RSASignature } from './rsaSignature.js';
// import { DSASignature } from './dsaSignature.js';

export class SignatureFactory {
  constructor() {
    this.signatures = new Map();
    this.registerDefaultSignatures();
  }

  // Register default signature algorithms
  registerDefaultSignatures() {
    this.register('ecdh', ECDSASignature);  // ECDH uses ECDSA for signing
    this.register('ecdh_2', ECDSABug);
    this.register('ecdh_3', ECDSASignature_3);
  }

  // Register a new signature algorithm
  register(keyExchangeAlgorithm, signatureClass) {
    if (!(signatureClass.prototype instanceof SignatureBase) && signatureClass !== SignatureBase) {
      throw new Error(`${signatureClass.name} must extend SignatureBase`);
    }
    this.signatures.set(keyExchangeAlgorithm.toLowerCase(), signatureClass);
  }

  // Create signature instance for key exchange algorithm
  create(keyExchangeAlgorithm, params = null) {
    const SignatureClass = this.signatures.get(keyExchangeAlgorithm.toLowerCase());
    if (!SignatureClass) {
      throw new Error(`No signature algorithm found for key exchange: ${keyExchangeAlgorithm}`);
    }

    // Pass parameters if available (e.g., curve parameters for ECDSA)
    if (keyExchangeAlgorithm.toLowerCase() === 'ecdh' && params) {
      return new SignatureClass(params);
    } else if (keyExchangeAlgorithm.toLowerCase() === 'ecdh_2' && params) {
      return new SignatureClass(params);
    } else if (keyExchangeAlgorithm.toLowerCase() === 'ecdh_3' && params) {
      return new SignatureClass(params);
    }

    return new SignatureClass();
  }

  // Get supported signature algorithms for key exchange
  getSupportedSignatures() {
    const result = {};
    for (const [keyExchange, SignatureClass] of this.signatures) {
      const tempInstance = new SignatureClass();
      result[keyExchange] = {
        signatureAlgorithm: tempInstance.getAlgorithmName(),
        parameters: tempInstance.getParameters()
      };
    }
    return result;
  }

  // Check if signature is supported for key exchange algorithm
  isSupported(keyExchangeAlgorithm) {
    return this.signatures.has(keyExchangeAlgorithm.toLowerCase());
  }

  // Get signature algorithm name for key exchange
  getSignatureAlgorithmName(keyExchangeAlgorithm) {
    const SignatureClass = this.signatures.get(keyExchangeAlgorithm.toLowerCase());
    if (!SignatureClass) {
      return null;
    }
    const tempInstance = new SignatureClass();
    return tempInstance.getAlgorithmName();
  }
}