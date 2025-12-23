import { ECDH } from './ecdh.js';
import { ECDH_2 } from './ecdh_2.js';
import { ECDH_3 } from './ecdh_3.js';
import { KeyExchange } from './keyExchange.js';
// Import future implementations here
// import { RSA } from './rsa.js';
// import { DH } from './dh.js';

export class KeyExchangeFactory {
  constructor() {
    this.algorithms = new Map();
    this.registerDefaultAlgorithms();
  }

  // Register default algorithms
  registerDefaultAlgorithms() {
    this.register('ecdh', ECDH);
    this.register('ecdh_2', ECDH_2);
    this.register('ecdh_3', ECDH_3);
  }

  // Register a new key exchange algorithm
  register(name, algorithmClass) {
    if (!(algorithmClass.prototype instanceof KeyExchange) && algorithmClass !== KeyExchange) {
      throw new Error(`${algorithmClass.name} must extend KeyExchange`);
    }
    this.algorithms.set(name.toLowerCase(), algorithmClass);
  }

  // Create instance of key exchange algorithm with optional parameters
  create(name, params = null) {
    const AlgorithmClass = this.algorithms.get(name.toLowerCase());
    if (!AlgorithmClass) {
      throw new Error(`Unknown key exchange algorithm: ${name}`);
    }
    
    // Pass parameters to constructor for algorithms that support it
    if (name.toLowerCase() === 'ecdh' && params) {
      return new AlgorithmClass(params);
    } else if (name.toLowerCase() === 'ecdh_2' && params) {
      return new AlgorithmClass(params);
    } else if (name.toLowerCase() === 'ecdh_3' && params) {
      return new AlgorithmClass(params);
    }
    
    return new AlgorithmClass();
  }

  // Get list of supported algorithms
  getSupportedAlgorithms() {
    return Array.from(this.algorithms.keys());
  }

  // Check if algorithm is supported
  isSupported(name) {
    return this.algorithms.has(name.toLowerCase());
  }
}