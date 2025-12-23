// ============================================
// File: src/crypto/secureRandom.js
// ============================================

export class SecureRandom {
  // Generate cryptographically secure random BigInt
  static generateRandomBigInt(bitLength) {
    const byteLength = Math.ceil(bitLength / 8);
    const randomBytes = crypto.getRandomValues(new Uint8Array(byteLength));
    
    // Convert to BigInt
    let result = 0n;
    for (let i = 0; i < byteLength; i++) {
      result = (result << 8n) + BigInt(randomBytes[i]);
    }
    
    // Ensure it's within the bit length
    const mask = (1n << BigInt(bitLength)) - 1n;
    return result & mask;
  }

  // Generate random private key for given order
  static generatePrivateKey(order, bitLength = 192) {
    let privateKey;
    do {
      privateKey = this.generateRandomBigInt(bitLength); // For P-192
      privateKey = privateKey % (order - 1n) + 1n;
    } while (privateKey <= 1n || privateKey >= order);
    
    return privateKey;
  }

  // Generate secure random k for ECDSA (RFC 6979 style)
  static async generateSecureK(messageHash, privateKey, order) {
    // Use HMAC-based deterministic k generation (RFC 6979)
    const encoder = new TextEncoder();
    
    // Convert inputs to bytes
    const hashBytes = this.bigIntToBytes(messageHash, 32);
    const keyBytes = this.bigIntToBytes(privateKey, 24);
    
    // HMAC-DRBG initialization
    let V = new Uint8Array(32).fill(0x01); // V = 0x01^32
    let K = new Uint8Array(32).fill(0x00); // K = 0x00^32
    
    // Import key for HMAC
    const hmacKey = await crypto.subtle.importKey(
      'raw', K, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    
    // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
    const data1 = new Uint8Array(V.length + 1 + keyBytes.length + hashBytes.length);
    data1.set(V, 0);
    data1.set([0x00], V.length);
    data1.set(keyBytes, V.length + 1);
    data1.set(hashBytes, V.length + 1 + keyBytes.length);
    
    const newK = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, data1));
    
    // Import new K
    const newHmacKey = await crypto.subtle.importKey(
      'raw', newK, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    
    // V = HMAC_K(V)
    V = new Uint8Array(await crypto.subtle.sign('HMAC', newHmacKey, V));
    
    // Convert V to BigInt and reduce mod order
    let k = 0n;
    for (let i = 0; i < V.length; i++) {
      k = (k << 8n) + BigInt(V[i]);
    }
    
    k = k % (order - 1n) + 1n;
    
    // Ensure k is valid
    if (k <= 1n || k >= order) {
      // Fallback to simple random if RFC 6979 fails
      return this.generatePrivateKey(order);
    }
    
    return k;
  }

  // Generate deterministic k for ECDSA using SHA-1 (RFC 6979 style)
static async generateSecureKSHA1(messageHash, privateKey, order) {
    const encoder = new TextEncoder();

    // Convert inputs to bytes
    const hashBytes = this.bigIntToBytes(messageHash, 20); // SHA-1 = 20 bytes
    const keyBytes = this.bigIntToBytes(privateKey, 24);   // 192-bit privkey

    // HMAC-DRBG initialization
    let V = new Uint8Array(20).fill(0x01); // V = 0x01^20
    let K = new Uint8Array(20).fill(0x00); // K = 0x00^20

    // Import key for HMAC
    const hmacKey = await crypto.subtle.importKey(
        'raw', K, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
    );

    // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
    const data1 = new Uint8Array(V.length + 1 + keyBytes.length + hashBytes.length);
    data1.set(V, 0);
    data1.set([0x00], V.length);
    data1.set(keyBytes, V.length + 1);
    data1.set(hashBytes, V.length + 1 + keyBytes.length);

    const newK = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, data1));

    // Import new K
    const newHmacKey = await crypto.subtle.importKey(
        'raw', newK, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
    );

    // V = HMAC_K(V)
    V = new Uint8Array(await crypto.subtle.sign('HMAC', newHmacKey, V));

    // Convert V to BigInt and reduce mod order
    let k = 0n;
    for (let i = 0; i < V.length; i++) {
        k = (k << 8n) + BigInt(V[i]);
    }

    k = k % (order - 1n) + 1n;

    // Ensure k is valid
    if (k <= 1n || k >= order) {
        // Fallback to simple random if RFC 6979 fails
        return this.generatePrivateKey(order);
    }

    return k;
}

  static bigIntToBytes(bigInt, length) {
    const hex = bigInt.toString(16).padStart(length * 2, '0');
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
  }
}