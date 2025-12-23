// ============================================
// File: src/crypto/encryption.js
// ============================================

// ✅ Helper: Check if running in Node.js
const isNode = typeof process !== 'undefined' && 
               process.versions != null && 
               process.versions.node != null;

export class Encryption {
  constructor() {
    this.aesKeyGCM = null;
    this.aesKeyCBC = null;
  }

  // ============================================
  // UTILITY: Base64 Encoding/Decoding
  // ============================================

  /**
   * ✅ Cross-platform base64 decode
   */
  base64Decode(base64String) {
    if (isNode) {
      // Node.js
      return new Uint8Array(Buffer.from(base64String, 'base64'));
    } else {
      // Browser
      return Uint8Array.from(atob(base64String), c => c.charCodeAt(0));
    }
  }

  /**
   * ✅ Cross-platform base64 encode
   */
  base64Encode(uint8Array) {
    if (isNode) {
      // Node.js
      return Buffer.from(uint8Array).toString('base64');
    } else {
      // Browser
      return btoa(String.fromCharCode(...uint8Array));
    }
  }

  // ============================================
  // UTILITY: BigInt Conversion
  // ============================================

  bigIntToBytes(bigInt, length) {
    if (!length) {
      const hex = bigInt.toString(16);
      length = Math.ceil(hex.length / 2);
    }
    
    const hex = bigInt.toString(16).padStart(length * 2, '0');
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  // ============================================
  // KEY DERIVATION
  // ============================================

  async deriveAESKey(sharedSecret) {
    const secretHex = sharedSecret.toString(16);
    const secretSize = Math.ceil(secretHex.length / 2);
    
    const secretBytes = this.bigIntToBytes(sharedSecret, secretSize);
    
    // Step 1: Import as key material
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      secretBytes,
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    // Step 2: Derive raw key bytes (32 bytes = 256 bits)
    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: new Uint8Array(16), // All zeros (MUST match client)
        iterations: 1000,
        hash: 'SHA-256'
      },
      keyMaterial,
      256 // 256 bits
    );

    const rawKeyBytes = new Uint8Array(derivedBits);
    
    // Step 3: Import as GCM key
    this.aesKeyGCM = await crypto.subtle.importKey(
      'raw',
      rawKeyBytes,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    // Step 4: Import as CBC key
    this.aesKeyCBC = await crypto.subtle.importKey(
      'raw',
      rawKeyBytes,
      { name: 'AES-CBC', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    return this.aesKeyGCM;
  }

  // ============================================
  // GCM MODE
  // ============================================

  async encryptGCM(aesKey, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      encoder.encode(plaintext)
    );

    const result = new Uint8Array(iv.length + ciphertext.byteLength);
    result.set(iv);
    result.set(new Uint8Array(ciphertext), iv.length);

    return this.base64Encode(result);
  }

  async decryptGCM(aesKey, encryptedData) {
    const data = this.base64Decode(encryptedData);

    const iv = data.slice(0, 12);
    const ciphertext = data.slice(12);

    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      ciphertext
    );

    return new TextDecoder().decode(plaintext);
  }

  // ============================================
  // CBC MODE
  // ============================================

  async encryptCBC(aesKey, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const encoder = new TextEncoder();
    const plaintextBytes = encoder.encode(plaintext);
    
    // ✅ Manual PKCS#7 padding
    const paddedPlaintext = this.addPKCS7Padding(plaintextBytes, 16);
    
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv },
      aesKey,
      paddedPlaintext
    );

    const result = new Uint8Array(iv.length + ciphertext.byteLength);
    result.set(iv);
    result.set(new Uint8Array(ciphertext), iv.length);

    return this.base64Encode(result);
  }

async decryptCBC(aesKey, encryptedData) {
  try {
    const data = this.base64Decode(encryptedData);
    const iv = data.slice(0, 16);
    const ciphertext = data.slice(16);

    const plaintextWithMaybePadding = await crypto.subtle.decrypt(
      { name: 'AES-CBC', iv },
      aesKey,
      ciphertext
    );

    const plaintextBytes = new Uint8Array(plaintextWithMaybePadding);
    
    // ✅ Check if WebCrypto already removed padding
    // If decrypted length < ciphertext length, padding was auto-removed
    if (plaintextBytes.length < ciphertext.length) {
      const result = new TextDecoder().decode(plaintextBytes);
      return result;
    }

    // Padding still present, remove manually
    const unpadded = this.removePKCS7Padding(plaintextBytes);
    const result = new TextDecoder().decode(unpadded);
    return result;
    
  } catch (error) {
    console.error('[CBC Decrypt] ❌ Error:', error.message);
    throw new Error('PADDING_ERROR');
  }
}

  // ============================================
  // PKCS#7 PADDING
  // ============================================

  addPKCS7Padding(data, blockSize) {
    const padding = blockSize - (data.length % blockSize);
    const padded = new Uint8Array(data.length + padding);
    padded.set(data);
    
    // Fill padding bytes
    for (let i = data.length; i < padded.length; i++) {
      padded[i] = padding;
    }
    
    return padded;
  }

  removePKCS7Padding(data) {
    if (data.length === 0) {
      console.error('[PKCS7] Empty data');
      throw new Error('PADDING_ERROR: Empty data');
    }
    
    const padding = data[data.length - 1];
    
    if (padding < 1 || padding > 16) {
      console.error(`[PKCS7] Invalid padding value: ${padding}`);
      throw new Error('PADDING_ERROR: Invalid padding value');
    }
    
    if (data.length < padding) {
      console.error(`[PKCS7] Data too short: ${data.length} < ${padding}`);
      throw new Error('PADDING_ERROR: Data too short');
    }
    
    // Verify all padding bytes
    for (let i = data.length - padding; i < data.length; i++) {
      if (data[i] !== padding) {
        console.error(`[PKCS7] Incorrect padding at position ${i}: expected ${padding}, got ${data[i]}`);
        throw new Error('PADDING_ERROR: Incorrect padding bytes');
      }
    }
    
    return data.slice(0, data.length - padding);
  }

  // ============================================
  // UNIFIED API
  // ============================================

  async encrypt(aesKey, plaintext, mode = 'GCM') {
    if (mode === 'CBC') {
      console.warn('⚠️ Using CBC mode - vulnerable to padding oracle attack!');
      if (!this.aesKeyCBC) {
        throw new Error('CBC key not derived. Call deriveAESKey() first.');
      }
      return await this.encryptCBC(this.aesKeyCBC, plaintext);
    } else {
      return await this.encryptGCM(aesKey, plaintext);
    }
  }

  async decrypt(aesKey, encryptedData, mode = 'GCM') {
    if (mode === 'CBC') {
      console.warn('⚠️ Using CBC mode - vulnerable to padding oracle attack!');
      if (!this.aesKeyCBC) {
        throw new Error('CBC key not derived. Call deriveAESKey() first.');
      }
      return await this.decryptCBC(this.aesKeyCBC, encryptedData);
    } else {
      return await this.decryptGCM(aesKey, encryptedData);
    }
  }
}