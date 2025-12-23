// ============================================
// File: src/crypto/ecdsaSignature.js
// ============================================

import { SignatureBase } from './signatureBase.js';
import { SecureRandom } from './secureRandom.js';

export class ECDSASignature extends SignatureBase {
  constructor(curveParams = null) {
    super("ECDSA-P192");
    
    // Use curve parameters from ECDH or defaults
    if (curveParams) {
      this.p = BigInt(curveParams.p);
      this.a = BigInt(curveParams.a);
      this.b = BigInt(curveParams.b);
      this.Gx = BigInt(curveParams.Gx);
      this.Gy = BigInt(curveParams.Gy);
      this.order = BigInt(curveParams.order);
    } else {
      // P-192 default parameters
      this.p = 6277101735386680763835789423207666416083908700390324961279n;
      this.a = -3n;
      this.b = 2455155546008943817740293915197451784769108058161191238065n;
      this.Gx = 3289624317623424368845348028842487418520868978772050262753n;
      this.Gy = 5673242899673324591834582889556471730778853907191064256384n;
      this.order = 6277101735386680763835789423176059013767194773182842284081n;
    }
    
    console.log('ECDSA Signature initialized for P-192 curve');
  }

  // Generate signature key pair (different from ECDH keys)
  generateSignatureKeyPair() {
    // Use deterministic key for demo, crypto.getRandomValues for production
    const privateKey = this.generatePrivateKey();
    const publicKey = this.generatePublicKey(privateKey);
    
    return {
      privateKey: privateKey.toString(),
      publicKey: this.serializePublicKey(publicKey)
    };
  }

  generatePrivateKey() {
    return SecureRandom.generatePrivateKey(this.order);
  }

  generatePublicKey(privateKey) {
    const G = { x: this.Gx, y: this.Gy };
    return this.scalarMult(G, privateKey);
  }

  // Hash message using SHA-256
  async hashMessage(message) {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = new Uint8Array(hashBuffer);
    
    // Convert to BigInt
    let hash = 0n;
    for (let i = 0; i < hashArray.length; i++) {
      hash = (hash << 8n) + BigInt(hashArray[i]);
    }
    
    return hash % this.order;
  }

  // Sign message with ECDSA
  async signMessage(message, privateKey) {
    const messageHash = await this.hashMessage(message);
    const privKey = BigInt(privateKey);
    
    // Generate deterministic k for demo
    let k = await SecureRandom.generateSecureK(messageHash, privKey, this.order);
    
    // Calculate r = (k * G).x mod order
    const G = { x: this.Gx, y: this.Gy };
    const kG = this.scalarMult(G, k);
    const r = kG.x % this.order;
    
    if (r === 0n) {
      throw new Error('Invalid signature generation (r = 0)');
    }
    
    // Calculate s = k^(-1) * (hash + r * privateKey) mod order
    const kInv = this.modInverse(k, this.order);
    const s = (kInv * (messageHash + r * privKey)) % this.order;
    
    if (s === 0n) {
      throw new Error('Invalid signature generation (s = 0)');
    }
    
    return {
      r: r.toString(),
      s: s.toString(),
      messageHash: messageHash.toString(),
      algorithm: this.algorithmName
    };
  }

  // Verify ECDSA signature
  async verifySignature(message, signature, publicKey) {
    try {
      const messageHash = await this.hashMessage(message);
      const r = BigInt(signature.r);
      const s = BigInt(signature.s);
      const pubKey = this.deserializePublicKey(publicKey);
      
      // Verify r and s are in valid range
      if (r <= 0n || r >= this.order || s <= 0n || s >= this.order) {
        return false;
      }
      
      // Calculate w = s^(-1) mod order
      const w = this.modInverse(s, this.order);
      
      // Calculate u1 = hash * w mod order
      const u1 = (messageHash * w) % this.order;
      
      // Calculate u2 = r * w mod order
      const u2 = (r * w) % this.order;
      
      // Calculate point = u1 * G + u2 * publicKey
      const G = { x: this.Gx, y: this.Gy };
      const point1 = this.scalarMult(G, u1);
      const point2 = this.scalarMult(pubKey, u2);
      const point = this.pointAdd(point1, point2);
      
      if (!point) return false;
      
      // Verify r == point.x mod order
      const v = point.x % this.order;
      return v === r;
      
    } catch (error) {
      console.error('ECDSA signature verification error:', error);
      return false;
    }
  }

  serializeSignature(signature) {
    return {
      r: signature.r,
      s: signature.s,
      messageHash: signature.messageHash,
      algorithm: signature.algorithm
    };
  }

  deserializeSignature(data) {
    return {
      r: data.r,
      s: data.s,
      messageHash: data.messageHash,
      algorithm: data.algorithm
    };
  }

  serializePublicKey(publicKey) {
    return {
      x: publicKey.x.toString(),
      y: publicKey.y.toString()
    };
  }

  deserializePublicKey(data) {
    return {
      x: BigInt(data.x),
      y: BigInt(data.y)
    };
  }

  validateSignature(signature) {
    return signature.r && signature.s && signature.algorithm === this.algorithmName;
  }

  getSignatureSize() {
    return 384; // 192 * 2 bits for r and s
  }

  getParameters() {
    return {
      algorithm: this.algorithmName,
      curve: "P-192",
      signatureSize: this.getSignatureSize(),
      hashAlgorithm: "SHA-256",
      p: this.p.toString(),
      a: this.a.toString(),
      b: this.b.toString(),
      G: {
        x: this.Gx.toString(),
        y: this.Gy.toString()
      },
      order: this.order.toString()
    };
  }

  // Helper methods (same as ECDH implementation)
  modInverse(a, m) {
    a = (a % m + m) % m;
    let [old_r, r] = [a, m];
    let [old_s, s] = [1n, 0n];

    while (r !== 0n) {
      const quotient = old_r / r;
      [old_r, r] = [r, old_r - quotient * r];
      [old_s, s] = [s, old_s - quotient * s];
    }

    return (old_s % m + m) % m;
  }

  pointAdd(P, Q) {
    if (!P) return Q;
    if (!Q) return P;

    if (P.x === Q.x && (P.y + Q.y) % this.p === 0n) {
      return null;
    }

    let lambda;
    if (P.x === Q.x && P.y === Q.y) {
      lambda = (3n * P.x * P.x + this.a) * this.modInverse(2n * P.y, this.p) % this.p;
    } else {
      lambda = (Q.y - P.y) * this.modInverse((Q.x - P.x + this.p) % this.p, this.p) % this.p;
    }

    const Rx = (lambda * lambda - P.x - Q.x) % this.p;
    const Ry = (lambda * (P.x - Rx) - P.y) % this.p;

    return {
      x: (Rx % this.p + this.p) % this.p,
      y: (Ry % this.p + this.p) % this.p
    };
  }

  scalarMult(P, n) {
    let Q = P;
    let R = null;
    let k = n;

    while (k > 0n) {
      if (k % 2n === 1n) {
        R = this.pointAdd(R, Q);
      }
      Q = this.pointAdd(Q, Q);
      k = k / 2n;
    }

    return R;
  }
}