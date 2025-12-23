import { SignatureBase } from './signatureBase.js';
import { SecureRandom } from './secureRandom.js';

export class ECDSABug extends SignatureBase {
  constructor(curveParams = null) {
    super("ECDSA-P256");
    
    if (curveParams) {
      this.p = BigInt(curveParams.p);
      this.a = BigInt(curveParams.a);
      this.b = BigInt(curveParams.b);
      this.Gx = BigInt(curveParams.Gx);
      this.Gy = BigInt(curveParams.Gy);
      this.order = BigInt(curveParams.order);
    } else {
      // P-256 parameters
      this.p = 115792089210356248762697446949407573530086143415290314195533631308867097853951n;
      this.a = -3n;
      this.b = 41058363725152142129326129780047268409114441015993725554835256314039467401291n;
      this.Gx = 48439561293906451759052585252797914202762949526041747995844080717082404635286n;
      this.Gy = 36134250956749795798585127919587881956611106672985015071877198253568414405109n;
      this.order = 115792089210356248762697446949407573529996955224135760342422259061068512044369n;
    }
    
    console.log('ECDSA Signature initialized for P-256 curve');
  }

  generateSignatureKeyPair() {
    const privateKey = this.generatePrivateKey();
    const publicKey = this.generatePublicKey(privateKey);
    
    return {
      privateKey: privateKey.toString(),
      publicKey: this.serializePublicKey(publicKey)
    };
  }

  generatePrivateKey() {
    // ✅ Use SecureRandom for production
    // return SecureRandom.generatePrivateKey(this.order, 256);
    
    // For testing only (deterministic):
    return 106929651395809795849503103048857480321800635263136332109986298710169199322776n;
  }

  generatePublicKey(privateKey) {
    const G = { x: this.Gx, y: this.Gy };
    return this.scalarMult(G, privateKey);
  }

  // ✅ FIXED: Use SHA-256 (matching client)
  async hashMessage(message) {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data); // ✅ SHA-256
    const hashArray = new Uint8Array(hashBuffer);
    
    let hash = 0n;
    for (let i = 0; i < hashArray.length; i++) {
      hash = (hash << 8n) + BigInt(hashArray[i]);
    }
    
    return hash % this.order;
  }

  async signMessage(message, privateKey) {
    const messageHash = await this.hashMessage(message);
    const privKey = BigInt(privateKey);
    
    // ✅ Use SecureRandom.generateSecureKSHA1 (SHA-1 version)
    let k = await SecureRandom.generateSecureKSHA1(messageHash, privKey, this.order);
    
    const G = { x: this.Gx, y: this.Gy };
    const kG = this.scalarMult(G, k);
    const r = kG.x % this.order;
    
    if (r === 0n) {
      throw new Error('Invalid signature generation (r = 0)');
    }
    
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

  async verifySignature(message, signature, publicKey) {
    try {
      const messageHash = await this.hashMessage(message);
      const r = BigInt(signature.r);
      const s = BigInt(signature.s);
      const pubKey = this.deserializePublicKey(publicKey);
      
      if (r <= 0n || r >= this.order || s <= 0n || s >= this.order) {
        return false;
      }
      
      const w = this.modInverse(s, this.order);
      const u1 = (messageHash * w) % this.order;
      const u2 = (r * w) % this.order;
      
      const G = { x: this.Gx, y: this.Gy };
      const point1 = this.scalarMult(G, u1);
      const point2 = this.scalarMult(pubKey, u2);
      const point = this.pointAdd(point1, point2);
      
      if (!point) return false;
      
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
    return data;
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
    return 512; // ✅ FIXED: 256 * 2 = 512 bits
  }

  getParameters() {
    return {
      algorithm: this.algorithmName,
      curve: "P-256", // ✅ FIXED
      signatureSize: this.getSignatureSize(),
      hashAlgorithm: "SHA-256", // ✅ FIXED
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

  // Helper methods
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