import { KeyExchange } from './keyExchange.js';
import { SecureRandom } from './secureRandom.js';

export class ECDH_2 extends KeyExchange {
  constructor(customParams = null) {
    super("ECDH-P256");
    
    if (customParams) {
      this.p = BigInt(customParams.p);
      this.a = BigInt(customParams.a);
      this.b = BigInt(customParams.b);
      this.Gx = BigInt(customParams.Gx);
      this.Gy = BigInt(customParams.Gy);
      this.order = BigInt(customParams.order);
    } else {
      // P-256 (secp256r1) parameters
      this.p = 115792089210356248762697446949407573530086143415290314195533631308867097853951n;
      this.a = -3n;
      this.b = 41058363725152142129326129780047268409114441015993725554835256314039467401291n;
      this.Gx = 48439561293906451759052585252797914202762949526041747995844080717082404635286n;
      this.Gy = 36134250956749795798585127919587881956611106672985015071877198253568414405109n;
      this.order = 115792089210356248762697446949407573529996955224135760342422259061068512044369n;
      console.log("ECDH initialized with default P-256 parameters");
    }

    this.validateCurveParameters();
  }

  validateCurveParameters() {
    try {
      const left = (this.Gy * this.Gy) % this.p;
      const right = (this.Gx * this.Gx * this.Gx + this.a * this.Gx + this.b) % this.p;
      
      if (left !== right) {
        throw new Error('Generator point is not on the curve');
      }
      
      console.log('✓ P-256 curve parameters validation passed');
      return true;
    } catch (error) {
      console.error('Curve parameters validation failed:', error);
      throw new Error('Invalid curve parameters: ' + error.message);
    }
  }

  modInverse(a, m) {
    a = BigInt(a);
    m = BigInt(m);
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
    
    const px = BigInt(P.x);
    const py = BigInt(P.y);
    const qx = BigInt(Q.x);
    const qy = BigInt(Q.y);
    
    if (px === qx && (py + qy) % this.p === 0n) {
      return null;
    }
    
    let lambda;
    if (px === qx && py === qy) {
      lambda = (3n * px * px + this.a) * this.modInverse(2n * py, this.p) % this.p;
    } else {
      lambda = (qy - py) * this.modInverse((qx - px + this.p) % this.p, this.p) % this.p;
    }
    
    const Rx = (lambda * lambda - px - qx) % this.p;
    const Ry = (lambda * (px - Rx) - py) % this.p;
    
    return {
      x: (Rx % this.p + this.p) % this.p,
      y: (Ry % this.p + this.p) % this.p
    };
  }

  scalarMult(P, n) {
    if (!P) return null;
    n = BigInt(n);
    if (n === 0n) return null;
    if (n === 1n) return { x: BigInt(P.x), y: BigInt(P.y) };
    
    let Q = { x: BigInt(P.x), y: BigInt(P.y) };
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

  generatePrivateKey() {
    return SecureRandom.generatePrivateKey(this.order, 256); // ✅ 256-bit
  }

  generatePublicKey(privateKey) {
    const privKey = BigInt(privateKey);
    const G = { x: this.Gx, y: this.Gy };
    return this.scalarMult(G, privKey);
  }

  computeSharedSecret(privateKey, publicKey) {
    const privKey = BigInt(privateKey);
    
    let pubKey;
    if (typeof publicKey.x === 'string') {
      pubKey = {
        x: BigInt(publicKey.x),
        y: BigInt(publicKey.y)
      };
    } else {
      pubKey = {
        x: BigInt(publicKey.x),
        y: BigInt(publicKey.y)
      };
    }
    
    const sharedPoint = this.scalarMult(pubKey, privKey);
    return sharedPoint ? sharedPoint.x : null;
  }

  serializePublicKey(publicKey) {
    return {
      x: BigInt(publicKey.x).toString(),
      y: BigInt(publicKey.y).toString()
    };
  }

  deserializePublicKey(data) {
    return {
      x: BigInt(data.x),
      y: BigInt(data.y)
    };
  }

  validatePublicKey(publicKey) {
    try {
      const x = BigInt(publicKey.x);
      const y = BigInt(publicKey.y);
      
      const left = (y * y) % this.p;
      const right = (x * x * x + this.a * x + this.b) % this.p;
      
      return left === right;
    } catch (e) {
      console.error('ECDH validatePublicKey error:', e);
      return false;
    }
  }

  getKeySize() {
    return 256; // ✅ FIXED: 256 for P-256
  }

  getParameters() {
    return {
      algorithm: this.algorithmName,
      curve: "P-256", // ✅ FIXED
      p: this.p.toString(),
      a: this.a.toString(),
      b: this.b.toString(),
      G: {
        x: this.Gx.toString(),
        y: this.Gy.toString()
      },
      order: this.order.toString(),
      keySize: this.getKeySize()
    };
  }
}