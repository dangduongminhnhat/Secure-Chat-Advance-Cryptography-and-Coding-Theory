import { KeyExchange } from './keyExchange.js';

export class ECDH extends KeyExchange {
  constructor(customParams = null) {
    super("ECDH-P192");
    
    if (customParams) {
      this.p = BigInt(customParams.p);
      this.a = BigInt(customParams.a);
      this.b = BigInt(customParams.b);
      this.Gx = BigInt(customParams.Gx);
      this.Gy = BigInt(customParams.Gy);
      this.order = BigInt(customParams.order);
    } else {
      this.p = 6277101735386680763835789423207666416083908700390324961279n;
      this.a = -3n;
      this.b = 2455155546008943817740293915197451784769108058161191238065n;
      this.Gx = 3289624317623424368845348028842487418520868978772050262753n;
      this.Gy = 5673242899673324591834582889556471730778853907191064256384n;
      this.order = 6277101735386680763835789423176059013767194773182842284081n;
      console.log("ECDH initialized with default P-192 parameters");
    }
  }

  // Modular inverse using Extended Euclidean Algorithm
  modInverse(a, m) {
    // ✅ Ensure BigInt
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

  // Point addition on elliptic curve
  pointAdd(P, Q) {
    if (!P) return Q;
    if (!Q) return P;
    
    // ✅ Ensure BigInt
    const px = BigInt(P.x);
    const py = BigInt(P.y);
    const qx = BigInt(Q.x);
    const qy = BigInt(Q.y);
    
    if (px === qx && (py + qy) % this.p === 0n) {
      return null;
    }
    
    let lambda;
    if (px === qx && py === qy) {
      // Point doubling
      lambda = (3n * px * px + this.a) * this.modInverse(2n * py, this.p) % this.p;
    } else {
      // Point addition
      lambda = (qy - py) * this.modInverse((qx - px + this.p) % this.p, this.p) % this.p;
    }
    
    const Rx = (lambda * lambda - px - qx) % this.p;
    const Ry = (lambda * (px - Rx) - py) % this.p;
    
    return {
      x: (Rx % this.p + this.p) % this.p,
      y: (Ry % this.p + this.p) % this.p
    };
  }

  // Scalar multiplication using double-and-add
  scalarMult(P, n) {
    if (!P) return null;
    
    // ✅ Ensure BigInt
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

  // Implementation of abstract methods
  generatePrivateKey() {
    // Fixed private key for demo (in production, use secure random)
    return 1853800949957290197646800317665265411650411285239850323051n;
  }

  generatePublicKey(privateKey) {
    // ✅ Ensure BigInt
    const privKey = BigInt(privateKey);
    const G = { x: this.Gx, y: this.Gy };
    return this.scalarMult(G, privKey);
  }

  computeSharedSecret(privateKey, publicKey) {
    // ✅ Ensure BigInt
    const privKey = BigInt(privateKey);
    
    // ✅ Deserialize publicKey if needed
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
    // ✅ Ensure string output
    return {
      x: BigInt(publicKey.x).toString(),
      y: BigInt(publicKey.y).toString()
    };
  }

  deserializePublicKey(data) {
    // ✅ Convert string to BigInt
    return {
      x: BigInt(data.x),
      y: BigInt(data.y)
    };
  }

  validatePublicKey(publicKey) {
    try {
      // ✅ Ensure BigInt
      const x = BigInt(publicKey.x);
      const y = BigInt(publicKey.y);
      
      // Check if point is on the curve: y^2 = x^3 + ax + b (mod p)
      const left = (y * y) % this.p;
      const right = (x * x * x + this.a * x + this.b) % this.p;
      
      return left === right;
    } catch (e) {
      console.error('ECDH validatePublicKey error:', e);
      return false;
    }
  }

  getKeySize() {
    return 192;
  }

  getParameters() {
    return {
      algorithm: this.algorithmName,
      curve: "P-192",
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