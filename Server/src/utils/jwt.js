export class JWTManager {
  constructor(secretKey) {
    this.secretKey = secretKey;
    this.algorithm = "HS256";
    this.issuer = "SecureChat";
    this.defaultExpiry = 300; // 5 phút
  }

  // Base64 URL encode
  base64UrlEncode(data) {
    return btoa(typeof data === "string" ? data : JSON.stringify(data))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
  }

  // Base64 URL decode
  base64UrlDecode(data) {
    const padding = "=".repeat((4 - data.length % 4) % 4);
    const base64 = data.replace(/-/g, "+").replace(/_/g, "/") + padding;
    return atob(base64);
  }

  // HMAC SHA-256 signature
  async createSignature(data) {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(this.secretKey);
    const messageData = encoder.encode(data);

    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyData,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const signature = await crypto.subtle.sign("HMAC", cryptoKey, messageData);
    return this.base64UrlEncode(String.fromCharCode(...new Uint8Array(signature)));
  }

  // 🔒 Encrypt sensitive data in JWT payload
  async encryptPayload(payload, encryptionKey) {
    const encoder = new TextEncoder();
    const data = encoder.encode(JSON.stringify(payload));
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const key = await crypto.subtle.importKey(
      "raw",
      encryptionKey,
      { name: "AES-GCM" },
      false,
      ["encrypt"]
    );

    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      data
    );

    const result = new Uint8Array(iv.length + encrypted.byteLength);
    result.set(iv);
    result.set(new Uint8Array(encrypted), iv.length);

    return this.base64UrlEncode(String.fromCharCode(...result));
  }

  // 🔓 Decrypt sensitive data from JWT payload
  async decryptPayload(encryptedData, encryptionKey) {
    const data = new Uint8Array(
      [...this.base64UrlDecode(encryptedData)].map((c) => c.charCodeAt(0))
    );

    const iv = data.slice(0, 12);
    const encrypted = data.slice(12);

    const key = await crypto.subtle.importKey(
      "raw",
      encryptionKey,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      encrypted
    );

    const decoder = new TextDecoder();
    return JSON.parse(decoder.decode(decrypted));
  }

  // Create JWT token
  async createToken(payload, expiresIn = this.defaultExpiry) {
    const now = Math.floor(Date.now() / 1000);

    const header = {
      alg: this.algorithm,
      typ: "JWT"
    };

    const jwtPayload = {
      iss: this.issuer,
      iat: now,
      exp: now + expiresIn,
      ...payload
    };

    const encodedHeader = this.base64UrlEncode(header);
    const encodedPayload = this.base64UrlEncode(jwtPayload);
    const data = `${encodedHeader}.${encodedPayload}`;
    const signature = await this.createSignature(data);

    return `${data}.${signature}`;
  }

  // Verify and decode JWT token
  async verifyToken(token) {
    try {
      const parts = token.split(".");
      if (parts.length !== 3) {
        throw new Error("Invalid token format");
      }

      const [encodedHeader, encodedPayload, signature] = parts;
      const data = `${encodedHeader}.${encodedPayload}`;
      const expectedSignature = await this.createSignature(data);

      if (signature !== expectedSignature) {
        throw new Error("Invalid signature");
      }

      const payload = JSON.parse(this.base64UrlDecode(encodedPayload));
      const now = Math.floor(Date.now() / 1000);

      if (payload.exp && payload.exp < now) {
        throw new Error("Token expired");
      }

      return payload;
    } catch (error) {
      throw new Error(`Token verification failed: ${error.message}`);
    }
  }
}