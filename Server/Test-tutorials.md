# 🔮 FUTURE PLAN & EXTENSIBILITY GUIDE - Test.py v2.1

## 📋 TABLE OF CONTENTS

1. [Current Implementation](#current-implementation)
2. [Adding New Algorithms - Step by Step](#adding-new-algorithms)
3. [Algorithm Roadmap](#algorithm-roadmap)
4. [RSA-2048 Implementation Example](#rsa-implementation)
5. [Ed25519 Implementation Example](#ed25519-implementation)
6. [Post-Quantum Algorithms](#post-quantum)
7. [Testing Best Practices](#testing-best-practices)
8. [Troubleshooting Guide](#troubleshooting)

---

## 📊 CURRENT IMPLEMENTATION

### **Supported Algorithms (v2.1)**

```
✅ ECDH P-192 + ECDSA P-192
   - Key Exchange: Elliptic Curve Diffie-Hellman
   - Signature: ECDSA with SHA-256
   - Security Level: ~96 bits
   - Status: FULLY IMPLEMENTED
```

### **Framework Architecture**

```
┌─────────────────────────────────────────────────────┐
│           ABSTRACT BASE CLASSES                     │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━    │
│  • KeyExchangeAlgorithm                             │
│    - get_curve_parameters()                         │
│    - generate_keypair()                             │
│    - compute_shared_secret()                        │
│    - validate_point()                               │
│                                                     │
│  • SignatureAlgorithm                               │
│    - generate_keypair()                             │
│    - sign_message()                                 │
│    - verify_signature()                             │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│           ALGORITHM FACTORY                         │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━    │
│  KEY_EXCHANGE_ALGORITHMS = {                        │
│    'ecdh': ECDHKeyExchange,                         │
│    # 'rsa': RSAKeyExchange,        # TODO           │
│    # 'dh': DHKeyExchange,          # TODO           │
│    # 'ed25519': Ed25519KeyExchange # TODO           │
│  }                                                  │
│                                                     │
│  SIGNATURE_ALGORITHMS = {                           │
│    'ecdh': ECDSASignature,                          │
│    # 'rsa': RSAPSSSignature,       # TODO           │
│    # 'dh': DSASignature,           # TODO           │
│    # 'ed25519': Ed25519Signature   # TODO           │
│  }                                                  │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│           AUTOMATIC TESTING                         │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━    │
│  Phase 1: Local Crypto Tests                        │
│  Phase 2: Server Integration Tests                  │
│  Phase 3: Comprehensive Workflow Tests              │
└─────────────────────────────────────────────────────┘
```

---

## 🚀 ADDING NEW ALGORITHMS - STEP BY STEP

### **Step 1: Implement KeyExchange Class**

```python
class NewAlgoKeyExchange(KeyExchangeAlgorithm):
    """
    Template for new key exchange algorithm
    """
    def __init__(self):
        super().__init__("NewAlgo-Name")
        # Initialize algorithm-specific parameters
        self.param1 = ...
        self.param2 = ...

    def get_curve_parameters(self) -> Dict[str, Any]:
        """
        Return algorithm parameters to send to server
        Example: {"keySize": 2048, "prime": "..."}
        """
        return {
            "param1": str(self.param1),
            "param2": str(self.param2),
        }

    def generate_keypair(self) -> Tuple[Any, Dict[str, Any]]:
        """
        Generate private and public keys
        Returns: (private_key, public_key_dict)

        Example:
        private_key = secrets.randbits(256)
        public_key = {"n": "...", "e": "..."}
        return private_key, public_key
        """
        # TODO: Implement key generation
        raise NotImplementedError()

    def compute_shared_secret(self, private_key: Any,
                              server_public_key: Dict[str, Any]) -> int:
        """
        Compute shared secret from server's public key
        Returns: shared_secret (as integer)

        Must match server's computation:
        client_secret = server_pub × client_priv
        server_secret = client_pub × server_priv
        → client_secret == server_secret
        """
        # TODO: Implement shared secret computation
        raise NotImplementedError()

    def validate_point(self, point: Any) -> bool:
        """
        Validate that point/key is valid

        Examples:
        - EC: Check point is on curve
        - RSA: Check modulus size
        - DH: Check is in valid group
        """
        # TODO: Implement validation
        return True
```

### **Step 2: Implement Signature Class**

```python
class NewAlgoSignature(SignatureAlgorithm):
    """
    Template for new signature algorithm
    """
    def __init__(self):
        super().__init__("NewAlgo-Signature")
        # Initialize signature parameters
        self.hash_algo = "SHA-256"

    def generate_keypair(self) -> Tuple[Any, Dict[str, Any]]:
        """
        Generate EPHEMERAL signature keypair
        IMPORTANT: Should be called for EACH signature operation

        Returns: (private_key, public_key_dict)
        """
        # TODO: Implement ephemeral keypair generation
        raise NotImplementedError()

    def sign_message(self, message: str, private_key: Any) -> Dict[str, Any]:
        """
        Sign a message with private key

        Returns: signature_dict with at minimum:
        {
            "signature": "...",  # The actual signature
            "algorithm": self.name,
            # Add algorithm-specific fields
        }
        """
        # TODO: Implement signing
        raise NotImplementedError()

    def verify_signature(self, message: str,
                        signature: Dict[str, Any],
                        public_key: Dict[str, Any]) -> bool:
        """
        Verify signature with public key

        Returns: True if valid, False otherwise
        """
        # TODO: Implement verification
        raise NotImplementedError()
```

### **Step 3: Register in Factory**

```python
class AlgorithmFactory:
    KEY_EXCHANGE_ALGORITHMS = {
        'ecdh': ECDHKeyExchange,
        'newalgo': NewAlgoKeyExchange,  # ✅ ADD HERE
    }

    SIGNATURE_ALGORITHMS = {
        'ecdh': ECDSASignature,
        'newalgo': NewAlgoSignature,    # ✅ ADD HERE
    }
```

### **Step 4: Add Test Case**

```python
def run_comprehensive_test(self):
    # ... existing code ...

    test_cases = [
        ('group-1', 'ecdh'),
        ('group-2', 'newalgo'),  # ✅ ADD TEST CASE
    ]
```

**That's it!** The framework automatically:

- Tests local crypto implementation
- Tests server integration
- Verifies signatures
- Tests full message workflow

---

## 📅 ALGORITHM ROADMAP

### **Phase 1: Current (v2.1) ✅**

```
Algorithm: ECDH P-192 + ECDSA P-192
Status: FULLY IMPLEMENTED
Security: ~96-bit (acceptable for educational/demo)
Dependencies: Pure Python (hashlib, secrets)
```

### **Phase 2: RSA Support (v2.2) 🔨**

**Target Date:** Q1 2024

**Algorithms:**

- RSA-2048 Key Exchange (RSA-KEM)
- RSA-PSS-2048 Signatures

**Dependencies:**

```bash
pip install cryptography
```

**Implementation Status:**

- [ ] RSA key generation (2048-bit)
- [ ] RSA-KEM shared secret
- [ ] RSA-PSS signature generation
- [ ] RSA-PSS verification
- [ ] Integration tests

**Complexity:** Medium (use `cryptography` library)

### **Phase 3: Enhanced ECC (v2.3) 🔮**

**Target Date:** Q2 2024

**Algorithms:**

- ECDH P-256 (stronger than P-192)
- ECDSA P-256

**Dependencies:**

```bash
pip install cryptography
```

**Benefits:**

- 128-bit security level
- NIST recommended
- Better resistance to attacks

### **Phase 4: Modern Crypto (v3.0) 🚀**

**Target Date:** Q3 2024

**Algorithms:**

- **Ed25519** (Curve25519 ECDH + EdDSA)
  - Faster than ECDSA
  - Simpler implementation
  - Better security properties

**Dependencies:**

```bash
pip install PyNaCl
```

**Why Ed25519?**

- Constant-time operations (side-channel resistant)
- No random nonce needed (deterministic signatures)
- Excellent performance
- Industry standard (SSH, TLS 1.3)

### **Phase 5: Classical DH (v3.1) 🔮**

**Target Date:** Q4 2024

**Algorithms:**

- Diffie-Hellman 2048/3072
- DSA Signatures

**Use Case:**

- Legacy system compatibility
- Educational purposes

### **Phase 6: Post-Quantum (v4.0) 🔬**

**Target Date:** 2025

**Algorithms:**

- **CRYSTALS-Kyber** (key exchange)
  - NIST PQC selected algorithm
  - Lattice-based
- **CRYSTALS-Dilithium** (signatures)
  - NIST PQC selected algorithm
  - Lattice-based

**Dependencies:**

```bash
pip install pqcrypto  # When available
```

**Challenges:**

- Larger key sizes
- Performance overhead
- Library maturity

---

## 💻 RSA-2048 IMPLEMENTATION EXAMPLE

### **Complete Implementation**

```python
#!/usr/bin/env python3
"""
RSA-2048 Implementation for Test Framework
Dependencies: pip install cryptography
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import hashlib
import json


class RSAKeyExchange(KeyExchangeAlgorithm):
    """
    RSA-2048 Key Exchange using RSA-KEM approach
    """
    def __init__(self, key_size=2048):
        super().__init__(f"RSA-{key_size}")
        self.key_size = key_size
        self.public_exponent = 65537

    def get_curve_parameters(self) -> Dict[str, Any]:
        return {
            "keySize": self.key_size,
            "publicExponent": str(self.public_exponent),
            "padding": "OAEP",
            "hashFunction": "SHA-256",
        }

    def generate_keypair(self) -> Tuple[Any, Dict[str, Any]]:
        """Generate RSA keypair"""
        # Generate RSA key
        private_key = rsa.generate_private_key(
            public_exponent=self.public_exponent,
            key_size=self.key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Extract public key parameters
        public_numbers = public_key.public_numbers()

        # Serialize public key for server
        public_key_dict = {
            'n': self._int_to_base64url(public_numbers.n),
            'e': self._int_to_base64url(public_numbers.e),
            'keySize': self.key_size,
        }

        return private_key, public_key_dict

    def compute_shared_secret(self, private_key: Any,
                              server_public_key: Dict[str, Any]) -> int:
        """
        Compute shared secret using RSA-KEM approach

        In RSA-KEM:
        1. Client generates random secret
        2. Client encrypts secret with server's public key
        3. Client sends encrypted secret to server
        4. Server decrypts with private key
        5. Both have same secret

        For testing (simplified):
        We combine both moduli to create shared secret
        """
        # Get client's public key
        client_public = private_key.public_key()
        client_n = client_public.public_numbers().n

        # Get server's modulus
        server_n = self._base64url_to_int(server_public_key['n'])

        # Combine moduli (simplified approach)
        combined = client_n ^ server_n  # XOR

        # Hash to get fixed-size secret
        hash_bytes = hashlib.sha256(str(combined).encode()).digest()
        shared_secret = int.from_bytes(hash_bytes, 'big')

        return shared_secret

    def validate_point(self, point: Any) -> bool:
        """Validate RSA public key"""
        # For RSA, we check the modulus size
        if isinstance(point, dict):
            try:
                n = self._base64url_to_int(point['n'])
                e = self._base64url_to_int(point['e'])

                # Check modulus bit length
                n_bits = n.bit_length()
                if abs(n_bits - self.key_size) > 1:
                    return False

                # Check standard exponent
                if e != self.public_exponent:
                    return False

                return True
            except:
                return False
        return False

    # Helper methods
    def _int_to_base64url(self, n: int) -> str:
        """Convert integer to base64url string"""
        # Convert to bytes
        byte_length = (n.bit_length() + 7) // 8
        n_bytes = n.to_bytes(byte_length, 'big')

        # Base64url encode
        import base64
        encoded = base64.urlsafe_b64encode(n_bytes).decode('ascii')
        return encoded.rstrip('=')  # Remove padding

    def _base64url_to_int(self, s: str) -> int:
        """Convert base64url string to integer"""
        import base64
        # Add padding
        padding = '=' * (4 - len(s) % 4)
        s_padded = s + padding

        # Decode
        n_bytes = base64.urlsafe_b64decode(s_padded)
        return int.from_bytes(n_bytes, 'big')


class RSAPSSSignature(SignatureAlgorithm):
    """
    RSA-PSS Signature (Probabilistic Signature Scheme)
    More secure than PKCS#1 v1.5
    """
    def __init__(self, key_size=2048):
        super().__init__(f"RSA-PSS-{key_size}")
        self.key_size = key_size
        self.salt_length = 32  # SHA-256 output length

    def generate_keypair(self) -> Tuple[Any, Dict[str, Any]]:
        """Generate EPHEMERAL RSA signature keypair"""
        # Generate fresh RSA key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Extract public key parameters
        public_numbers = public_key.public_numbers()

        public_key_dict = {
            'n': self._int_to_base64url(public_numbers.n),
            'e': self._int_to_base64url(public_numbers.e),
            'keySize': self.key_size,
        }

        return private_key, public_key_dict

    def sign_message(self, message: str, private_key: Any) -> Dict[str, Any]:
        """Sign message with RSA-PSS"""
        message_bytes = message.encode('utf-8')

        # Hash message
        message_hash = hashlib.sha256(message_bytes).hexdigest()

        # Sign with PSS padding
        signature_bytes = private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=self.salt_length
            ),
            hashes.SHA256()
        )

        # Convert to base64
        import base64
        signature_b64 = base64.b64encode(signature_bytes).decode('ascii')

        return {
            'signature': signature_b64,
            'messageHash': message_hash,
            'algorithm': self.name,
            'hashAlgorithm': 'SHA-256',
            'saltLength': self.salt_length,
        }

    def verify_signature(self, message: str,
                        signature: Dict[str, Any],
                        public_key_dict: Dict[str, Any]) -> bool:
        """Verify RSA-PSS signature"""
        try:
            # Reconstruct public key
            n = self._base64url_to_int(public_key_dict['n'])
            e = self._base64url_to_int(public_key_dict['e'])

            public_numbers = rsa.RSAPublicNumbers(e, n)
            public_key = public_numbers.public_key(default_backend())

            # Decode signature
            import base64
            signature_bytes = base64.b64decode(signature['signature'])

            message_bytes = message.encode('utf-8')

            # Verify
            public_key.verify(
                signature_bytes,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=self.salt_length
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            return False

    # Helper methods
    def _int_to_base64url(self, n: int) -> str:
        byte_length = (n.bit_length() + 7) // 8
        n_bytes = n.to_bytes(byte_length, 'big')
        import base64
        encoded = base64.urlsafe_b64encode(n_bytes).decode('ascii')
        return encoded.rstrip('=')

    def _base64url_to_int(self, s: str) -> int:
        import base64
        padding = '=' * (4 - len(s) % 4)
        s_padded = s + padding
        n_bytes = base64.urlsafe_b64decode(s_padded)
        return int.from_bytes(n_bytes, 'big')


# ═══════════════════════════════════════════════════════════════════
# REGISTER IN FACTORY
# ═══════════════════════════════════════════════════════════════════

class AlgorithmFactory:
    KEY_EXCHANGE_ALGORITHMS = {
        'ecdh': ECDHKeyExchange,
        'rsa': RSAKeyExchange,     # ✅ ADD THIS
    }

    SIGNATURE_ALGORITHMS = {
        'ecdh': ECDSASignature,
        'rsa': RSAPSSSignature,    # ✅ ADD THIS
    }
```

### **Testing RSA**

```python
def main():
    # ... existing code ...

    test_cases = [
        ('group-1', 'ecdh'),
        ('group-2', 'rsa'),   # ✅ Test RSA
    ]
```

---

## 🔐 ED25519 IMPLEMENTATION EXAMPLE

### **Complete Implementation**

```python
#!/usr/bin/env python3
"""
Ed25519 Implementation for Test Framework
Dependencies: pip install PyNaCl
"""

from nacl.public import PrivateKey, PublicKey, Box
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder
import hashlib


class Ed25519KeyExchange(KeyExchangeAlgorithm):
    """
    Curve25519 ECDH for key exchange
    """
    def __init__(self):
        super().__init__("Ed25519-KeyExchange")

    def get_curve_parameters(self) -> Dict[str, Any]:
        return {
            "curve": "Curve25519",
            "keySize": 256,
        }

    def generate_keypair(self) -> Tuple[PrivateKey, Dict[str, Any]]:
        """Generate Curve25519 keypair"""
        # Generate private key
        private_key = PrivateKey.generate()
        public_key = private_key.public_key

        # Serialize public key
        public_key_dict = {
            'key': public_key.encode(encoder=HexEncoder).decode('ascii'),
            'curve': 'Curve25519',
        }

        return private_key, public_key_dict

    def compute_shared_secret(self, private_key: PrivateKey,
                              server_public_key: Dict[str, Any]) -> int:
        """Compute shared secret using Curve25519"""
        # Decode server public key
        server_key_bytes = bytes.fromhex(server_public_key['key'])
        server_public = PublicKey(server_key_bytes)

        # Compute shared secret using Box
        box = Box(private_key, server_public)
        shared_key = box.shared_key()

        # Convert to integer
        shared_secret = int.from_bytes(shared_key, 'big')
        return shared_secret

    def validate_point(self, point: Any) -> bool:
        """Validate Curve25519 public key"""
        try:
            if isinstance(point, dict) and 'key' in point:
                key_bytes = bytes.fromhex(point['key'])
                # Try to construct PublicKey (will raise if invalid)
                PublicKey(key_bytes)
                return True
        except:
            return False
        return False


class Ed25519Signature(SignatureAlgorithm):
    """
    Ed25519 Pure Signature (EdDSA)
    """
    def __init__(self):
        super().__init__("Ed25519-Pure")

    def generate_keypair(self) -> Tuple[SigningKey, Dict[str, Any]]:
        """Generate EPHEMERAL Ed25519 signing keypair"""
        # Generate signing key
        signing_key = SigningKey.generate()
        verify_key = signing_key.verify_key

        # Serialize verify key
        public_key_dict = {
            'key': verify_key.encode(encoder=HexEncoder).decode('ascii'),
            'algorithm': 'Ed25519',
        }

        return signing_key, public_key_dict

    def sign_message(self, message: str, signing_key: SigningKey) -> Dict[str, Any]:
        """Sign message with Ed25519"""
        message_bytes = message.encode('utf-8')

        # Hash message
        message_hash = hashlib.sha256(message_bytes).hexdigest()

        # Sign (Ed25519 is deterministic - no random k needed!)
        signed = signing_key.sign(message_bytes)
        signature_hex = signed.signature.hex()

        return {
            'signature': signature_hex,
            'messageHash': message_hash,
            'algorithm': self.name,
        }

    def verify_signature(self, message: str,
                        signature: Dict[str, Any],
                        public_key_dict: Dict[str, Any]) -> bool:
        """Verify Ed25519 signature"""
        try:
            # Reconstruct verify key
            verify_key_bytes = bytes.fromhex(public_key_dict['key'])
            verify_key = VerifyKey(verify_key_bytes)

            # Decode signature
            signature_bytes = bytes.fromhex(signature['signature'])

            message_bytes = message.encode('utf-8')

            # Verify
            verify_key.verify(message_bytes, signature_bytes)
            return True
        except Exception as e:
            return False


# ═══════════════════════════════════════════════════════════════════
# REGISTER IN FACTORY
# ═══════════════════════════════════════════════════════════════════

class AlgorithmFactory:
    KEY_EXCHANGE_ALGORITHMS = {
        'ecdh': ECDHKeyExchange,
        'rsa': RSAKeyExchange,
        'ed25519': Ed25519KeyExchange,  # ✅ ADD THIS
    }

    SIGNATURE_ALGORITHMS = {
        'ecdh': ECDSASignature,
        'rsa': RSAPSSSignature,
        'ed25519': Ed25519Signature,    # ✅ ADD THIS
    }
```

---

## 🔬 POST-QUANTUM ALGORITHMS

### **CRYSTALS-Kyber (Key Exchange)**

**Status:** Future (waiting for stable library)

**Dependencies:**

```bash
# When available:
pip install liboqs-python
```

**Skeleton Implementation:**

```python
class KyberKeyExchange(KeyExchangeAlgorithm):
    """
    CRYSTALS-Kyber (NIST PQC selected)
    Lattice-based key encapsulation
    """
    def __init__(self, variant='kyber512'):
        super().__init__(f"Kyber-{variant}")
        self.variant = variant  # kyber512, kyber768, kyber1024

    def get_curve_parameters(self) -> Dict[str, Any]:
        return {
            "algorithm": "Kyber",
            "variant": self.variant,
            "securityLevel": self._get_security_level(),
        }

    def _get_security_level(self) -> int:
        levels = {
            'kyber512': 128,   # AES-128 equivalent
            'kyber768': 192,   # AES-192 equivalent
            'kyber1024': 256,  # AES-256 equivalent
        }
        return levels.get(self.variant, 128)

    def generate_keypair(self) -> Tuple[Any, Dict[str, Any]]:
        """Generate Kyber keypair"""
        # TODO: Implement with liboqs when available
        # from oqs import KeyEncapsulation
        # kem = KeyEncapsulation(self.variant)
        # public_key = kem.generate_keypair()
        # private_key = kem.export_secret_key()
        raise NotImplementedError("Waiting for stable library")

    def compute_shared_secret(self, private_key: Any,
                              server_public_key: Dict[str, Any]) -> int:
        """Compute shared secret using Kyber KEM"""
        # TODO: Implement
        # ciphertext, shared_secret = kem.encap_secret(server_public_key)
        # Send ciphertext to server
        # Server decaps to get same shared_secret
        raise NotImplementedError()

    def validate_point(self, point: Any) -> bool:
        # Kyber public keys have specific format
        # Check size matches variant
        return True
```

### **CRYSTALS-Dilithium (Signatures)**

```python
class DilithiumSignature(SignatureAlgorithm):
    """
    CRYSTALS-Dilithium (NIST PQC selected)
    Lattice-based digital signatures
    """
    def __init__(self, variant='dilithium2'):
        super().__init__(f"Dilithium-{variant}")
        self.variant = variant

    def generate_keypair(self) -> Tuple[Any, Dict[str, Any]]:
        """Generate EPHEMERAL Dilithium keypair"""
        # TODO: Implement with liboqs
        # from oqs import Signature
        # sig = Signature(self.variant)
        # public_key = sig.generate_keypair()
        raise NotImplementedError()

    def sign_message(self, message: str, private_key: Any) -> Dict[str, Any]:
        """Sign with Dilithium"""
        # TODO: Implement
        # signature = sig.sign(message.encode())
        raise NotImplementedError()

    def verify_signature(self, message: str,
                        signature: Dict[str, Any],
                        public_key: Dict[str, Any]) -> bool:
        """Verify Dilithium signature"""
        # TODO: Implement
        # is_valid = sig.verify(message.encode(), signature, public_key)
        raise NotImplementedError()
```

---

## ✅ TESTING BEST PRACTICES

### **1. Local Crypto Testing**

```python
def test_algorithm_crypto(self, algorithm: str):
    """
    Test crypto locally before server integration

    Tests:
    1. Key generation works
    2. Shared secret matches on both sides
    3. Signature generation works
    4. Signature verification works
    5. Encryption/decryption works
    """
    # Already implemented in framework!
    # Just call: tester.test_algorithm_crypto('rsa')
```

### **2. Server Integration Testing**

```python
def test_full_workflow(self, user_id: str, algorithm: str):
    """
    Test complete workflow with server

    Steps:
    1. Create session
    2. Verify server signature (MANDATORY)
    3. Key exchange with client signature
    4. Check server verified client signature
    5. Send encrypted messages with signatures
    6. Verify response signatures
    """
    # Already implemented!
    # Framework handles all checks automatically
```

### **3. Edge Case Testing**

Add these tests for robustness:

```python
def test_edge_cases(self):
    """Test edge cases and error handling"""

    # Test 1: Invalid public key
    try:
        invalid_key = {"x": "invalid", "y": "data"}
        key_exchange.validate_point(invalid_key)
        # Should return False or raise exception
    except:
        pass

    # Test 2: Signature verification with wrong key
    message = "test"
    sig1_priv, sig1_pub = signature.generate_keypair()
    sig2_priv, sig2_pub = signature.generate_keypair()

    sig = signature.sign_message(message, sig1_priv)
    verified = signature.verify_signature(message, sig, sig2_pub)
    assert not verified, "Should fail with wrong key"

    # Test 3: Modified message
    sig = signature.sign_message("original", sig1_priv)
    verified = signature.verify_signature("modified", sig, sig1_pub)
    assert not verified, "Should fail with modified message"

    # Test 4: Expired session token
    # Test 5: Network failures
    # Test 6: Concurrent requests
```

### **4. Performance Benchmarking**

```python
import time

def benchmark_algorithm(algorithm: str, iterations: int = 100):
    """Benchmark algorithm performance"""

    key_exchange = AlgorithmFactory.create_key_exchange(algorithm)
    signature = AlgorithmFactory.create_signature(algorithm)

    # Benchmark key generation
    start = time.time()
    for _ in range(iterations):
        priv, pub = key_exchange.generate_keypair()
    keygen_time = (time.time() - start) / iterations

    # Benchmark signature generation
    priv, pub = signature.generate_keypair()
    start = time.time()
    for _ in range(iterations):
        sig = signature.sign_message("test", priv)
    sign_time = (time.time() - start) / iterations

    # Benchmark verification
    sig = signature.sign_message("test", priv)
    start = time.time()
    for _ in range(iterations):
        signature.verify_signature("test", sig, pub)
    verify_time = (time.time() - start) / iterations

    print(f"\n{algorithm.upper()} Benchmark Results:")
    print(f"  Key Generation: {keygen_time*1000:.2f} ms")
    print(f"  Sign Message:   {sign_time*1000:.2f} ms")
    print(f"  Verify Signature: {verify_time*1000:.2f} ms")
```

---

## 🔧 TROUBLESHOOTING GUIDE

### **Common Issues**

#### **Issue 1: Signature Verification Fails**

**Symptoms:**

```
✗ Server session signature verification FAILED
```

**Causes:**

1. JSON serialization mismatch (spaces, order)
2. Wrong public key used
3. Hash function mismatch

**Solution:**

```python
# Ensure EXACT same JSON serialization as server
session_data_obj = {
    "sessionId": session_id,
    "algorithm": algorithm,
    "userId": user_id,
    "createdAt": created_at
}

# Use separators=(',', ':') - NO SPACES
session_data_str = json.dumps(session_data_obj, separators=(',', ':'))

# Verify with EPHEMERAL public key from response
verified = signature.verify_signature(
    session_data_str,
    session_signature,
    server_signature_pub_key  # From response, not session creation!
)
```

#### **Issue 2: Shared Secret Mismatch**

**Symptoms:**

```
✗ Decryption failed
✗ Authentication tag verification failed
```

**Causes:**

1. Different computation methods
2. Byte order mismatch
3. Endianness issues

**Solution:**

```python
# Ensure EXACT same computation as server
# For ECDH:
shared_point = scalar_mult(server_public, client_private)
shared_secret = shared_point[0]  # Use x-coordinate

# For RSA:
# Match server's approach exactly
combined = client_n ^ server_n
hash_bytes = hashlib.sha256(str(combined).encode()).digest()
shared_secret = int.from_bytes(hash_bytes, 'big')
```

#### **Issue 3: JWT Decoding Errors**

**Symptoms:**

```
✗ Failed to decode JWT: Invalid padding
```

**Solution:**

```python
def decode_jwt_payload(jwt_token: str) -> dict:
    parts = jwt_token.split('.')
    if len(parts) != 3:
        raise Exception("Invalid JWT format")

    payload_encoded = parts[1]

    # ✅ ADD PADDING
    padding = '=' * (4 - len(payload_encoded) % 4)
    payload_bytes = base64.urlsafe_b64decode(payload_encoded + padding)

    payload = json.loads(payload_bytes.decode('utf-8'))
    return payload
```

#### **Issue 4: Import Errors**

**Symptoms:**

```
ModuleNotFoundError: No module named 'Crypto'
```

**Solution:**

```bash
# Install dependencies
pip install pycryptodome  # For AES
pip install requests       # For HTTP

# For RSA:
pip install cryptography

# For Ed25519:
pip install PyNaCl

# For Post-Quantum (future):
pip install liboqs-python
```

---

## 📊 TESTING MATRIX

### **Compatibility Matrix**

```
┌─────────────┬──────────┬──────────┬──────────┬──────────┐
│ Algorithm   │ Client   │ Server   │ Status   │ Priority │
├─────────────┼──────────┼──────────┼──────────┼──────────┤
│ ECDH P-192  │    ✅    │    ✅   │  DONE    │   HIGH   │
│ RSA-2048    │    🔨    │    🔨   │  TODO    │   HIGH   │
│ ECDH P-256  │    🔮    │    🔮   │  FUTURE  │  MEDIUM  │
│ Ed25519     │    🔮    │    🔮   │  FUTURE  │  MEDIUM  │
│ DH-2048     │    🔮    │    🔮   │  FUTURE  │   LOW    │
│ Kyber       │    🔬    │    🔬   │  R&D     │   LOW    │
│ Dilithium   │    🔬    │    🔬   │  R&D     │   LOW    │
└─────────────┴──────────┴──────────┴──────────┴──────────┘

Legend:
✅ Implemented
🔨 In Progress
🔮 Planned
🔬 Research
```

### **Test Coverage Goals**

```
Phase 1 (Current):
├─ Local Crypto Tests: 100% ✅
├─ Server Integration: 100% ✅
├─ Signature Verification: 100% ✅
└─ Message Workflow: 100% ✅

Phase 2 (RSA):
├─ Local Crypto Tests: 0% 🔨
├─ Server Integration: 0% 🔨
├─ Edge Cases: 0% 🔨
└─ Performance Tests: 0% 🔨

Phase 3 (Ed25519):
├─ All Tests: 0% 🔮
└─ Benchmarks: 0% 🔮
```

---

## 🎯 QUICK START FOR NEW CONTRIBUTORS

### **Adding a New Algorithm in 5 Minutes**

```python
# 1. Copy template
class MyAlgoKeyExchange(KeyExchangeAlgorithm):
    def __init__(self):
        super().__init__("MyAlgo")

    def get_curve_parameters(self):
        return {"param": "value"}

    def generate_keypair(self):
        # Your implementation
        pass

    def compute_shared_secret(self, priv, pub):
        # Your implementation
        pass

    def validate_point(self, point):
        return True

# 2. Copy signature template
class MyAlgoSignature(SignatureAlgorithm):
    # Similar structure...
    pass

# 3. Register
AlgorithmFactory.KEY_EXCHANGE_ALGORITHMS['myalgo'] = MyAlgoKeyExchange
AlgorithmFactory.SIGNATURE_ALGORITHMS['myalgo'] = MyAlgoSignature

# 4. Test
test_cases.append(('group-X', 'myalgo'))

# 5. Run
python Test.py
```

**Done!** Framework handles the rest.

---

## 📚 ADDITIONAL RESOURCES

### **Learning Materials**

1. **ECDH/ECDSA:**

   - NIST FIPS 186-5 (Digital Signature Standard)
   - SEC 1: Elliptic Curve Cryptography

2. **RSA:**

   - PKCS #1 v2.2: RSA Cryptography Standard
   - RFC 8017: PKCS #1 v2.2

3. **Ed25519:**

   - RFC 8032: Edwards-Curve Digital Signature Algorithm
   - libsodium documentation

4. **Post-Quantum:**
   - NIST PQC Standardization Project
   - liboqs documentation

### **Useful Libraries**

```python
# Cryptography
pip install cryptography      # RSA, ECDH P-256
pip install PyNaCl            # Ed25519, Curve25519
pip install pycryptodome      # AES, utilities

# Post-Quantum (when stable)
pip install liboqs-python     # NIST PQC algorithms

# Testing
pip install pytest            # Unit testing
pip install pytest-benchmark # Performance testing
```

---

## 🏁 CONCLUSION

This test framework is designed to be **fully extensible**. Adding new algorithms requires:

1. Implement 2 classes (KeyExchange + Signature)
2. Register in factory
3. Add test case

The framework automatically:

- Tests local crypto
- Tests server integration
- Verifies signatures
- Tests full message workflow
- Reports results

**Future is ready!** Just follow the templates and examples above.

Happy testing! 🚀
