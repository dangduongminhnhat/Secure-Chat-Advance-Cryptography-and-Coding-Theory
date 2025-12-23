#!/usr/bin/env python3
"""
✅ SECURE CHAT SERVER TESTER - v2.3
Supports:
- group-1: ECDH P-192 + AES-GCM
- group-2: ECDH P-256 + AES-GCM
- group-3: ECDH P-256 + AES-CBC
"""

import requests
import json
import time
import base64
import hashlib
import sys
import secrets
from abc import ABC, abstractmethod
from typing import Dict, Tuple, Optional, Any
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad


# ═══════════════════════════════════════════════════════════════════
# 📐 ABSTRACT BASE CLASSES
# ═══════════════════════════════════════════════════════════════════

class KeyExchangeAlgorithm(ABC):
    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def get_curve_parameters(self) -> Dict[str, Any]:
        pass

    @abstractmethod
    def generate_keypair(self) -> Tuple[Any, Dict[str, Any]]:
        pass

    @abstractmethod
    def compute_shared_secret(self, private_key: Any, server_public_key: Dict[str, Any]) -> int:
        pass

    @abstractmethod
    def validate_point(self, point: Any) -> bool:
        pass

    @abstractmethod
    def get_shared_secret_byte_size(self) -> int:
        """Return the byte size of shared secret for this algorithm"""
        pass

    def get_algorithm_name(self) -> str:
        return self.name


class SignatureAlgorithm(ABC):
    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def generate_keypair(self) -> Tuple[Any, Dict[str, Any]]:
        pass

    @abstractmethod
    def sign_message(self, message: str, private_key: Any) -> Dict[str, Any]:
        pass

    @abstractmethod
    def verify_signature(self, message: str, signature: Dict[str, Any], public_key: Dict[str, Any]) -> bool:
        pass

    def get_algorithm_name(self) -> str:
        return self.name


# ═══════════════════════════════════════════════════════════════════
# 🔐 ECDH P-192 IMPLEMENTATION
# ═══════════════════════════════════════════════════════════════════

class ECDHKeyExchange(KeyExchangeAlgorithm):
    """ECDH P-192 (secp192r1)"""

    def __init__(self):
        super().__init__("ECDH-P192")
        self.p = 6277101735386680763835789423207666416083908700390324961279
        self.a = -3
        self.b = 2455155546008943817740293915197451784769108058161191238065
        self.Gx = 3289624317623424368845348028842487418520868978772050262753
        self.Gy = 5673242899673324591834582889556471730778853907191064256384
        self.order = 6277101735386680763835789423176059013767194773182842284081

    def get_curve_parameters(self) -> Dict[str, Any]:
        return {
            "p": str(self.p),
            "a": str(self.a),
            "b": str(self.b),
            "Gx": str(self.Gx),
            "Gy": str(self.Gy),
            "order": str(self.order)
        }

    def get_shared_secret_byte_size(self) -> int:
        return 24  # P-192 = 192 bits = 24 bytes

    def mod_inverse(self, a, m):
        if a < 0:
            a = (a % m + m) % m
        old_r, r = a, m
        old_s, s = 1, 0
        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
        return (old_s % m + m) % m

    def point_add(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2:
            if (y1 + y2) % self.p == 0:
                return None
            if y1 == y2:
                return self.point_double(P)
        lambda_val = ((y2 - y1) * self.mod_inverse((x2 - x1) %
                      self.p, self.p)) % self.p
        x3 = (lambda_val * lambda_val - x1 - x2) % self.p
        y3 = (lambda_val * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def point_double(self, P):
        if P is None:
            return None
        x, y = P
        lambda_val = ((3 * x * x + self.a) *
                      self.mod_inverse(2 * y, self.p)) % self.p
        x3 = (lambda_val * lambda_val - 2 * x) % self.p
        y3 = (lambda_val * (x - x3) - y) % self.p
        return (x3, y3)

    def scalar_mult(self, P, n):
        if P is None or n == 0:
            return None
        if n == 1:
            return P
        Q = P
        R = None
        k = n
        while k > 0:
            if k % 2 == 1:
                R = self.point_add(R, Q)
            Q = self.point_double(Q)
            k = k // 2
        return R

    def generate_keypair(self) -> Tuple[int, Dict[str, str]]:
        private_key = secrets.randbelow(self.order - 1) + 1
        G = (self.Gx, self.Gy)
        public_key_point = self.scalar_mult(G, private_key)
        if public_key_point is None:
            raise Exception("Failed to generate public key")
        public_key = {
            'x': str(public_key_point[0]),
            'y': str(public_key_point[1])
        }
        return private_key, public_key

    def compute_shared_secret(self, private_key: int, server_public_key: Dict[str, str]) -> int:
        server_x = int(server_public_key['x'])
        server_y = int(server_public_key['y'])
        server_point = (server_x, server_y)
        if not self.validate_point(server_point):
            raise Exception("Invalid server public key")
        shared_point = self.scalar_mult(server_point, private_key)
        if shared_point is None:
            raise Exception("Failed to compute shared secret")
        return shared_point[0]

    def validate_point(self, point) -> bool:
        if point is None:
            return True
        x, y = point
        left = (y * y) % self.p
        right = (x * x * x + self.a * x + self.b) % self.p
        return left == right


# ═══════════════════════════════════════════════════════════════════
# 🔐 ECDH P-256 IMPLEMENTATION
# ═══════════════════════════════════════════════════════════════════

class ECDHKeyExchange_P256(KeyExchangeAlgorithm):
    """ECDH P-256 (secp256r1)"""

    def __init__(self):
        super().__init__("ECDH-P256")
        self.p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
        self.a = -3
        self.b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
        self.Gx = 48439561293906451759052585252797914202762949526041747995844080717082404635286
        self.Gy = 36134250956749795798585127919587881956611106672985015071877198253568414405109
        self.order = 115792089210356248762697446949407573529996955224135760342422259061068512044369

    def get_curve_parameters(self) -> Dict[str, Any]:
        return {
            "p": str(self.p),
            "a": str(self.a),
            "b": str(self.b),
            "Gx": str(self.Gx),
            "Gy": str(self.Gy),
            "order": str(self.order)
        }

    def get_shared_secret_byte_size(self) -> int:
        return 32  # P-256 = 256 bits = 32 bytes

    def mod_inverse(self, a, m):
        if a < 0:
            a = (a % m + m) % m
        old_r, r = a, m
        old_s, s = 1, 0
        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
        return (old_s % m + m) % m

    def point_add(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2:
            if (y1 + y2) % self.p == 0:
                return None
            if y1 == y2:
                return self.point_double(P)
        lambda_val = ((y2 - y1) * self.mod_inverse((x2 - x1) %
                      self.p, self.p)) % self.p
        x3 = (lambda_val * lambda_val - x1 - x2) % self.p
        y3 = (lambda_val * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def point_double(self, P):
        if P is None:
            return None
        x, y = P
        lambda_val = ((3 * x * x + self.a) *
                      self.mod_inverse(2 * y, self.p)) % self.p
        x3 = (lambda_val * lambda_val - 2 * x) % self.p
        y3 = (lambda_val * (x - x3) - y) % self.p
        return (x3, y3)

    def scalar_mult(self, P, n):
        if P is None or n == 0:
            return None
        if n == 1:
            return P
        Q = P
        R = None
        k = n
        while k > 0:
            if k % 2 == 1:
                R = self.point_add(R, Q)
            Q = self.point_double(Q)
            k = k // 2
        return R

    def generate_keypair(self) -> Tuple[int, Dict[str, str]]:
        private_key = secrets.randbelow(self.order - 1) + 1
        G = (self.Gx, self.Gy)
        public_key_point = self.scalar_mult(G, private_key)
        if public_key_point is None:
            raise Exception("Failed to generate public key")
        public_key = {
            'x': str(public_key_point[0]),
            'y': str(public_key_point[1])
        }
        return private_key, public_key

    def compute_shared_secret(self, private_key: int, server_public_key: Dict[str, str]) -> int:
        server_x = int(server_public_key['x'])
        server_y = int(server_public_key['y'])
        server_point = (server_x, server_y)
        if not self.validate_point(server_point):
            raise Exception("Invalid server public key")
        shared_point = self.scalar_mult(server_point, private_key)
        if shared_point is None:
            raise Exception("Failed to compute shared secret")
        return shared_point[0]

    def validate_point(self, point) -> bool:
        if point is None:
            return True
        x, y = point
        left = (y * y) % self.p
        right = (x * x * x + self.a * x + self.b) % self.p
        return left == right


# ═══════════════════════════════════════════════════════════════════
# 🔐 ECDSA SIGNATURES
# ═══════════════════════════════════════════════════════════════════

class ECDSASignature(SignatureAlgorithm):
    """ECDSA P-192"""

    def __init__(self):
        super().__init__("ECDSA-P192")
        self.ecdh = ECDHKeyExchange()

    def generate_keypair(self) -> Tuple[int, Dict[str, str]]:
        return self.ecdh.generate_keypair()

    def hash_message(self, message: str) -> int:
        hasher = hashlib.sha256()
        hasher.update(message.encode('utf-8'))
        hash_bytes = hasher.digest()
        hash_int = int.from_bytes(hash_bytes, byteorder='big')
        return hash_int % self.ecdh.order

    def sign_message(self, message: str, private_key: int) -> Dict[str, Any]:
        message_hash = self.hash_message(message)
        k = secrets.randbelow(self.ecdh.order - 1) + 1
        G = (self.ecdh.Gx, self.ecdh.Gy)
        kG = self.ecdh.scalar_mult(G, k)
        r = kG[0] % self.ecdh.order
        if r == 0:
            raise Exception("Invalid signature generation (r = 0)")
        k_inv = self.ecdh.mod_inverse(k, self.ecdh.order)
        s = (k_inv * (message_hash + r * private_key)) % self.ecdh.order
        if s == 0:
            raise Exception("Invalid signature generation (s = 0)")
        return {
            'r': str(r),
            's': str(s),
            'messageHash': str(message_hash),
            'algorithm': self.name
        }

    def verify_signature(self, message: str, signature: Dict[str, Any], public_key: Dict[str, str]) -> bool:
        try:
            message_hash = self.hash_message(message)
            r = int(signature['r'])
            s = int(signature['s'])
            pub_x = int(public_key['x'])
            pub_y = int(public_key['y'])
            pub_point = (pub_x, pub_y)

            if r <= 0 or r >= self.ecdh.order or s <= 0 or s >= self.ecdh.order:
                return False

            w = self.ecdh.mod_inverse(s, self.ecdh.order)
            u1 = (message_hash * w) % self.ecdh.order
            u2 = (r * w) % self.ecdh.order

            G = (self.ecdh.Gx, self.ecdh.Gy)
            point1 = self.ecdh.scalar_mult(G, u1)
            point2 = self.ecdh.scalar_mult(pub_point, u2)
            point = self.ecdh.point_add(point1, point2)

            if point is None:
                return False

            v = point[0] % self.ecdh.order
            return v == r
        except Exception:
            return False


class ECDSASignature_P256(SignatureAlgorithm):
    """ECDSA P-256"""

    def __init__(self):
        super().__init__("ECDSA-P256")
        self.ecdh = ECDHKeyExchange_P256()

    def generate_keypair(self) -> Tuple[int, Dict[str, str]]:
        return self.ecdh.generate_keypair()

    def hash_message(self, message: str) -> int:
        hasher = hashlib.sha256()
        hasher.update(message.encode('utf-8'))
        hash_bytes = hasher.digest()
        hash_int = int.from_bytes(hash_bytes, byteorder='big')
        return hash_int % self.ecdh.order

    def sign_message(self, message: str, private_key: int) -> Dict[str, Any]:
        message_hash = self.hash_message(message)
        k = secrets.randbelow(self.ecdh.order - 1) + 1
        G = (self.ecdh.Gx, self.ecdh.Gy)
        kG = self.ecdh.scalar_mult(G, k)
        r = kG[0] % self.ecdh.order
        if r == 0:
            raise Exception("Invalid signature generation (r = 0)")
        k_inv = self.ecdh.mod_inverse(k, self.ecdh.order)
        s = (k_inv * (message_hash + r * private_key)) % self.ecdh.order
        if s == 0:
            raise Exception("Invalid signature generation (s = 0)")
        return {
            'r': str(r),
            's': str(s),
            'messageHash': str(message_hash),
            'algorithm': self.name
        }

    def verify_signature(self, message: str, signature: Dict[str, Any], public_key: Dict[str, str]) -> bool:
        try:
            message_hash = self.hash_message(message)
            r = int(signature['r'])
            s = int(signature['s'])
            pub_x = int(public_key['x'])
            pub_y = int(public_key['y'])
            pub_point = (pub_x, pub_y)

            if r <= 0 or r >= self.ecdh.order or s <= 0 or s >= self.ecdh.order:
                return False

            w = self.ecdh.mod_inverse(s, self.ecdh.order)
            u1 = (message_hash * w) % self.ecdh.order
            u2 = (r * w) % self.ecdh.order

            G = (self.ecdh.Gx, self.ecdh.Gy)
            point1 = self.ecdh.scalar_mult(G, u1)
            point2 = self.ecdh.scalar_mult(pub_point, u2)
            point = self.ecdh.point_add(point1, point2)

            if point is None:
                return False

            v = point[0] % self.ecdh.order
            return v == r
        except Exception:
            return False


# ═══════════════════════════════════════════════════════════════════
# 🔐 FACTORY
# ═══════════════════════════════════════════════════════════════════

class AlgorithmFactory:
    """Factory for creating algorithm instances"""

    KEY_EXCHANGE_ALGORITHMS = {
        'ecdh': ECDHKeyExchange,        # P-192 (group-1)
        'ecdh_2': ECDHKeyExchange_P256,  # P-256 (group-2)
        'ecdh_3': ECDHKeyExchange_P256,  # P-256 (group-3, CBC mode)
    }

    SIGNATURE_ALGORITHMS = {
        'ecdh': ECDSASignature,         # P-192
        'ecdh_2': ECDSASignature_P256,  # P-256
        'ecdh_3': ECDSASignature_P256,  # P-256
    }

    @classmethod
    def create_key_exchange(cls, algorithm: str) -> KeyExchangeAlgorithm:
        algorithm = algorithm.lower()
        if algorithm not in cls.KEY_EXCHANGE_ALGORITHMS:
            raise ValueError(f"Unknown key exchange algorithm: {algorithm}")
        return cls.KEY_EXCHANGE_ALGORITHMS[algorithm]()

    @classmethod
    def create_signature(cls, algorithm: str) -> SignatureAlgorithm:
        algorithm = algorithm.lower()
        if algorithm not in cls.SIGNATURE_ALGORITHMS:
            raise ValueError(f"Unknown signature algorithm: {algorithm}")
        return cls.SIGNATURE_ALGORITHMS[algorithm]()

    @classmethod
    def get_supported_algorithms(cls) -> list:
        return list(cls.KEY_EXCHANGE_ALGORITHMS.keys())


# ═══════════════════════════════════════════════════════════════════
# 🔐 ENCRYPTION
# ═══════════════════════════════════════════════════════════════════

class Encryption:
    """Encryption utilities with GCM and CBC support"""

    @staticmethod
    def bigint_to_bytes(bigint: int, length: int) -> bytes:
        hex_str = format(bigint, f'0{length * 2}x')
        return bytes.fromhex(hex_str)

    @staticmethod
    def derive_aes_key(shared_secret: int, algorithm: KeyExchangeAlgorithm) -> bytes:
        """Derive AES key with correct byte size for algorithm"""
        secret_byte_size = algorithm.get_shared_secret_byte_size()
        secret_bytes = Encryption.bigint_to_bytes(
            shared_secret, secret_byte_size)

        salt = b'\x00' * 16
        iterations = 1000
        key_length = 32

        aes_key = PBKDF2(secret_bytes, salt, key_length,
                         count=iterations, hmac_hash_module=SHA256)
        return aes_key

    @staticmethod
    def encrypt_gcm(aes_key: bytes, plaintext: str) -> str:
        """Encrypt using AES-GCM (secure, default)"""
        iv = get_random_bytes(12)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        result = iv + ciphertext + tag
        return base64.b64encode(result).decode('utf-8')

    @staticmethod
    def decrypt_gcm(aes_key: bytes, encrypted_data: str) -> str:
        """Decrypt using AES-GCM"""
        data = base64.b64decode(encrypted_data)
        iv = data[:12]
        ciphertext_with_tag = data[12:]
        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')

    @staticmethod
    def encrypt_cbc(aes_key: bytes, plaintext: str) -> str:
        """Encrypt using AES-CBC"""
        iv = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
        padded = pad(plaintext.encode('utf-8'), 16)
        ciphertext = cipher.encrypt(padded)
        result = iv + ciphertext
        return base64.b64encode(result).decode('utf-8')

    @staticmethod
    def decrypt_cbc(aes_key: bytes, encrypted_data: str) -> str:
        """Decrypt using AES-CBC"""
        data = base64.b64decode(encrypted_data)
        iv = data[:16]
        ciphertext = data[16:]
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
        padded = cipher.decrypt(ciphertext)
        plaintext = unpad(padded, 16)
        return plaintext.decode('utf-8')


# ═══════════════════════════════════════════════════════════════════
# 🔧 JWT UTILITIES
# ═══════════════════════════════════════════════════════════════════

def decode_jwt_payload(jwt_token: str) -> dict:
    """Decode JWT payload (middle part) without verification"""
    try:
        parts = jwt_token.split('.')
        if len(parts) != 3:
            raise Exception("Invalid JWT format")

        payload_encoded = parts[1]
        padding = '=' * (4 - len(payload_encoded) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_encoded + padding)
        payload = json.loads(payload_bytes.decode('utf-8'))

        return payload
    except Exception as e:
        raise Exception(f"Failed to decode JWT: {e}")


# ═══════════════════════════════════════════════════════════════════
# 🧪 TESTER
# ═══════════════════════════════════════════════════════════════════

class ExtensibleServerTester:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'SecureChat-Tester/2.3'
        })
        self.encryption = Encryption()
        self.factory = AlgorithmFactory()

    def log(self, message: str, level: str = "INFO"):
        colors = {
            "INFO": "\033[36m",
            "PASS": "\033[32m",
            "FAIL": "\033[31m",
            "WARN": "\033[33m",
            "SUCCESS": "\033[92m",
            "ALGORITHM": "\033[95m",
        }
        reset = "\033[0m"
        timestamp = time.strftime("%H:%M:%S")
        color = colors.get(level, "")
        print(f"{color}[{timestamp}] {level}: {message}{reset}")

    def make_request(self, method: str, endpoint: str, data: dict = None,
                     params: dict = None, user_id: str = None) -> Optional[requests.Response]:
        url = f"{self.base_url}{endpoint}"
        if params is None:
            params = {}
        if user_id and 'userId' not in params:
            params['userId'] = user_id
        headers = {}
        if user_id:
            headers['x-user-id'] = user_id

        try:
            if method.upper() == 'GET':
                return self.session.get(url, params=params, headers=headers, timeout=30)
            elif method.upper() == 'POST':
                return self.session.post(url, json=data, params=params, headers=headers, timeout=30)
        except requests.exceptions.RequestException as e:
            self.log(f"Request failed: {e}", "FAIL")
            return None

    def test_full_workflow(self, user_id: str, algorithm: str, mode: str = "GCM"):
        """Test full workflow with server"""
        self.log(f"\n{'='*70}", "INFO")
        self.log(
            f"🧪 Testing: {user_id} | {algorithm.upper()} | {mode}", "ALGORITHM")
        self.log(f"{'='*70}", "INFO")

        try:
            key_exchange = self.factory.create_key_exchange(algorithm)
            signature = self.factory.create_signature(algorithm)
        except Exception as e:
            self.log(f"✗ {e}", "FAIL")
            return False

        # Step 1: Create session
        self.log(f"\n📝 Step 1: Creating session...", "INFO")
        session_data = {'algorithm': algorithm}
        curve_params = key_exchange.get_curve_parameters()
        session_data['curveParameters'] = curve_params

        response = self.make_request(
            'POST', '/session/create', data=session_data, user_id=user_id)
        if not response or response.status_code != 200:
            self.log(f"✗ Session creation failed", "FAIL")
            return False

        result = response.json()
        if not result.get('success'):
            self.log(f"✗ Server error: {result.get('error')}", "FAIL")
            return False

        session_token = result['sessionToken']
        server_public_key = result['serverPublicKey']
        server_signature_pub_key = result['serverSignaturePublicKey']
        session_signature = result['sessionSignature']

        self.log(f"✓ Session created", "PASS")

        # Verify server signature
        jwt_payload = decode_jwt_payload(session_token)
        session_id = jwt_payload.get('sid')
        created_at = jwt_payload.get('createdAt')

        session_data_obj = {
            "sessionId": session_id,
            "algorithm": algorithm,
            "userId": user_id,
            "createdAt": created_at
        }

        session_data_str = json.dumps(session_data_obj, separators=(',', ':'))

        verified = signature.verify_signature(
            session_data_str,
            session_signature,
            server_signature_pub_key
        )

        if not verified:
            self.log(f"✗ Server signature verification FAILED", "FAIL")
            return False

        self.log(f"✓ Server signature verified", "PASS")

        # Step 2: Key exchange
        self.log(f"\n🔑 Step 2: Key exchange...", "INFO")

        client_ecdh_private, client_ecdh_public = key_exchange.generate_keypair()
        client_sig_private, client_sig_public = signature.generate_keypair()

        client_pub_str = json.dumps(client_ecdh_public, separators=(',', ':'))
        client_sig = signature.sign_message(client_pub_str, client_sig_private)

        exchange_data = {
            'sessionToken': session_token,
            'clientPublicKey': client_ecdh_public,
            'clientPublicKeySignature': client_sig,
            'clientSignaturePublicKey': client_sig_public
        }

        response = self.make_request(
            'POST', '/session/exchange', data=exchange_data, user_id=user_id)
        if not response or response.status_code != 200:
            self.log(f"✗ Key exchange failed", "FAIL")
            return False

        result = response.json()
        if not result.get('success'):
            self.log(f"✗ Key exchange error: {result.get('error')}", "FAIL")
            return False

        session_token = result.get('sessionToken', session_token)

        shared_secret = key_exchange.compute_shared_secret(
            client_ecdh_private, server_public_key)
        aes_key = self.encryption.derive_aes_key(shared_secret, key_exchange)

        self.log(f"✓ Key exchange completed", "PASS")

        # Step 3: Send messages
        self.log(
            f"\n💬 Step 3: Testing encrypted messaging ({mode})...", "INFO")

        test_messages = ["hello", "name", "age", "location", "hobby"]
        success_count = 0

        for msg in test_messages:
            # Encrypt based on mode
            if mode == "CBC":
                encrypted_msg = self.encryption.encrypt_cbc(aes_key, msg)
            else:
                encrypted_msg = self.encryption.encrypt_gcm(aes_key, msg)

            msg_sig_private, msg_sig_public = signature.generate_keypair()
            msg_signature = signature.sign_message(
                encrypted_msg, msg_sig_private)

            msg_data = {
                'sessionToken': session_token,
                'encryptedMessage': encrypted_msg,
                'mode': mode,
                'messageSignature': msg_signature,
                'clientSignaturePublicKey': msg_sig_public
            }

            response = self.make_request(
                'POST', '/message/send', data=msg_data, user_id=user_id)

            if response and response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    session_token = result.get('sessionToken', session_token)
                    encrypted_response = result.get('encryptedResponse')

                    if encrypted_response:
                        # Decrypt based on mode
                        if mode == "CBC":
                            decrypted = self.encryption.decrypt_cbc(
                                aes_key, encrypted_response)
                        else:
                            decrypted = self.encryption.decrypt_gcm(
                                aes_key, encrypted_response)

                        self.log(f"  '{msg}' → '{decrypted}'", "SUCCESS")
                        success_count += 1
                else:
                    self.log(
                        f"  ✗ '{msg}' failed: {result.get('error')}", "FAIL")
            else:
                self.log(f"  ✗ '{msg}' failed", "FAIL")

            time.sleep(0.3)

        if success_count == len(test_messages):
            self.log(
                f"✓ All messages successful ({success_count}/{len(test_messages)})", "PASS")
        else:
            self.log(
                f"⚠ Some messages failed ({success_count}/{len(test_messages)})", "WARN")

        self.log(f"\n✅ Test completed for {user_id}", "SUCCESS")
        return success_count > 0

    def run_comprehensive_test(self):
        """Run comprehensive tests for all 3 groups"""
        self.log("🚀 SecureChat Server Test Framework v2.3", "INFO")
        self.log(f"Target: {self.base_url}", "INFO")
        self.log("=" * 70, "INFO")

        # Test cases: (user_id, algorithm, mode)
        test_cases = [
            ('group-1', 'ecdh', 'GCM'),      # P-192 + GCM
            ('group-2', 'ecdh_2', 'GCM'),    # P-256 + GCM
            ('group-3', 'ecdh_3', 'CBC'),    # P-256 + CBC
        ]

        results = {}
        for user_id, algorithm, mode in test_cases:
            success = self.test_full_workflow(user_id, algorithm, mode)
            results[f"{user_id}/{mode}"] = success
            time.sleep(1)

        # Summary
        self.log("\n" + "=" * 70, "INFO")
        self.log("📊 TEST SUMMARY", "INFO")
        self.log("=" * 70, "INFO")

        for test_name, success in results.items():
            status = "✅ PASS" if success else "❌ FAIL"
            self.log(f"{test_name.upper()}: {status}",
                     "PASS" if success else "FAIL")

        total = len(results)
        passed = sum(1 for s in results.values() if s)
        self.log(f"\nTotal: {passed}/{total} tests passed",
                 "SUCCESS" if passed == total else "WARN")
        self.log("\n🏁 Test Framework Completed!", "SUCCESS")


# ═══════════════════════════════════════════════════════════════════
# 🎯 MAIN
# ═══════════════════════════════════════════════════════════════════

def main():
    server_url = "Your Clodflare URL"

    # Check dependencies
    try:
        import requests
        from Crypto.Cipher import AES
    except ImportError:
        print("Installing required packages...")
        import subprocess
        subprocess.check_call(
            [sys.executable, '-m', 'pip', 'install', 'requests', 'pycryptodome'])

    # Run tests
    tester = ExtensibleServerTester(server_url)
    tester.run_comprehensive_test()


if __name__ == "__main__":
    main()
