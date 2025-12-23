package com.example.securechat;

import android.util.Base64;
import android.util.Log;

import com.example.securechat.crypto.KeyExchange;
import com.example.securechat.crypto.KeyExchangeFactory;
import com.example.securechat.crypto.AlgorithmSelector;
import com.example.securechat.crypto.SignatureFactory;
import com.example.securechat.crypto.SignatureBase;

import org.json.JSONObject;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class CryptoManager {
    private static final String TAG = "CryptoManager";

    private KeyExchangeFactory keyExchangeFactory;
    private SignatureFactory signatureFactory;
    private KeyExchange keyExchange;
    private SignatureBase signatureManager;
    private SecretKeySpec aesKey;
    private String algorithm;
    private BigInteger sharedSecret;

    // Signature-related fields
    private SignatureBase.KeyPair clientSignatureKeys;
    private JSONObject serverSignaturePublicKey;
    private String signatureAlgorithm;
    private String encryptionMode = "GCM"; // Default to secure mode

    public CryptoManager() {
        keyExchangeFactory = new KeyExchangeFactory();
        signatureFactory = new SignatureFactory();
    }

    public void initializeForUser(String userId) throws Exception {
        algorithm = AlgorithmSelector.getAlgorithmForUser(userId);
        keyExchange = keyExchangeFactory.create(algorithm);

        // Initialize signature manager
        if (signatureFactory.isSupported(algorithm)) {
            signatureManager = signatureFactory.create(algorithm);
            signatureAlgorithm = signatureManager.getAlgorithmName();

            // Generate client signature keys
            clientSignatureKeys = signatureManager.generateSignatureKeyPair();

            Log.d(TAG, "Initialized " + AlgorithmSelector.getAlgorithmDisplayName(algorithm) +
                    " for user: " + userId + " with " + signatureAlgorithm + " signatures");
        } else {
            Log.w(TAG, "No signature support available for " + algorithm);
        }
    }

    public String getAlgorithmName() {
        return algorithm != null ? AlgorithmSelector.getAlgorithmDisplayName(algorithm) : "Unknown";
    }

    public String getSignatureAlgorithmName() {
        return signatureAlgorithm;
    }

    // Get client signature public key
    public JSONObject getClientSignaturePublicKey() {
        return clientSignatureKeys != null ? clientSignatureKeys.publicKey : null;
    }

    // Set server signature public key
    public void setServerSignaturePublicKey(JSONObject serverSignaturePublicKey) {
        this.serverSignaturePublicKey = serverSignaturePublicKey;
    }

    // ✅ Verify server signature (original method - with Signature object)
    public boolean verifyServerSignature(String message, SignatureBase.Signature signature) {
        if (signatureManager == null || serverSignaturePublicKey == null) {
            Log.w(TAG, "Signature manager or server public key not available");
            return false;
        }
        return signatureManager.verifySignature(message, signature, serverSignaturePublicKey);
    }

    // ✅ NEW: Verify server signature with JSONObject signature
    public boolean verifyServerSignature(String message, JSONObject signatureJson, JSONObject publicKey) {
        if (signatureManager == null) {
            Log.w(TAG, "Signature manager not available");
            return false;
        }

        try {
            // Convert JSON to Signature object
            SignatureBase.Signature signature = SignatureBase.Signature.fromJSON(
                    signatureJson,
                    signatureAlgorithm
            );

            // Use the provided public key (for session verification before serverSignaturePublicKey is set)
            return signatureManager.verifySignature(message, signature, publicKey);

        } catch (Exception e) {
            Log.e(TAG, "Error verifying signature from JSON", e);
            return false;
        }
    }

    // ✅ NEW: Verify server signature with JSONObject (using stored serverSignaturePublicKey)
    public boolean verifyServerSignature(String message, JSONObject signatureJson) {
        if (signatureManager == null || serverSignaturePublicKey == null) {
            Log.w(TAG, "Signature manager or server public key not available");
            return false;
        }

        try {
            // Convert JSON to Signature object
            SignatureBase.Signature signature = SignatureBase.Signature.fromJSON(
                    signatureJson,
                    signatureAlgorithm
            );

            return signatureManager.verifySignature(message, signature, serverSignaturePublicKey);

        } catch (Exception e) {
            Log.e(TAG, "Error verifying signature from JSON", e);
            return false;
        }
    }

    /**
     * Verify signature with specific public key (not the stored one)
     * Used for verifying ephemeral signatures
     */
    public boolean verifySignatureWithPublicKey(
            String message,
            SignatureBase.Signature signature,
            JSONObject publicKey
    ) {
        if (signatureManager == null) {
            Log.w(TAG, "Signature manager not available");
            return false;
        }

        // Verify with the provided public key (ephemeral)
        return signatureManager.verifySignature(message, signature, publicKey);
    }

    // Check if signature is supported
    public boolean isSignatureSupported() {
        return signatureManager != null && clientSignatureKeys != null;
    }

    // ========== Key Exchange Methods ==========

    public void generateKeyPair() throws Exception {
        if (keyExchange == null) {
            throw new IllegalStateException("KeyExchange not initialized");
        }

        keyExchange.generatePrivateKey();
        Log.d(TAG, "Key pair generated using " + keyExchange.getAlgorithmName());
    }

    public JSONObject getPublicKeyJson() throws Exception {
        if (keyExchange == null) {
            throw new IllegalStateException("KeyExchange not initialized");
        }

        return keyExchange.generatePublicKey();
    }

    public void computeSharedSecret(JSONObject serverPublicKey) throws Exception {
        if (keyExchange == null) {
            throw new IllegalStateException("KeyExchange not initialized");
        }

        keyExchange.computeSharedSecret(serverPublicKey);

        // Get shared secret as BigInteger
        byte[] secretBytes = keyExchange.getSharedSecretBytes();
        sharedSecret = new BigInteger(1, secretBytes);

        deriveAESKey();
    }

    // ✅ ADD HELPER METHOD
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private void deriveAESKey() throws Exception {
        if (sharedSecret == null) {
            throw new IllegalStateException("Shared secret not computed yet");
        }

        // ✅ AUTO-DETECT byte size from algorithm
        int secretByteSize = getSecretByteSizeForAlgorithm();

        // Convert BigInt to bytes with correct size
        byte[] secretBytes = bigIntToBytes(sharedSecret, secretByteSize);

        // Use PBKDF2
        byte[] salt = new byte[16];
        Arrays.fill(salt, (byte) 0);

        byte[] keyBytes = pbkdf2(secretBytes, salt, 1000, 32);

        aesKey = new SecretKeySpec(keyBytes, "AES");

        Log.d(TAG, "✅ AES key derived successfully");
    }

    // ✅ Helper method to get correct byte size
    private int getSecretByteSizeForAlgorithm() {
        if (keyExchange == null) {
            return 24; // Default fallback
        }

        String algoName = keyExchange.getAlgorithmName();
        Log.d(TAG, "Determining byte size for algorithm: " + algoName);

        // ✅ Fallback: Calculate from key size
        int keySize = keyExchange.getKeySize();
        return keySize / 8; // bits to bytes
    }

    private byte[] pbkdf2(byte[] password, byte[] salt, int iterations, int keyLength) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(password, "HmacSHA256"));

        byte[] result = new byte[keyLength];
        int hLen = mac.getMacLength();
        int blockCount = (keyLength + hLen - 1) / hLen;

        for (int i = 1; i <= blockCount; i++) {
            byte[] block = new byte[salt.length + 4];
            System.arraycopy(salt, 0, block, 0, salt.length);

            block[salt.length] = (byte) (i >>> 24);
            block[salt.length + 1] = (byte) (i >>> 16);
            block[salt.length + 2] = (byte) (i >>> 8);
            block[salt.length + 3] = (byte) i;

            byte[] u = mac.doFinal(block);
            byte[] t = u.clone();

            for (int j = 1; j < iterations; j++) {
                u = mac.doFinal(u);
                for (int k = 0; k < u.length; k++) {
                    t[k] ^= u[k];
                }
            }

            int copyLength = Math.min(t.length, keyLength - (i - 1) * hLen);
            System.arraycopy(t, 0, result, (i - 1) * hLen, copyLength);
        }

        return result;
    }

    private byte[] bigIntToBytes(BigInteger bigInt, int length) {
        String hex = format(bigInt, length * 2);
        return hexToBytes(hex);
    }

    private String format(BigInteger bigInt, int length) {
        String hex = bigInt.toString(16);
        while (hex.length() < length) {
            hex = "0" + hex;
        }
        if (hex.length() > length) {
            hex = hex.substring(hex.length() - length);
        }
        return hex;
    }

    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    // ✅ Set encryption mode
    public void setEncryptionMode(String mode) {
        if ("CBC".equals(mode) || "GCM".equals(mode)) {
            this.encryptionMode = mode;
            Log.d(TAG, "Encryption mode set to: " + mode);
        } else {
            Log.w(TAG, "Invalid encryption mode: " + mode);
        }
    }

    public String getEncryptionMode() {
        return encryptionMode;
    }

    public String encryptGCM(String plaintext) throws Exception {
        if (aesKey == null) {
            throw new IllegalStateException("AES key not derived");
        }

        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);

        return Base64.encodeToString(result, Base64.NO_WRAP);
    }

    public String decryptGCM(String encryptedData) throws Exception {
        if (aesKey == null) {
            throw new IllegalStateException("AES key not derived");
        }

        byte[] data = Base64.decode(encryptedData, Base64.NO_WRAP);

        byte[] iv = Arrays.copyOfRange(data, 0, 12);
        byte[] ciphertext = Arrays.copyOfRange(data, 12, data.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);

        byte[] plaintext = cipher.doFinal(ciphertext);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    // ✅ CBC Encryption (Vulnerable - for educational purposes)
    private String encryptCBC(String plaintext) throws Exception {
        if (aesKey == null) {
            throw new IllegalStateException("AES key not derived");
        }

        byte[] iv = new byte[16]; // 16 bytes for CBC
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);

        return Base64.encodeToString(result, Base64.NO_WRAP);
    }

    // ⚠️ VULNERABLE: Exposes padding oracle - for educational purposes only!
    private String decryptCBC(String encryptedData) throws Exception {
        if (aesKey == null) {
            throw new IllegalStateException("AES key not derived");
        }

        byte[] data = Base64.decode(encryptedData, Base64.NO_WRAP);

        byte[] iv = Arrays.copyOfRange(data, 0, 16);
        byte[] ciphertext = Arrays.copyOfRange(data, 16, data.length);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);

        try {
            byte[] plaintext = cipher.doFinal(ciphertext);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (javax.crypto.BadPaddingException e) {
            // ⚠️ VULNERABILITY: This reveals padding information!
            throw new RuntimeException("PADDING_ERROR", e);
        } catch (Exception e) {
            throw new RuntimeException("DECRYPT_ERROR", e);
        }
    }

    // ✅ Padding Oracle Check (for educational attack demo)
    public PaddingOracleResult checkPadding(String encryptedData) {
        try {
            decryptCBC(encryptedData);
            return new PaddingOracleResult(true, null);
        } catch (RuntimeException e) {
            String errorType = e.getMessage().equals("PADDING_ERROR") ? "PADDING_ERROR" : "DECRYPT_ERROR";
            return new PaddingOracleResult(false, errorType);
        } catch (Exception e) {
            return new PaddingOracleResult(false, "UNKNOWN_ERROR");
        }
    }

    // ✅ Unified encrypt method
    public String encrypt(String plaintext) throws Exception {
        if ("CBC".equals(encryptionMode)) {
            Log.w(TAG, "⚠️ Using CBC mode - vulnerable to padding oracle attack!");
            return encryptCBC(plaintext);
        } else {
            return encryptGCM(plaintext);
        }
    }

    // ✅ Unified decrypt method
    public String decrypt(String encryptedData) throws Exception {
        if ("CBC".equals(encryptionMode)) {
            Log.w(TAG, "⚠️ Using CBC mode - vulnerable to padding oracle attack!");
            return decryptCBC(encryptedData);
        } else {
            return decryptGCM(encryptedData);
        }
    }

    // ✅ Helper class for padding oracle results
    public static class PaddingOracleResult {
        public final boolean isValid;
        public final String errorType;

        public PaddingOracleResult(boolean isValid, String errorType) {
            this.isValid = isValid;
            this.errorType = errorType;
        }
    }

    public boolean isKeyExchangeComplete() {
        return aesKey != null && sharedSecret != null;
    }

    public JSONObject getAlgorithmParameters() throws Exception {
        if (keyExchange == null) {
            throw new IllegalStateException("KeyExchange not initialized");
        }

        return keyExchange.getParameters();
    }

    // Test encryption
    public void testEncryption() {
        try {
            String testMessage = "Hello, World!";
            Log.d(TAG, "=== Testing Encryption ===");
            Log.d(TAG, "Original: " + testMessage);

            String encrypted = encrypt(testMessage);
            Log.d(TAG, "Encrypted: " + encrypted);

            String decrypted = decrypt(encrypted);
            Log.d(TAG, "Decrypted: " + decrypted);

            boolean match = testMessage.equals(decrypted);
            Log.d(TAG, "Test result: " + (match ? "PASS" : "FAIL"));

        } catch (Exception e) {
            Log.e(TAG, "Encryption test failed", e);
        }
    }

    // Test signature
    public void testSignature() {
        if (signatureManager == null) {
            Log.w(TAG, "No signature manager available for testing");
            return;
        }

        try {
            String testMessage = "Hello, " + signatureAlgorithm + "!";
            Log.d(TAG, "=== Testing " + signatureAlgorithm + " Signature ===");
            Log.d(TAG, "Original: " + testMessage);

            SignatureBase.Signature signature = signMessage(testMessage);
            Log.d(TAG, "Signature created with " + signature.algorithm);

            boolean verified = signatureManager.verifySignature(
                    testMessage, signature, clientSignatureKeys.publicKey);
            Log.d(TAG, "Signature verification: " + (verified ? "PASS" : "FAIL"));

        } catch (Exception e) {
            Log.e(TAG, signatureAlgorithm + " signature test failed", e);
        }
    }

    /**
     * Generate EPHEMERAL signature keypair for each signing operation
     * This ensures forward secrecy and follows cryptographic best practices
     */
    public SignatureBase.KeyPair generateEphemeralSignatureKeyPair() throws Exception {
        if (signatureManager == null) {
            throw new IllegalStateException("Signature manager not initialized");
        }

        // Generate FRESH random keypair
        SignatureBase.KeyPair ephemeralKeys = signatureManager.generateSignatureKeyPair();

        return ephemeralKeys;
    }

    /**
     * Sign message with EPHEMERAL keypair (generates new keypair each time)
     */
    public SignatureWithPublicKey signMessageEphemeral(String message) throws Exception {
        if (signatureManager == null) {
            throw new IllegalStateException("Signature manager not initialized");
        }

        // ✅ Generate EPHEMERAL keypair for THIS signature
        SignatureBase.KeyPair ephemeralKeys = generateEphemeralSignatureKeyPair();

        // Sign with ephemeral private key
        SignatureBase.Signature signature = signatureManager.signMessage(
                message,
                ephemeralKeys.privateKey
        );

        Log.d(TAG, "✅ Message signed with EPHEMERAL key");

        // ✅ Return BOTH signature AND public key
        return new SignatureWithPublicKey(signature, ephemeralKeys.publicKey);
    }

    /**
     * Inner class to hold signature + public key pair
     */
    public static class SignatureWithPublicKey {
        public final SignatureBase.Signature signature;
        public final JSONObject publicKey;

        public SignatureWithPublicKey(SignatureBase.Signature signature, JSONObject publicKey) {
            this.signature = signature;
            this.publicKey = publicKey;
        }
    }

    // Keep existing methods for backward compatibility
    public SignatureBase.Signature signMessage(String message) throws Exception {
        // This uses the stored clientSignatureKeys (for session creation)
        if (signatureManager == null || clientSignatureKeys == null) {
            throw new IllegalStateException("Signature manager not initialized");
        }
        return signatureManager.signMessage(message, clientSignatureKeys.privateKey);
    }
}