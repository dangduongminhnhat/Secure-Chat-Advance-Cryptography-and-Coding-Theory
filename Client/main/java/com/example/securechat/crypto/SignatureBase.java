package com.example.securechat.crypto;

import org.json.JSONObject;

public abstract class SignatureBase {
    protected String algorithmName;

    public SignatureBase(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    // Abstract methods - must be implemented by subclasses
    public abstract KeyPair generateSignatureKeyPair();
    public abstract Signature signMessage(String message, String privateKey) throws Exception;
    public abstract boolean verifySignature(String message, Signature signature, JSONObject publicKey);

    // Optional: Validate signature
    public boolean validateSignature(Signature signature) {
        return true; // Default implementation
    }

    // Get algorithm name
    public String getAlgorithmName() {
        return algorithmName;
    }

    // Get signature size in bits
    public abstract int getSignatureSize();

    // Get signature parameters
    public abstract JSONObject getParameters() throws Exception;

    // Abstract inner class for signature - MUST be extended by subclasses
    public static abstract class Signature {
        public String algorithm;

        public Signature(String algorithm) {
            this.algorithm = algorithm;
        }

        // Abstract method - must be implemented by subclasses
        public abstract JSONObject toJSON() throws Exception;

        // Static method to create signature from JSON
        public static Signature fromJSON(JSONObject json, String algorithmType) throws Exception {
            String algorithm = json.getString("algorithm");

            // Factory method to create appropriate signature type
            switch (algorithm) {
                case "ECDSA-P192":
                    return ECDSASignature.ECDSASignatureData.fromJSON(json);
                // Add more cases for other signature types in the future
                case "ECDSA-P256":  // ✅ ADD THIS CASE
                    return ECDSASignature2.ECDSASignatureData.fromJSON(json);
                default:
                    throw new IllegalArgumentException("Unknown signature algorithm: " + algorithm);
            }
        }
    }

    // Concrete inner class for key pair
    public static class KeyPair {
        public String privateKey;
        public JSONObject publicKey;

        public KeyPair(String privateKey, JSONObject publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }
    }
}