package com.example.securechat.crypto;

import org.json.JSONObject;

public abstract class KeyExchange {
    protected String algorithmName;

    public KeyExchange(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    // Abstract methods - must be implemented by subclasses
    public abstract void generatePrivateKey();
    public abstract JSONObject generatePublicKey() throws Exception;
    public abstract void computeSharedSecret(JSONObject serverPublicKey) throws Exception;
    public abstract byte[] getSharedSecretBytes();

    // Optional: Validate public key
    public boolean validatePublicKey(JSONObject publicKey) {
        return true; // Default implementation
    }

    // Get algorithm name
    public String getAlgorithmName() {
        return algorithmName;
    }

    // Get key size in bits
    public abstract int getKeySize();

    // Get algorithm parameters
    public abstract JSONObject getParameters() throws Exception;
}