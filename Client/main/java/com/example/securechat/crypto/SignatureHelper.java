package com.example.securechat.crypto;

import org.json.JSONObject;

public class SignatureHelper {

    // Helper method to create signature from JSON
    public static SignatureBase.Signature createSignatureFromJSON(JSONObject json) throws Exception {
        String algorithm = json.getString("algorithm");

        switch (algorithm) {
            case "ECDSA-P192":
                return ECDSASignature.ECDSASignatureData.fromJSON(json);
            // Add more signature types here in the future
            case "ECDSA-P256":  // ✅ ADD THIS CASE
                return ECDSASignature2.ECDSASignatureData.fromJSON(json);
            default:
                throw new IllegalArgumentException("Unsupported signature algorithm: " + algorithm);
        }
    }

    // Helper method to validate signature JSON
    public static boolean isValidSignatureJSON(JSONObject json) {
        try {
            if (!json.has("algorithm")) return false;

            String algorithm = json.getString("algorithm");
            switch (algorithm) {
                case "ECDSA-P192":
                case "ECDSA-P256":  // ✅ ADD THIS CASE
                    return json.has("r") && json.has("s") && json.has("messageHash");
                default:
                    return false;
            }
        } catch (Exception e) {
            return false;
        }
    }
}