package com.example.securechat.crypto;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class SignatureFactory {
    private Map<String, Class<? extends SignatureBase>> signatures;

    public SignatureFactory() {
        signatures = new HashMap<>();
        registerDefaultSignatures();
    }

    private void registerDefaultSignatures() {
        signatures.put("ecdh", ECDSASignature.class);  // ECDH uses ECDSA
        signatures.put("ecdh_2", ECDSASignature2.class);
        signatures.put("ecdh_3", ECDSASignature2.class);
    }

    public void register(String keyExchangeAlgorithm, Class<? extends SignatureBase> signatureClass) {
        signatures.put(keyExchangeAlgorithm.toLowerCase(), signatureClass);
    }

    public SignatureBase create(String keyExchangeAlgorithm) throws Exception {
        Class<? extends SignatureBase> signatureClass = signatures.get(keyExchangeAlgorithm.toLowerCase());
        if (signatureClass == null) {
            throw new IllegalArgumentException("No signature algorithm for key exchange: " + keyExchangeAlgorithm);
        }
        return signatureClass.newInstance();
    }

    public Set<String> getSupportedKeyExchangeAlgorithms() {
        return signatures.keySet();
    }

    public boolean isSupported(String keyExchangeAlgorithm) {
        return signatures.containsKey(keyExchangeAlgorithm.toLowerCase());
    }

    public String getSignatureAlgorithmName(String keyExchangeAlgorithm) throws Exception {
        if (!isSupported(keyExchangeAlgorithm)) {
            return null;
        }
        SignatureBase instance = create(keyExchangeAlgorithm);
        return instance.getAlgorithmName();
    }
}