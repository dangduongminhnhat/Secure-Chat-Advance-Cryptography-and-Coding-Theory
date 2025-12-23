package com.example.securechat.crypto;

import java.util.HashMap;
import java.util.Map;

public class AlgorithmSelector {
    private static final Map<String, String> USER_ALGORITHM_MAP = new HashMap<>();

    static {
        // Map userId to algorithm
        USER_ALGORITHM_MAP.put("group-1", "ecdh");
        USER_ALGORITHM_MAP.put("group-2", "ecdh_2");
        USER_ALGORITHM_MAP.put("group-3", "ecdh_3");
    }

    public static String getAlgorithmForUser(String userId) {
        return USER_ALGORITHM_MAP.getOrDefault(userId, "ecdh"); // Default to ECDH
    }

    public static String getAlgorithmDisplayName(String algorithm) {
        switch (algorithm.toLowerCase()) {
            case "ecdh":
                return "ECDH P-192";
            case "ecdh_2":
            case "ecdh_3":
                return "ECDH P-256";
            default:
                return algorithm.toUpperCase();
        }
    }
}