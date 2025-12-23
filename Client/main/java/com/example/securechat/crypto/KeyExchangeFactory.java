package com.example.securechat.crypto;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class KeyExchangeFactory {
    private Map<String, Class<? extends KeyExchange>> algorithms;

    public KeyExchangeFactory() {
        algorithms = new HashMap<>();
        registerDefaultAlgorithms();
    }

    private void registerDefaultAlgorithms() {
        algorithms.put("ecdh", ECDHKeyExchange.class);
        algorithms.put("ecdh_2", ECDHKeyExchange2.class);
        algorithms.put("ecdh_3", ECDHKeyExchange2.class);
    }

    public void register(String name, Class<? extends KeyExchange> algorithmClass) {
        algorithms.put(name.toLowerCase(), algorithmClass);
    }

    public KeyExchange create(String name) throws Exception {
        Class<? extends KeyExchange> algorithmClass = algorithms.get(name.toLowerCase());
        if (algorithmClass == null) {
            throw new IllegalArgumentException("Unknown key exchange algorithm: " + name);
        }
        return algorithmClass.newInstance();
    }

    public Set<String> getSupportedAlgorithms() {
        return algorithms.keySet();
    }

    public boolean isSupported(String name) {
        return algorithms.containsKey(name.toLowerCase());
    }
}