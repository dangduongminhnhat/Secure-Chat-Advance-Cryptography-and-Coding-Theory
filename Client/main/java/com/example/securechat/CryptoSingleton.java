package com.example.securechat;

public class CryptoSingleton {
    private static CryptoSingleton instance;
    private CryptoManager cryptoManager;
    private boolean isReady = false;

    private CryptoSingleton() {}

    public static synchronized CryptoSingleton getInstance() {
        if (instance == null) {
            instance = new CryptoSingleton();
        }
        return instance;
    }

    public void setCryptoManager(CryptoManager cryptoManager) {
        this.cryptoManager = cryptoManager;
        this.isReady = cryptoManager != null && cryptoManager.isKeyExchangeComplete();
    }

    public CryptoManager getCryptoManager() {
        return cryptoManager;
    }

    public boolean isReady() {
        return isReady && cryptoManager != null && cryptoManager.isKeyExchangeComplete();
    }

    public void clear() {
        cryptoManager = null;
        isReady = false;
    }
}