package com.example.securechat.crypto;

import android.util.Log;
import org.json.JSONObject;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class ECDSASignature extends SignatureBase {
    private static final String TAG = "ECDSASignature";

    // P-192 parameters (same as ECDH)
    private static final BigInteger CURVE_P = new BigInteger("6277101735386680763835789423207666416083908700390324961279");
    private static final BigInteger CURVE_A = BigInteger.valueOf(-3);
    private static final BigInteger CURVE_B = new BigInteger("2455155546008943817740293915197451784769108058161191238065");
    private static final BigInteger CURVE_GX = new BigInteger("3289624317623424368845348028842487418520868978772050262753");
    private static final BigInteger CURVE_GY = new BigInteger("5673242899673324591834582889556471730778853907191064256384");
    private static final BigInteger CURVE_ORDER = new BigInteger("6277101735386680763835789423176059013767194773182842284081");

    public ECDSASignature() {
        super("ECDSA-P192");
    }

    public static class ECPoint {
        public BigInteger x, y;

        public ECPoint(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
        }
    }

    // Concrete implementation of Signature for ECDSA
    public static class ECDSASignatureData extends SignatureBase.Signature {
        public String r, s, messageHash;

        public ECDSASignatureData(String r, String s, String messageHash) {
            super("ECDSA-P192");
            this.r = r;
            this.s = s;
            this.messageHash = messageHash;
        }

        @Override
        public JSONObject toJSON() throws Exception {
            JSONObject json = new JSONObject();
            json.put("r", r);
            json.put("s", s);
            json.put("messageHash", messageHash);
            json.put("algorithm", algorithm);
            return json;
        }

        public static ECDSASignatureData fromJSON(JSONObject json) throws Exception {
            return new ECDSASignatureData(
                    json.getString("r"),
                    json.getString("s"),
                    json.getString("messageHash")
            );
        }
    }

    @Override
    public KeyPair generateSignatureKeyPair() {
        SecureRandom random = new SecureRandom();
        byte[] privateKeyBytes = new byte[24]; // 192 bits
        random.nextBytes(privateKeyBytes);

        BigInteger privateKey = new BigInteger(1, privateKeyBytes)
                .mod(CURVE_ORDER.subtract(BigInteger.ONE))
                .add(BigInteger.ONE);

        ECPoint publicKeyPoint = scalarMult(new ECPoint(CURVE_GX, CURVE_GY), privateKey);

        try {
            JSONObject publicKey = new JSONObject();
            publicKey.put("x", publicKeyPoint.x.toString());
            publicKey.put("y", publicKeyPoint.y.toString());

            return new KeyPair(privateKey.toString(), publicKey);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate ECDSA signature key pair", e);
        }
    }

    @Override
    public Signature signMessage(String message, String privateKeyStr) throws Exception {
        BigInteger messageHash = hashMessage(message);
        BigInteger privateKey = new BigInteger(privateKeyStr);

        // Generate random k
        SecureRandom random = new SecureRandom();
        BigInteger k;
        do {
            byte[] kBytes = new byte[24];
            random.nextBytes(kBytes);
            k = new BigInteger(1, kBytes).mod(CURVE_ORDER.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        } while (k.equals(BigInteger.ZERO));

        // Calculate r = (k * G).x mod order
        ECPoint kG = scalarMult(new ECPoint(CURVE_GX, CURVE_GY), k);
        BigInteger r = kG.x.mod(CURVE_ORDER);

        if (r.equals(BigInteger.ZERO)) {
            throw new Exception("Invalid ECDSA signature generation (r = 0)");
        }

        // Calculate s = k^(-1) * (hash + r * privateKey) mod order
        BigInteger kInv = k.modInverse(CURVE_ORDER);
        BigInteger s = kInv.multiply(messageHash.add(r.multiply(privateKey))).mod(CURVE_ORDER);

        if (s.equals(BigInteger.ZERO)) {
            throw new Exception("Invalid ECDSA signature generation (s = 0)");
        }

        return new ECDSASignatureData(r.toString(), s.toString(), messageHash.toString());
    }

    @Override
    public boolean verifySignature(String message, Signature signature, JSONObject publicKeyJson) {
        try {
            // Cast to ECDSASignatureData
            if (!(signature instanceof ECDSASignatureData)) {
                Log.e(TAG, "Invalid signature type for ECDSA verification");
                return false;
            }

            ECDSASignatureData ecdsaSig = (ECDSASignatureData) signature;
            BigInteger messageHash = hashMessage(message);
            BigInteger r = new BigInteger(ecdsaSig.r);
            BigInteger s = new BigInteger(ecdsaSig.s);

            BigInteger pubX = new BigInteger(publicKeyJson.getString("x"));
            BigInteger pubY = new BigInteger(publicKeyJson.getString("y"));
            ECPoint publicKey = new ECPoint(pubX, pubY);

            // Verify r and s are in valid range
            if (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(CURVE_ORDER) >= 0 ||
                    s.compareTo(BigInteger.ZERO) <= 0 || s.compareTo(CURVE_ORDER) >= 0) {
                return false;
            }

            // Calculate w = s^(-1) mod order
            BigInteger w = s.modInverse(CURVE_ORDER);

            // Calculate u1 = hash * w mod order
            BigInteger u1 = messageHash.multiply(w).mod(CURVE_ORDER);

            // Calculate u2 = r * w mod order
            BigInteger u2 = r.multiply(w).mod(CURVE_ORDER);

            // Calculate point = u1 * G + u2 * publicKey
            ECPoint point1 = scalarMult(new ECPoint(CURVE_GX, CURVE_GY), u1);
            ECPoint point2 = scalarMult(publicKey, u2);
            ECPoint point = pointAdd(point1, point2);

            if (point == null) return false;

            // Verify r == point.x mod order
            BigInteger v = point.x.mod(CURVE_ORDER);
            return v.equals(r);

        } catch (Exception e) {
            Log.e(TAG, "ECDSA signature verification error", e);
            return false;
        }
    }

    @Override
    public boolean validateSignature(Signature signature) {
        if (!(signature instanceof ECDSASignatureData)) {
            return false;
        }
        ECDSASignatureData ecdsaSig = (ECDSASignatureData) signature;
        return ecdsaSig.r != null && ecdsaSig.s != null &&
                algorithmName.equals(ecdsaSig.algorithm);
    }

    // Hash message using SHA-256
    public BigInteger hashMessage(String message) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(message.getBytes(StandardCharsets.UTF_8));

        // Convert to BigInteger
        BigInteger hash = new BigInteger(1, hashBytes);

        // Reduce to curve order
        return hash.mod(CURVE_ORDER);
    }

    @Override
    public int getSignatureSize() {
        return 384; // 192 * 2 bits for r and s
    }

    @Override
    public JSONObject getParameters() throws Exception {
        JSONObject params = new JSONObject();
        params.put("algorithm", algorithmName);
        params.put("curve", "P-192");
        params.put("signatureSize", getSignatureSize());
        params.put("hashAlgorithm", "SHA-256");
        params.put("p", CURVE_P.toString());
        params.put("a", CURVE_A.toString());
        params.put("b", CURVE_B.toString());
        params.put("gx", CURVE_GX.toString());
        params.put("gy", CURVE_GY.toString());
        params.put("order", CURVE_ORDER.toString());
        return params;
    }

    // Helper methods (same as ECDH implementation)
    private ECPoint pointAdd(ECPoint pointP, ECPoint pointQ) {
        if (pointP == null) return pointQ;
        if (pointQ == null) return pointP;

        if (pointP.x.equals(pointQ.x)) {
            if (pointP.y.add(pointQ.y).mod(CURVE_P).equals(BigInteger.ZERO)) {
                return null;
            }
            if (pointP.y.equals(pointQ.y)) {
                return pointDouble(pointP);
            }
        }

        BigInteger deltaY = pointQ.y.subtract(pointP.y);
        BigInteger deltaX = pointQ.x.subtract(pointP.x);
        BigInteger slope = deltaY.multiply(deltaX.modInverse(CURVE_P)).mod(CURVE_P);

        BigInteger resultX = slope.multiply(slope).subtract(pointP.x).subtract(pointQ.x).mod(CURVE_P);
        BigInteger resultY = slope.multiply(pointP.x.subtract(resultX)).subtract(pointP.y).mod(CURVE_P);

        if (resultX.compareTo(BigInteger.ZERO) < 0) {
            resultX = resultX.add(CURVE_P);
        }
        if (resultY.compareTo(BigInteger.ZERO) < 0) {
            resultY = resultY.add(CURVE_P);
        }

        return new ECPoint(resultX, resultY);
    }

    private ECPoint pointDouble(ECPoint point) {
        if (point == null) return null;

        BigInteger numerator = point.x.multiply(point.x).multiply(BigInteger.valueOf(3)).add(CURVE_A);
        BigInteger denominator = point.y.multiply(BigInteger.valueOf(2));
        BigInteger slope = numerator.multiply(denominator.modInverse(CURVE_P)).mod(CURVE_P);

        BigInteger resultX = slope.multiply(slope).subtract(point.x.multiply(BigInteger.valueOf(2))).mod(CURVE_P);
        BigInteger resultY = slope.multiply(point.x.subtract(resultX)).subtract(point.y).mod(CURVE_P);

        if (resultX.compareTo(BigInteger.ZERO) < 0) {
            resultX = resultX.add(CURVE_P);
        }
        if (resultY.compareTo(BigInteger.ZERO) < 0) {
            resultY = resultY.add(CURVE_P);
        }

        return new ECPoint(resultX, resultY);
    }

    private ECPoint scalarMult(ECPoint point, BigInteger scalar) {
        if (point == null || scalar.equals(BigInteger.ZERO)) {
            return null;
        }

        if (scalar.equals(BigInteger.ONE)) {
            return new ECPoint(point.x, point.y);
        }

        ECPoint result = null;
        ECPoint addend = new ECPoint(point.x, point.y);
        BigInteger k = scalar;

        while (k.compareTo(BigInteger.ZERO) > 0) {
            if (k.testBit(0)) {
                result = pointAdd(result, addend);
            }
            addend = pointDouble(addend);
            k = k.shiftRight(1);
        }

        return result;
    }
}