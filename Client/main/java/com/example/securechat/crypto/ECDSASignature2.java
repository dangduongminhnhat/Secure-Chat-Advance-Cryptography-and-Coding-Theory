package com.example.securechat.crypto;

import android.util.Log;
import org.json.JSONObject;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class ECDSASignature2 extends SignatureBase {
    private static final String TAG = "ECDSASignature2";

    // P-256 parameters
    private static final BigInteger CURVE_P = new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951");
    private static final BigInteger CURVE_A = BigInteger.valueOf(-3);
    private static final BigInteger CURVE_B = new BigInteger("41058363725152142129326129780047268409114441015993725554835256314039467401291");
    private static final BigInteger CURVE_GX = new BigInteger("48439561293906451759052585252797914202762949526041747995844080717082404635286");
    private static final BigInteger CURVE_GY = new BigInteger("36134250956749795798585127919587881956611106672985015071877198253568414405109");
    private static final BigInteger CURVE_ORDER = new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369");

    public ECDSASignature2() {
        super("ECDSA-P256");
    }

    public static class ECPoint {
        public BigInteger x, y;

        public ECPoint(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
        }
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // ECDSA SIGNATURE DATA CLASS
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    public static class ECDSASignatureData extends SignatureBase.Signature {
        public String r, s, messageHash;

        public ECDSASignatureData(String r, String s, String messageHash) {
            super("ECDSA-P256");  // ✅ Make sure algorithm name matches
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

        // ✅ CRITICAL: This method must exist
        public static ECDSASignatureData fromJSON(JSONObject json) throws Exception {
            return new ECDSASignatureData(
                    json.getString("r"),
                    json.getString("s"),
                    json.getString("messageHash")
            );
        }
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // KEY PAIR GENERATION
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Override
    public KeyPair generateSignatureKeyPair() {
        SecureRandom random = new SecureRandom();
        byte[] privateKeyBytes = new byte[32]; // 256 bits for P-256
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

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // SIGNING
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Override
    public Signature signMessage(String message, String privateKeyStr) throws Exception {
        BigInteger messageHash = hashMessage(message);
        BigInteger privateKey = new BigInteger(privateKeyStr);

        // Generate random k
        SecureRandom random = new SecureRandom();
        BigInteger k;
        do {
            byte[] kBytes = new byte[32];
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

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // VERIFICATION
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Override
    public boolean verifySignature(String message, Signature signature, JSONObject publicKeyJson) {
        try {
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

            if (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(CURVE_ORDER) >= 0 ||
                    s.compareTo(BigInteger.ZERO) <= 0 || s.compareTo(CURVE_ORDER) >= 0) {
                return false;
            }

            BigInteger w = s.modInverse(CURVE_ORDER);
            BigInteger u1 = messageHash.multiply(w).mod(CURVE_ORDER);
            BigInteger u2 = r.multiply(w).mod(CURVE_ORDER);

            ECPoint point1 = scalarMult(new ECPoint(CURVE_GX, CURVE_GY), u1);
            ECPoint point2 = scalarMult(publicKey, u2);
            ECPoint point = pointAdd(point1, point2);

            if (point == null) return false;

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

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // HASH FUNCTION
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    public BigInteger hashMessage(String message) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(message.getBytes(StandardCharsets.UTF_8));

        BigInteger hash = new BigInteger(1, hashBytes);
        return hash.mod(CURVE_ORDER);
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // METADATA
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Override
    public int getSignatureSize() {
        return 512; // 256 * 2 bits for r and s
    }

    @Override
    public JSONObject getParameters() throws Exception {
        JSONObject params = new JSONObject();
        params.put("algorithm", algorithmName);
        params.put("curve", "P-256");
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

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // HELPER METHODS (EC Operations)
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

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