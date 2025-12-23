package com.example.securechat.crypto;

import android.util.Log;
import org.json.JSONObject;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class ECDHKeyExchange extends KeyExchange {
    private static final String TAG = "ECDHKeyExchange";

    // ECDH P-192 parameters
    private static final BigInteger CURVE_P = new BigInteger("6277101735386680763835789423207666416083908700390324961279");
    private static final BigInteger CURVE_A = BigInteger.valueOf(-3);
    private static final BigInteger CURVE_B = new BigInteger("2455155546008943817740293915197451784769108058161191238065");
    private static final BigInteger CURVE_GX = new BigInteger("3289624317623424368845348028842487418520868978772050262753");
    private static final BigInteger CURVE_GY = new BigInteger("5673242899673324591834582889556471730778853907191064256384");
    private static final BigInteger CURVE_ORDER = new BigInteger("6277101735386680763835789423176059013767194773182842284081");

    private BigInteger privateKey;
    private ECPoint publicKey;
    private BigInteger sharedSecret;

    public static class ECPoint {
        public BigInteger x, y;

        public ECPoint(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
        }

        @Override
        public String toString() {
            return "ECPoint{x=" + x + ", y=" + y + "}";
        }
    }

    public ECDHKeyExchange() {
        super("ECDH-P192");
    }

    @Override
    public void generatePrivateKey() {
        SecureRandom random = new SecureRandom();
        byte[] privateKeyBytes = new byte[24]; // 192 bits
        random.nextBytes(privateKeyBytes);

        privateKey = new BigInteger(1, privateKeyBytes).mod(CURVE_ORDER.subtract(BigInteger.ONE)).add(BigInteger.ONE);

        // Generate public key
        ECPoint G = new ECPoint(CURVE_GX, CURVE_GY);
        publicKey = scalarMult(G, privateKey);
    }

    @Override
    public JSONObject generatePublicKey() throws Exception {
        if (publicKey == null) {
            throw new IllegalStateException("Private key not generated yet");
        }

        JSONObject pubKey = new JSONObject();
        pubKey.put("x", publicKey.x.toString());
        pubKey.put("y", publicKey.y.toString());
        return pubKey;
    }

    @Override
    public void computeSharedSecret(JSONObject serverPublicKey) throws Exception {
        BigInteger serverX = new BigInteger(serverPublicKey.getString("x"));
        BigInteger serverY = new BigInteger(serverPublicKey.getString("y"));
        ECPoint serverPoint = new ECPoint(serverX, serverY);

        // Validate server public key
        if (!validatePublicKey(serverPublicKey)) {
            throw new Exception("Invalid server public key");
        }

        ECPoint sharedPoint = scalarMult(serverPoint, privateKey);
        if (sharedPoint == null) {
            throw new Exception("Failed to compute shared secret - point at infinity");
        }

        sharedSecret = sharedPoint.x;
    }

    @Override
    public byte[] getSharedSecretBytes() {
        if (sharedSecret == null) {
            throw new IllegalStateException("Shared secret not computed yet");
        }

        // Return the shared secret as 24 bytes for P-192
        // Server expects bigInt, we need to make sure we return the right format
        return toByteArray(sharedSecret, 24);
    }

    @Override
    public boolean validatePublicKey(JSONObject publicKey) {
        try {
            BigInteger x = new BigInteger(publicKey.getString("x"));
            BigInteger y = new BigInteger(publicKey.getString("y"));

            // Check if point is on the curve: y^2 = x^3 + ax + b (mod p)
            BigInteger left = y.multiply(y).mod(CURVE_P);
            BigInteger right = x.multiply(x).multiply(x).add(CURVE_A.multiply(x)).add(CURVE_B).mod(CURVE_P);
            return left.equals(right);
        } catch (Exception e) {
            Log.e(TAG, "Error validating public key", e);
            return false;
        }
    }

    @Override
    public int getKeySize() {
        return 192;
    }

    @Override
    public JSONObject getParameters() throws Exception {
        JSONObject params = new JSONObject();
        params.put("algorithm", algorithmName);
        params.put("curve", "P-192");
        params.put("keySize", getKeySize());
        params.put("p", CURVE_P.toString());
        params.put("a", CURVE_A.toString());
        params.put("b", CURVE_B.toString());
        params.put("gx", CURVE_GX.toString());
        params.put("gy", CURVE_GY.toString());
        params.put("order", CURVE_ORDER.toString());
        return params;
    }

    // ECDH helper methods
    private BigInteger modInverse(BigInteger a, BigInteger m) {
        return a.modInverse(m);
    }

    private ECPoint pointAdd(ECPoint pointP, ECPoint pointQ) {
        if (pointP == null) return pointQ;
        if (pointQ == null) return pointP;

        // Check if Q is inverse of P (same x, opposite y)
        if (pointP.x.equals(pointQ.x)) {
            if (pointP.y.add(pointQ.y).mod(CURVE_P).equals(BigInteger.ZERO)) {
                return null; // Point at infinity
            }
            // Points are the same, do point doubling
            if (pointP.y.equals(pointQ.y)) {
                return pointDouble(pointP);
            }
        }

        // Regular point addition
        BigInteger deltaY = pointQ.y.subtract(pointP.y);
        BigInteger deltaX = pointQ.x.subtract(pointP.x);

        // Calculate slope
        BigInteger slope = deltaY.multiply(modInverse(deltaX, CURVE_P)).mod(CURVE_P);

        // Calculate result point
        BigInteger resultX = slope.multiply(slope).subtract(pointP.x).subtract(pointQ.x).mod(CURVE_P);
        BigInteger resultY = slope.multiply(pointP.x.subtract(resultX)).subtract(pointP.y).mod(CURVE_P);

        // Ensure positive coordinates
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

        // Calculate slope for point doubling: (3x^2 + a) / (2y)
        BigInteger numerator = point.x.multiply(point.x).multiply(BigInteger.valueOf(3)).add(CURVE_A);
        BigInteger denominator = point.y.multiply(BigInteger.valueOf(2));
        BigInteger slope = numerator.multiply(modInverse(denominator, CURVE_P)).mod(CURVE_P);

        // Calculate result point
        BigInteger resultX = slope.multiply(slope).subtract(point.x.multiply(BigInteger.valueOf(2))).mod(CURVE_P);
        BigInteger resultY = slope.multiply(point.x.subtract(resultX)).subtract(point.y).mod(CURVE_P);

        // Ensure positive coordinates
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
            if (k.testBit(0)) { // if k is odd
                result = pointAdd(result, addend);
            }
            addend = pointDouble(addend);
            k = k.shiftRight(1);
        }

        return result;
    }

    private byte[] toByteArray(BigInteger bigInt, int length) {
        // Convert to minimal byte array first
        byte[] bytes = bigInt.toByteArray();

        // If already correct length, return as-is
        if (bytes.length == length) {
            return bytes;
        }

        // If too long (due to sign bit), remove the leading zero
        if (bytes.length > length && bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, length + 1);
        }

        // If too short, pad with leading zeros
        if (bytes.length < length) {
            byte[] padded = new byte[length];
            System.arraycopy(bytes, 0, padded, length - bytes.length, bytes.length);
            return padded;
        }

        // If still too long, take the last 'length' bytes
        return Arrays.copyOfRange(bytes, bytes.length - length, bytes.length);
    }
}