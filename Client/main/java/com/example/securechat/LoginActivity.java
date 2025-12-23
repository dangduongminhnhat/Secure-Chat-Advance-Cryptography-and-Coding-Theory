package com.example.securechat;

import android.app.ProgressDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Log;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import com.example.securechat.CryptoSingleton;
import com.example.securechat.crypto.SignatureBase;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.Network;
import android.net.NetworkCapabilities;

import com.example.securechat.crypto.AlgorithmSelector;

import org.json.JSONObject;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.CertificatePinner;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class LoginActivity extends AppCompatActivity {
    private static final String TAG = "LoginActivity";
    private static final String BASE_URL = "https://secure-chat.your-name.workers.dev";
    private static final String HOSTNAME = "secure-chat.your-name.workers.dev";
    private static final String SPKI_BASE64 = "YOUR_SPKI_BASE64";
    private EditText userIdInput;
    private Button loginButton;
    private TextView algorithmInfo;
    private SharedPreferences prefs;
    private ProgressDialog progressDialog;

    private OkHttpClient client;
    private CryptoManager cryptoManager;
    private String userId;
    private String sessionToken;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // ✅ CHECK ROOT FIRST (before anything else)
        if (RootDetection.isDeviceRooted(this)) {
            showRootDetectedDialog();
            return; // Don't proceed with normal initialization
        }

        setContentView(R.layout.activity_login);

        initViews();
        setupUI();

        client = buildClient();

        // Check if user is already logged in
        String savedUserId = prefs.getString("userId", "");
        String savedSessionToken = prefs.getString("sessionToken", "");
        if (!savedUserId.isEmpty() && !savedSessionToken.isEmpty()) {
            // Try to restore session
            attemptSessionRestore(savedUserId, savedSessionToken);
        }
    }

    private void showRootDetectedDialog() {
        new AlertDialog.Builder(this)
                .setTitle("⚠️ Cảnh báo bảo mật")
                .setMessage("Thiết bị của bạn đã bị root/jailbreak.\n\n" +
                        "Vì lý do bảo mật, ứng dụng này không thể chạy trên thiết bị đã root.\n\n" +
                        "Không nên cài đặt ứng dụng này ở thiết bị này.")
                .setIcon(android.R.drawable.ic_dialog_alert)
                .setCancelable(false) // Không cho phép dismiss bằng back button
                .setPositiveButton("OK", (dialog, which) -> {
                    // ✅ Exit app khi nhấn OK
                    finish();
                    System.exit(0); // Force exit
                })
                .show();
    }

    private void initViews() {
        userIdInput = findViewById(R.id.userIdInput);
        loginButton = findViewById(R.id.loginButton);
        algorithmInfo = findViewById(R.id.algorithmInfo);
        prefs = getSharedPreferences("SecureChat", MODE_PRIVATE);
    }

    private void setupUI() {
        showAlgorithmMapping();

        loginButton.setOnClickListener(v -> {
            String userId = userIdInput.getText().toString().trim();
            if (userId.isEmpty()) {
                Toast.makeText(this, "Please enter User ID", Toast.LENGTH_SHORT).show();
                return;
            }

            // Start login process
            startLoginProcess(userId);
        });

        userIdInput.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                updateAlgorithmDisplay(s.toString());
            }

            @Override
            public void afterTextChanged(Editable s) {
            }
        });
    }

    private void showAlgorithmMapping() {
        String mapping = "Welcome to Secure Chat Application";
        algorithmInfo.setText(mapping);
        algorithmInfo.setTextColor(getResources().getColor(android.R.color.black));
    }

    private void updateAlgorithmDisplay(String userId) {
        if (userId.isEmpty()) {
            showAlgorithmMapping();
            return;
        }

        String algorithm = AlgorithmSelector.getAlgorithmForUser(userId);
        String displayName = AlgorithmSelector.getAlgorithmDisplayName(algorithm);

        algorithmInfo.setText("Please enter Correct UserId");
        algorithmInfo.setTextColor(getResources().getColor(android.R.color.holo_blue_dark));
    }

    private OkHttpClient buildClient() {
        boolean debug = false;
        OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .connectTimeout(15, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS);
        if (!debug) {
            Log.d("SSL Pinning", "Have Pinning Here");
            CertificatePinner pinner = new CertificatePinner.Builder()
                    .add(HOSTNAME, "sha256/" + SPKI_BASE64)
                    .build();
            builder.certificatePinner(pinner);
        }
        return builder.build();
    }

    private void startLoginProcess(String userId) {
        this.userId = userId;

        showProgress("Initializing...");

        // Initialize crypto manager
        try {
            cryptoManager = new CryptoManager();
            cryptoManager.initializeForUser(userId);

            updateProgress("Creating session...");
            createSession();

        } catch (Exception e) {
            hideProgress();
            Log.e(TAG, "Error initializing crypto", e);
            showError("Failed to initialize encryption: " + e.getMessage());
        }
    }

    private boolean isNetworkAvailable() {
        ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);

        if (connectivityManager != null) {
            NetworkInfo activeNetworkInfo = connectivityManager.getActiveNetworkInfo();
            return activeNetworkInfo != null && activeNetworkInfo.isConnected();
        }

        return false;
    }

    private void createSession() {
        try {
            String algorithm = AlgorithmSelector.getAlgorithmForUser(userId);
            Log.d(TAG, "Algorithm for user: " + algorithm);

            JSONObject requestBody = new JSONObject();
            requestBody.put("algorithm", algorithm);

            // If ECDH, include P-192 curve parameters (nested)
            if ("ecdh".equals(algorithm)) {
                JSONObject curveParams = new JSONObject();
                curveParams.put("p", "6277101735386680763835789423207666416083908700390324961279");
                curveParams.put("a", "-3");
                curveParams.put("b", "2455155546008943817740293915197451784769108058161191238065");
                curveParams.put("Gx", "3289624317623424368845348028842487418520868978772050262753");
                curveParams.put("Gy", "5673242899673324591834582889556471730778853907191064256384");
                curveParams.put("order", "6277101735386680763835789423176059013767194773182842284081");

                requestBody.put("curveParameters", curveParams);
                Log.d(TAG, "Added ECDH curve parameters");
            }

            if ("ecdh_2".equals(algorithm)) {
                // a = -3
                //// b =
                // 41058363725152142129326129780047268409114441015993725554835256314039467401291
                //// mod =
                // 115792089210356248762697446949407573530086143415290314195533631308867097853951
                //// Gx =
                // 48439561293906451759052585252797914202762949526041747995844080717082404635286
                //// Gy =
                // 36134250956749795798585127919587881956611106672985015071877198253568414405109
                //// order =
                // 115792089210356248762697446949407573529996955224135760342422259061068512044369
                JSONObject curveParams = new JSONObject();
                curveParams.put("p", "115792089210356248762697446949407573530086143415290314195533631308867097853951");
                curveParams.put("a", "-3");
                curveParams.put("b", "41058363725152142129326129780047268409114441015993725554835256314039467401291");
                curveParams.put("Gx", "48439561293906451759052585252797914202762949526041747995844080717082404635286");
                curveParams.put("Gy", "36134250956749795798585127919587881956611106672985015071877198253568414405109");
                curveParams.put("order",
                        "115792089210356248762697446949407573529996955224135760342422259061068512044369");

                requestBody.put("curveParameters", curveParams);
                Log.d(TAG, "Added ECDH curve parameters");
            }

            RequestBody body = RequestBody.create(
                    requestBody.toString(),
                    MediaType.parse("application/json"));

            Request request = new Request.Builder()
                    .url(BASE_URL + "/session/create?userId=" + userId)
                    .addHeader("x-user-id", userId)
                    .addHeader("Content-Type", "application/json")
                    .post(body)
                    .build();

            // ✅ Check network first
            if (!isNetworkAvailable()) {
                hideProgress();
                showError("No internet connection!\nPlease check your network settings.");
                return;
            }

            client.newCall(request).enqueue(new Callback() {
                @Override
                public void onFailure(Call call, IOException e) {
                    Log.e(TAG, "=== Request onFailure ===");
                    Log.e(TAG, "Error type: " + e.getClass().getSimpleName());
                    Log.e(TAG, "Error message: " + e.getMessage());
                    if (e.getCause() != null) {
                        Log.e(TAG, "Error cause: " + e.getCause().getMessage());
                    }
                    e.printStackTrace();

                    runOnUiThread(() -> {
                        hideProgress();
                        handleNetworkError(e);
                    });
                }

                @Override
                public void onResponse(Call call, Response response) throws IOException {
                    String responseBody = "";
                    try {
                        responseBody = response.body().string();
                    } catch (Exception e) {
                        Log.e(TAG, "Error reading response body", e);
                    }

                    final String finalResponseBody = responseBody;
                    final int responseCode = response.code();
                    final boolean isSuccessful = response.isSuccessful();

                    runOnUiThread(() -> {
                        if (!isSuccessful) {
                            Log.e(TAG, "Response not successful: " + responseCode);
                            hideProgress();
                            handleServerError(responseCode, finalResponseBody);
                            return;
                        }

                        try {
                            JSONObject jsonResponse = new JSONObject(finalResponseBody);

                            // Check success field
                            if (!jsonResponse.getBoolean("success")) {
                                hideProgress();
                                showError("Server error: " + jsonResponse.optString("error"));
                                return;
                            }

                            sessionToken = jsonResponse.getString("sessionToken");
                            String serverAlgorithm = jsonResponse.getString("algorithm");
                            JSONObject serverPublicKey = jsonResponse.getJSONObject("serverPublicKey");

                            // ✅ BẮT BUỘC: Server PHẢI gửi signature
                            if (!jsonResponse.has("sessionSignature")
                                    || !jsonResponse.has("serverSignaturePublicKey")) {
                                hideProgress();
                                Log.e(TAG, "❌ SECURITY ERROR: Server did not provide signature!");
                                showError("Security Error: Server signature missing!\n" +
                                        "This server is not secure. Please contact administrator.");
                                return; // ❌ REJECT SESSION
                            }

                            // ✅ BẮT BUỘC: Verify session signature
                            try {
                                JSONObject sessionSignatureJson = jsonResponse.getJSONObject("sessionSignature");
                                JSONObject serverSigPubKey = jsonResponse.getJSONObject("serverSignaturePublicKey");

                                // Store server signature public key FIRST
                                cryptoManager.setServerSignaturePublicKey(serverSigPubKey);

                                // Extract session data from JWT
                                String sessionId = extractSessionIdFromJWT(sessionToken);
                                if (sessionId.isEmpty()) {
                                    hideProgress();
                                    showError("Failed to extract session ID from token");
                                    return;
                                }

                                // Reconstruct session data
                                JSONObject sessionData = new JSONObject();
                                sessionData.put("sessionId", sessionId);
                                sessionData.put("algorithm", serverAlgorithm);
                                sessionData.put("userId", userId);
                                sessionData.put("createdAt", extractCreatedAtFromJWT(sessionToken));

                                String sessionDataString = sessionData.toString();

                                Log.d(TAG, "Verifying session signature (MANDATORY)...");

                                // ✅ Use Method 2: verify with JSONObject signature and publicKey
                                boolean verified = cryptoManager.verifyServerSignature(
                                        sessionDataString, // String message
                                        sessionSignatureJson, // JSONObject signature
                                        serverSigPubKey // JSONObject publicKey
                                );

                                if (!verified) {
                                    hideProgress();
                                    Log.e(TAG, "❌ SECURITY ALERT: Session signature verification FAILED!");
                                    showError("SECURITY ALERT!\n\n" +
                                            "Server signature verification failed!\n" +
                                            "This could indicate:\n" +
                                            "• Man-in-the-middle attack\n" +
                                            "• Server compromise\n" +
                                            "• Network tampering\n\n" +
                                            "DO NOT PROCEED!");
                                    return;
                                }

                                Log.d(TAG, "✅ Session signature verified successfully!");

                            } catch (Exception e) {
                                hideProgress();
                                Log.e(TAG, "Error verifying session signature", e);
                                showError("Security Error: " + e.getMessage());
                                return;
                            }

                            // ✅ Only proceed if signature verified
                            Log.d(TAG, "Proceeding to key exchange...");
                            updateProgress("Exchanging keys...");
                            performKeyExchange(serverPublicKey);

                        } catch (Exception e) {
                            hideProgress();
                            Log.e(TAG, "Error parsing session response", e);
                            showError("Failed to create session: " + e.getMessage());
                        }
                    });
                }

                /**
                 * Extract sessionId from JWT token (decode payload)
                 */
                private String extractSessionIdFromJWT(String jwtToken) {
                    try {
                        String[] parts = jwtToken.split("\\.");
                        if (parts.length != 3) {
                            return "";
                        }

                        String payload = parts[1];
                        while (payload.length() % 4 != 0) {
                            payload += "=";
                        }

                        byte[] decodedBytes = android.util.Base64.decode(
                                payload.replace('-', '+').replace('_', '/'),
                                android.util.Base64.NO_WRAP);

                        String decodedString = new String(decodedBytes, "UTF-8");
                        JSONObject payloadJson = new JSONObject(decodedString);

                        return payloadJson.optString("sid", "");

                    } catch (Exception e) {
                        Log.e(TAG, "Error extracting sessionId from JWT", e);
                        return "";
                    }
                }

                /**
                 * Extract createdAt from JWT token
                 */
                private long extractCreatedAtFromJWT(String jwtToken) {
                    try {
                        String[] parts = jwtToken.split("\\.");
                        if (parts.length != 3) {
                            return System.currentTimeMillis();
                        }

                        String payload = parts[1];
                        while (payload.length() % 4 != 0) {
                            payload += "=";
                        }

                        byte[] decodedBytes = android.util.Base64.decode(
                                payload.replace('-', '+').replace('_', '/'),
                                android.util.Base64.NO_WRAP);

                        String decodedString = new String(decodedBytes, "UTF-8");
                        JSONObject payloadJson = new JSONObject(decodedString);

                        return payloadJson.optLong("createdAt", System.currentTimeMillis());

                    } catch (Exception e) {
                        Log.e(TAG, "Error extracting createdAt from JWT", e);
                        return System.currentTimeMillis();
                    }
                }
            });

        } catch (Exception e) {
            hideProgress();
            Log.e(TAG, "Error creating session", e);
            showError("Failed to create session: " + e.getMessage());
        }
    }

    private void performKeyExchange(JSONObject serverPublicKey) {
        try {
            cryptoManager.generateKeyPair();
            JSONObject clientPublicKey = cryptoManager.getPublicKeyJson();
            cryptoManager.computeSharedSecret(serverPublicKey);

            JSONObject requestBody = new JSONObject();
            requestBody.put("sessionToken", sessionToken);
            requestBody.put("clientPublicKey", clientPublicKey);

            if (!cryptoManager.isSignatureSupported()) {
                hideProgress();
                showError("Signature not supported");
                return;
            }

            try {
                String publicKeyString = clientPublicKey.toString();

                Log.d(TAG, "Signing with EPHEMERAL key (key exchange)...");

                // ✅ Sign with EPHEMERAL keypair
                CryptoManager.SignatureWithPublicKey signResult = cryptoManager.signMessageEphemeral(publicKeyString);

                // ✅ Include signature + ephemeral public key
                requestBody.put("clientPublicKeySignature", signResult.signature.toJSON());
                requestBody.put("clientSignaturePublicKey", signResult.publicKey);

                Log.d(TAG, "✅ Signed with EPHEMERAL key");

            } catch (Exception e) {
                hideProgress();
                Log.e(TAG, "Failed to sign", e);
                showError("Failed to sign: " + e.getMessage());
                return;
            }

            RequestBody body = RequestBody.create(
                    requestBody.toString(),
                    MediaType.parse("application/json"));

            Request request = new Request.Builder()
                    .url(BASE_URL + "/session/exchange?userId=" + userId)
                    .addHeader("x-user-id", userId)
                    .post(body)
                    .build();

            client.newCall(request).enqueue(new Callback() {
                @Override
                public void onFailure(Call call, IOException e) {
                    runOnUiThread(() -> {
                        hideProgress();
                        handleNetworkError(e);
                    });
                }

                @Override
                public void onResponse(Call call, Response response) throws IOException {
                    String responseBody = response.body().string();

                    final String finalResponseBody = responseBody;
                    final int responseCode = response.code();
                    final boolean isSuccessful = response.isSuccessful();

                    runOnUiThread(() -> {
                        hideProgress();

                        if (isSuccessful) {
                            try {
                                JSONObject jsonResponse = new JSONObject(finalResponseBody);

                                if (!jsonResponse.getBoolean("success")) {
                                    String error = jsonResponse.optString("error", "Unknown error");
                                    showError("Key exchange failed: " + error);
                                    return;
                                }

                                // Get updated JWT token
                                String updatedToken = jsonResponse.optString("sessionToken", sessionToken);
                                sessionToken = updatedToken;

                                // ✅ BẮT BUỘC: Check if server verified our signature
                                if (!jsonResponse.has("clientSignatureVerified")) {
                                    showError("Server did not verify client signature");
                                    return;
                                }

                                boolean clientSigVerified = jsonResponse.getBoolean("clientSignatureVerified");
                                if (!clientSigVerified) {
                                    Log.e(TAG, "❌ Server rejected client signature!");
                                    showError("SECURITY ERROR!\n\n" +
                                            "Server rejected your signature.\n" +
                                            "This should never happen.\n" +
                                            "Please check your cryptographic implementation.");
                                    return; // ❌ Server rejected us
                                }

                                Log.d(TAG, "✅ Server verified client signature successfully");
                                Log.d(TAG, "✅ Mutual authentication complete");

                                if (cryptoManager.isKeyExchangeComplete()) {
                                    // Key exchange successful
                                    saveSuccessfulLogin();
                                    proceedToChatActivity();
                                } else {
                                    showError("Key exchange incomplete");
                                }
                            } catch (Exception e) {
                                Log.e(TAG, "Error parsing key exchange response", e);
                                showError("Failed to parse key exchange response: " + e.getMessage());
                            }
                        } else {
                            handleServerError(responseCode, finalResponseBody);
                        }
                    });
                }
            });

        } catch (Exception e) {
            hideProgress();
            Log.e(TAG, "Error in key exchange", e);
            showError("Key exchange failed: " + e.getMessage());
        }
    }

    private void attemptSessionRestore(String savedUserId, String savedSessionToken) {
        showProgress("Restoring session...");

        // Check if session is still valid
        Request request = new Request.Builder()
                .url(BASE_URL + "/session/status?token=" + savedSessionToken + "&userId=" + savedUserId)
                .get()
                .build();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                runOnUiThread(() -> {
                    hideProgress();
                    Log.d(TAG, "Session restore failed, need new login");
                });
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                String responseBody = "";
                try {
                    responseBody = response.body().string();
                } catch (Exception e) {
                    Log.e(TAG, "Error reading response body", e);
                }

                // Create final copy for lambda
                final String finalResponseBody = responseBody;
                final boolean isSuccessful = response.isSuccessful();

                runOnUiThread(() -> {
                    hideProgress();

                    if (isSuccessful) {
                        try {
                            JSONObject result = new JSONObject(finalResponseBody);
                            boolean exists = result.getBoolean("exists");

                            if (exists) {
                                // Session still valid, go to chat
                                proceedToChatActivity(savedUserId, savedSessionToken);
                            } else {
                                // Session expired, clear and stay in login
                                clearSavedCredentials();
                            }
                        } catch (Exception e) {
                            clearSavedCredentials();
                        }
                    } else {
                        clearSavedCredentials();
                    }
                });
            }
        });
    }

    private void saveSuccessfulLogin() {
        // Save crypto manager to singleton
        CryptoSingleton.getInstance().setCryptoManager(cryptoManager);

        // Save basic session info
        prefs.edit()
                .putString("userId", userId)
                .putString("sessionToken", sessionToken)
                .putBoolean("freshLogin", true)
                .apply();
    }

    private void clearSavedCredentials() {
        // Clear singleton
        CryptoSingleton.getInstance().clear();

        // Clear preferences
        prefs.edit().clear().apply();
    }

    private void proceedToChatActivity() {
        proceedToChatActivity(userId, sessionToken);
    }

    private void proceedToChatActivity(String userId, String sessionToken) {
        Intent intent = new Intent(this, ChatActivity.class);
        intent.putExtra("userId", userId);
        intent.putExtra("sessionToken", sessionToken);
        intent.putExtra("algorithmName", cryptoManager != null ? cryptoManager.getAlgorithmName() : "Unknown");
        intent.putExtra("freshLogin", true); // Indicate this is a fresh login with key exchange
        startActivity(intent);
        finish();
    }

    private void showProgress(String message) {
        if (progressDialog == null) {
            progressDialog = new ProgressDialog(this);
            progressDialog.setCancelable(false);
        }
        progressDialog.setMessage(message);
        progressDialog.show();
    }

    private void updateProgress(String message) {
        if (progressDialog != null && progressDialog.isShowing()) {
            progressDialog.setMessage(message);
        }
    }

    private void hideProgress() {
        if (progressDialog != null && progressDialog.isShowing()) {
            progressDialog.dismiss();
        }
    }

    private void showError(String message) {
        new AlertDialog.Builder(this)
                .setTitle("Login Error")
                .setMessage(message)
                .setPositiveButton("OK", null)
                .setIcon(android.R.drawable.ic_dialog_alert)
                .show();
    }

    private void handleNetworkError(IOException e) {
        Log.e(TAG, "Network error", e);

        // Check if it's SSL pinning error
        if (e.getMessage() != null &&
                (e.getMessage().contains("Certificate pinning failure") ||
                        e.getMessage().contains("peer not authenticated"))) {
            showSSLPinningError();
        } else {
            showError("Network error: " + e.getMessage());
        }
    }

    private void showSSLPinningError() {
        new AlertDialog.Builder(this)
                .setTitle("Security Warning")
                .setMessage(
                        "SSL Certificate pinning failed. This could indicate a security issue or the server certificate has changed.")
                .setPositiveButton("OK", null)
                .setIcon(android.R.drawable.ic_dialog_alert)
                .show();
    }

    private void handleServerError(int statusCode, String responseBody) {
        String errorMessage = "Server error: " + statusCode;

        switch (statusCode) {
            case 400:
                errorMessage = "Bad request - Missing userId";
                break;
            case 403:
                errorMessage = "Access forbidden - Invalid userId";
                break;
            case 429:
                errorMessage = "Daily quota exceeded";
                break;
            case 430:
                errorMessage = "Too many requests per minute";
                break;
        }

        showError(errorMessage);
    }
}