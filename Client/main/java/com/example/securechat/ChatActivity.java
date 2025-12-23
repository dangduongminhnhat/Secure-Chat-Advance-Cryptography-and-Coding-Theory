package com.example.securechat;

import com.example.securechat.crypto.AlgorithmSelector;
import com.example.securechat.crypto.SignatureBase;

import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import org.json.JSONObject;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.CertificatePinner;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class ChatActivity extends AppCompatActivity {
    private static final String TAG = "ChatActivity";
    private static final String BASE_URL = "https://secure-chat.your-name.workers.dev";
    private static final String HOSTNAME = "secure-chat.your-name.workers.dev";
    private static final String SPKI_BASE64 = "YOUR_SPKI_BASE64";

    private EditText inputMessage;
    private Button sendButton, logoutButton;
    private TextView statusText;
    private RecyclerView messagesRecyclerView;
    private MessageAdapter messageAdapter;
    private List<Message> messages;

    private OkHttpClient client;
    private String userId;
    private String sessionToken;
    private String algorithmName;
    private CryptoManager cryptoManager;
    private boolean freshLogin;
    private ProgressDialog progressDialog;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_chat);

        initViews();
        setupRecyclerView();

        // Get data from intent
        userId = getIntent().getStringExtra("userId");
        sessionToken = getIntent().getStringExtra("sessionToken");
        algorithmName = getIntent().getStringExtra("algorithmName");
        freshLogin = getIntent().getBooleanExtra("freshLogin", false);

        if (userId == null || sessionToken == null) {
            Toast.makeText(this, "Invalid session data", Toast.LENGTH_SHORT).show();
            finish();
            return;
        }

        client = buildClient();

        // Get crypto manager from singleton
        cryptoManager = CryptoSingleton.getInstance().getCryptoManager();

        if (freshLogin && CryptoSingleton.getInstance().isReady()) {
            // Fresh login with crypto ready
            setStatusText("Connected & Encrypted (" + algorithmName + ")");
            showWelcomeMessages(true, algorithmName);
        } else {
            // Restored session or crypto not ready
            showProgress("Verifying session...");
            verifyRestoredSession();
        }

        sendButton.setOnClickListener(v -> {
            String message = inputMessage.getText().toString().trim();
            if (message.isEmpty())
                return;

            sendMessage(message);
            inputMessage.setText("");
        });

        logoutButton.setOnClickListener(v -> logout());
    }

    private void initViews() {
        inputMessage = findViewById(R.id.inputMessage);
        sendButton = findViewById(R.id.sendButton);
        logoutButton = findViewById(R.id.logoutButton);
        statusText = findViewById(R.id.statusText);
        messagesRecyclerView = findViewById(R.id.messagesRecyclerView);
    }

    private void setupRecyclerView() {
        messages = new ArrayList<>();
        messageAdapter = new MessageAdapter(messages);
        messagesRecyclerView.setLayoutManager(new LinearLayoutManager(this));
        messagesRecyclerView.setAdapter(messageAdapter);
    }

    private void verifyRestoredSession() {
        Request request = new Request.Builder()
                .url(BASE_URL + "/session/status?token=" + sessionToken + "&userId=" + userId)
                .addHeader("x-user-id", userId)
                .get()
                .build();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                runOnUiThread(() -> {
                    hideProgress();
                    showError("Session verification failed. Please login again.");
                    finish();
                });
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                String responseBody = response.body().string();

                runOnUiThread(() -> {
                    hideProgress();

                    if (response.isSuccessful()) {
                        try {
                            JSONObject result = new JSONObject(responseBody);

                            if (!result.getBoolean("success")) {
                                showError("Session verification failed. Please login again.");
                                finish();
                                return;
                            }

                            boolean exists = result.getBoolean("exists");
                            String serverAlgorithm = result.optString("algorithm", "Unknown");

                            if (exists) {
                                // Session is valid but no crypto - limited functionality
                                setStatusText("Connected (Session Restored - " + serverAlgorithm + ")");
                                showWelcomeMessages(false, serverAlgorithm);
                            } else {
                                showError("Session expired. Please login again.");
                                clearSavedCredentials();
                                finish();
                            }
                        } catch (Exception e) {
                            showError("Invalid session response. Please login again.");
                            finish();
                        }
                    } else {
                        showError("Session verification failed. Please login again.");
                        finish();
                    }
                });
            }
        });
    }

    private void setStatusText(String status) {
        runOnUiThread(() -> statusText.setText("Status: " + status));
    }

    private void addMessage(String content, boolean isFromUser) {
        runOnUiThread(() -> {
            messages.add(new Message(content, isFromUser, System.currentTimeMillis()));
            messageAdapter.notifyItemInserted(messages.size() - 1);
            messagesRecyclerView.scrollToPosition(messages.size() - 1);
        });
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

    private void showWelcomeMessages(boolean isFreshLogin, String algorithm) {
        if (isFreshLogin && CryptoSingleton.getInstance().isReady()) {
            addMessage("🔒 Secure connection established", false);
            addMessage("🔐 Algorithm: " + algorithm, false);
            addMessage("✅ Full end-to-end encryption active", false);
        } else {
            addMessage("🔄 Session restored", false);
            addMessage("🔐 Algorithm: " + algorithm, false);
            addMessage("⚠️ Limited functionality - login again for full E2E encryption", false);
        }
        addMessage("You can ask me about: name, age, location, hobby", false);
    }

    private void sendMessage(String message) {
        if (!CryptoSingleton.getInstance().isReady()) {
            addMessage("❌ Encryption not available", false);
            return;
        }

        try {
            JSONObject requestBody = new JSONObject();
            requestBody.put("sessionToken", sessionToken);

            String encryptedMessage;
            try {
                if ("ecdh_3".equals(AlgorithmSelector.getAlgorithmForUser(userId))) {
                    cryptoManager.setEncryptionMode("CBC");
                }
                encryptedMessage = cryptoManager.encrypt(message);
                requestBody.put("encryptedMessage", encryptedMessage);
            } catch (Exception e) {
                addMessage("❌ Encryption failed", false);
                return;
            }

            if (!cryptoManager.isSignatureSupported()) {
                addMessage("❌ Signature not supported", false);
                return;
            }

            try {
                Log.d(TAG, "Signing message with EPHEMERAL key...");

                // ✅ Sign with NEW EPHEMERAL keypair for THIS message
                CryptoManager.SignatureWithPublicKey signResult = cryptoManager.signMessageEphemeral(encryptedMessage);

                requestBody.put("messageSignature", signResult.signature.toJSON());
                requestBody.put("clientSignaturePublicKey", signResult.publicKey);

                Log.d(TAG, "✅ Message signed with EPHEMERAL key");

            } catch (Exception e) {
                addMessage("❌ Failed to sign: " + e.getMessage(), false);
                return;
            }

            RequestBody body = RequestBody.create(
                    requestBody.toString(),
                    MediaType.parse("application/json"));

            Request request = new Request.Builder()
                    .url(BASE_URL + "/message/send?userId=" + userId)
                    .addHeader("x-user-id", userId)
                    .post(body)
                    .build();

            addMessage(message, true);

            client.newCall(request).enqueue(new Callback() {
                @Override
                public void onFailure(Call call, IOException e) {
                    runOnUiThread(() -> addMessage("❌ Send failed", false));
                }

                @Override
                public void onResponse(Call call, Response response) throws IOException {
                    String responseBody = response.body().string();

                    runOnUiThread(() -> {
                        if (response.isSuccessful()) {
                            try {
                                JSONObject jsonResponse = new JSONObject(responseBody);

                                if (!jsonResponse.getBoolean("success")) {
                                    addMessage("❌ " + jsonResponse.optString("error"), false);
                                    return;
                                }

                                // Update session token
                                String newToken = jsonResponse.optString("sessionToken", null);
                                if (newToken != null) {
                                    sessionToken = newToken;
                                    getSharedPreferences("SecureChat", MODE_PRIVATE)
                                            .edit().putString("sessionToken", sessionToken).apply();
                                }

                                // ✅ Server MUST provide signature + ephemeral public key
                                if (!jsonResponse.has("responseSignature") ||
                                        !jsonResponse.has("serverSignaturePublicKey")) {
                                    addMessage("❌ Server response not signed!", false);
                                    return;
                                }

                                String encryptedResponse = jsonResponse.getString("encryptedResponse");
                                JSONObject respSigJson = jsonResponse.getJSONObject("responseSignature");
                                JSONObject serverEphemeralPubKey = jsonResponse
                                        .getJSONObject("serverSignaturePublicKey");

                                Log.d(TAG, "Verifying response with server's EPHEMERAL public key...");

                                try {
                                    SignatureBase.Signature respSignature = SignatureBase.Signature.fromJSON(
                                            respSigJson,
                                            cryptoManager.getSignatureAlgorithmName());

                                    // ✅ Verify with server's EPHEMERAL public key from THIS response
                                    // Create temporary crypto manager for verification with different public key
                                    boolean verified = cryptoManager.verifySignatureWithPublicKey(
                                            encryptedResponse,
                                            respSignature,
                                            serverEphemeralPubKey // ✅ Use ephemeral key from response
                                    );

                                    if (!verified) {
                                        Log.e(TAG, "❌ Response signature verification FAILED");
                                        addMessage("❌ SECURITY ALERT: Invalid signature!", false);
                                        return;
                                    }

                                    Log.d(TAG, "✅ Response signature verified (EPHEMERAL key)");

                                } catch (Exception e) {
                                    addMessage("❌ Signature verification error", false);
                                    return;
                                }

                                // Decrypt response
                                try {
                                    if ("ecdh_3".equals(AlgorithmSelector.getAlgorithmForUser(userId))) {
                                        cryptoManager.setEncryptionMode("CBC");
                                    }
                                    String decryptedResponse = cryptoManager.decrypt(encryptedResponse);
                                    addMessage(decryptedResponse, false);
                                } catch (Exception e) {
                                    addMessage("❌ Decryption failed", false);
                                }

                            } catch (Exception e) {
                                addMessage("❌ Error: " + e.getMessage(), false);
                            }
                        } else {
                            handleServerError(response.code(), responseBody);
                        }
                    });
                }
            });

        } catch (Exception e) {
            addMessage("❌ Error: " + e.getMessage(), false);
        }
    }

    private void showProgress(String message) {
        if (progressDialog == null) {
            progressDialog = new ProgressDialog(this);
            progressDialog.setCancelable(false);
        }
        progressDialog.setMessage(message);
        progressDialog.show();
    }

    private void hideProgress() {
        if (progressDialog != null && progressDialog.isShowing()) {
            progressDialog.dismiss();
        }
    }

    private void showError(String message) {
        new AlertDialog.Builder(this)
                .setTitle("Error")
                .setMessage(message)
                .setPositiveButton("OK", null)
                .setIcon(android.R.drawable.ic_dialog_alert)
                .show();
    }

    private void handleServerError(int statusCode, String responseBody) {
        String errorMessage = "Server error: " + statusCode;

        try {
            JSONObject errorJson = new JSONObject(responseBody);
            if (errorJson.has("error")) {
                errorMessage = errorJson.getString("error");
            }
        } catch (Exception e) {
            // Use default message
        }

        switch (statusCode) {
            case 400:
                if (errorMessage.contains("Missing required fields")) {
                    errorMessage = "Missing required fields - check encryption";
                }
                break;
            case 403:
                errorMessage = "Access forbidden";
                break;
            case 404:
                errorMessage = "Session expired";
                logout();
                return;
            case 429:
                errorMessage = "Daily quota exceeded";
                break;
            case 430:
                errorMessage = "Too many requests per minute";
                break;
        }

        addMessage("❌ " + errorMessage, false);
    }

    private void clearSavedCredentials() {
        CryptoSingleton.getInstance().clear();
        SharedPreferences prefs = getSharedPreferences("SecureChat", MODE_PRIVATE);
        prefs.edit().clear().apply();
    }

    private void logout() {
        // Delete session on server
        try {
            JSONObject requestBody = new JSONObject();
            requestBody.put("sessionToken", sessionToken);

            RequestBody body = RequestBody.create(
                    requestBody.toString(),
                    MediaType.parse("application/json"));

            Request request = new Request.Builder()
                    .url(BASE_URL + "/session/delete?userId=" + userId)
                    .addHeader("x-user-id", userId)
                    .post(body)
                    .build();

            client.newCall(request).enqueue(new Callback() {
                @Override
                public void onFailure(Call call, IOException e) {
                    Log.d(TAG, "Session deletion failed (server might be down)");
                }

                @Override
                public void onResponse(Call call, Response response) {
                    Log.d(TAG, "Session deleted on server");
                }
            });

        } catch (Exception e) {
            Log.e(TAG, "Error deleting session", e);
        }

        // Clear local storage
        clearSavedCredentials();

        // Go back to login
        finish();
    }

    @Override
    public void onBackPressed() {
        new AlertDialog.Builder(this)
                .setTitle("Logout")
                .setMessage("Do you want to logout?")
                .setPositiveButton("Yes", (dialog, which) -> logout())
                .setNegativeButton("No", null)
                .show();
    }
}