# SecureChat: E2EE Mobile Messaging System

> An **educational proof-of-concept secure messaging application** developed as a **course assignment** for **Advanced Cryptography and Coding Theory**.

> A proof-of-concept secure messaging application implementing **End-to-End Encryption (E2EE)**, **ECDH Key Exchange**, and **Digital Signatures**. Built with Android (Java) and Cloudflare Workers (Serverless).

![Platform](https://img.shields.io/badge/Platform-Android%20%7C%20Cloudflare%20Workers-orange?style=flat-square)
![Status](https://img.shields.io/badge/Status-Educational%20%2F%20PoC-green?style=flat-square)

## Overview

**SecureChat** demonstrates modern cryptography concepts applied to a real-world scenario. It ensures that messages remain private between users, verifying identity through signatures, and securing the transport layer against MITM attacks.

> ⚠️ This project is **not intended for production use**.

### Key Cryptographic Features

- **End-to-End Encryption:** Messages are encrypted on the device using shared secrets derived via **ECDH (Elliptic Curve Diffie-Hellman)**.
- **Digital Signatures (Non-Repudiation):** Every message is signed using **ECDSA**, ensuring the sender cannot deny sending the message.
- **Forward Secrecy:** Ephemeral keys are generated for sessions to protect past communications.
- **Security Hardening:**
  - **Root Detection:** The app detects and restricts usage on rooted/jailbroken devices.
  - **SSL/Certificate Pinning:** Prevents Man-in-the-Middle (MITM) attacks by validating the server's certificate hash.
  - **Replay Attack Protection:** Timestamp and nonce validation.

## 🎓 Academic Context & Intended Vulnerabilities

Although SecureChat uses standard cryptographic algorithms, the system **intentionally contains cryptographic weaknesses** embedded at the protocol or implementation level.

### Intentional Cryptographic Vulnerabilities

The application includes **three deliberately introduced cryptographic vulnerabilities**, each associated with a dedicated test account:

- **`group-1`** — Cryptographic vulnerability #1
- **`group-2`** — Cryptographic vulnerability #2
- **`group-3`** — Cryptographic vulnerability #3

Each vulnerability is designed to:

- Represent a **realistic cryptographic misuse or design flaw**
- Encourage **cryptanalysis, protocol review, or implementation analysis**
- Highlight common mistakes in applied cryptography

> Students are expected to identify the vulnerability, explain its **root cause**, analyze its **security impact**, and propose a **secure mitigation or redesign**.

## Architecture

The project follows a Monorepo structure:

- **`client/` (Android):** Native Android app acting as the secure terminal. Handles key generation, encryption, and UI.
- **`server/` (Cloudflare Worker):** A lightweight, serverless API handling user registration, message routing, and temporary storage (KV). **It never sees the plaintext messages.**

## Installation & Setup Guide

Prerequisites:

- **Node.js** (v16+) & npm
- **Android Studio** (Koala or newer recommended)
- **Cloudflare Account** (Free tier works)

### Part 1: Server Setup (Cloudflare Workers)

1.  **Navigate to the server directory:**

    ```bash
    cd server
    ```

2.  **Install dependencies:**

    ```bash
    npm install
    ```

3.  **Authenticate with Cloudflare:**

    ```bash
    npx wrangler login
    ```

    _This will open your browser to authorize Wrangler._

4.  **Setup the Database (KV Namespace):**
    Create a KV namespace to store user quotas and public keys:

    ```bash
    npx wrangler kv:namespace create "USER_KV"
    ```

    _Output Example:_

    ```text
    { binding = "USER_KV", id = "e44c839d-xxxx-xxxx-xxxx-xxxxxxxxxxxx" }
    ```

5.  **Configure `wrangler.toml`:**
    Open `server/wrangler.toml` and update the `kv_namespaces` section with the **ID** you got in the previous step:

    ```toml
    [[kv_namespaces]]
    binding = "USER_KV"
    id = "YOUR_NEW_ID_HERE"
    ```

6.  **Deploy the Server:**
    ```bash
    npx wrangler deploy
    ```
    **Note the URL:** After deployment, Wrangler will output your worker URL (e.g., `https://secure-chat.your-name.workers.dev`). You will need this for the client.

### Part 2: Client Setup (Android)

1.  **Open the Project:**
    Open Android Studio -> Select `Open` -> Navigate to the `client/` folder.

2.  **Configure the Server URL:**
    Open `app/src/main/java/com/example/securechat/ChatActivity.java` (and `LoginActivity.java` if applicable).
    Update the `BASE_URL` constant with your Cloudflare Worker URL from Part 1.

    ```java
    // In ChatActivity.java
    private static final String BASE_URL = "<<https://secure-chat.your-name.workers.dev>>";
    ```

3.  **Configure SSL Pinning (Crucial for Security):**
    If you are using your own domain, you must update the Certificate Hash (SPKI).

    - _For testing/development:_ You can temporarily disable the `CertificatePinner` block in `NetworkUtils.java` or `ChatActivity.java`.
    - _For production:_ Run this command to get your domain's hash:
      ```bash
      openssl s_client -servername your-worker.workers.dev -connect your-worker.workers.dev:443 | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
      ```
      Update the `SPKI_BASE64` string in the Android code with this new hash.

4.  **Build and Run:**
    - Sync Gradle files.
    - Connect an Android Device (must be **Non-Rooted**) or use an Emulator (ensure it's a standard production image, not a Google APIs image with root access).
    - Click **Run**.

## ⚠️ Security Disclaimer

- This project is **intentionally vulnerable**.
- It is designed **for educational evaluation only**.
- Do **not** reuse any cryptographic design or code from this project in real-world systems without proper security review.
