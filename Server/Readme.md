# 🎨 SECURE CHAT - KIẾN TRÚC HOÀN CHỈNH VỚI EPHEMERAL SIGNATURES

---

## 📊 1. TỔNG QUAN KIẾN TRÚC HỆ THỐNG

```mermaid
graph TB
    subgraph "🤖 ANDROID CLIENT"
        subgraph "📱 Presentation Layer"
            LA[LoginActivity<br/>━━━━━━━━━<br/>• User input<br/>• Session restore<br/>• Progress display]
            CA[ChatActivity<br/>━━━━━━━━━<br/>• Message UI<br/>• RecyclerView<br/>• Status display]
        end

        subgraph "💼 Business Logic"
            CS[CryptoSingleton<br/>━━━━━━━━━<br/>• Global state<br/>• isReady flag]
            CM[CryptoManager<br/>━━━━━━━━━<br/>• Orchestrator<br/>• Key management]
        end

        subgraph "🔐 Crypto Factories"
            KF[KeyExchangeFactory<br/>━━━━━━━━━<br/>• Algorithm registry<br/>• Instance creation]
            SF[SignatureFactory<br/>━━━━━━━━━<br/>• Signature registry<br/>• Instance creation]
        end

        subgraph "🔑 Key Exchange Implementations"
            ECDH[ECDHKeyExchange<br/>━━━━━━━━━<br/>P-192 Curve<br/>• Point addition<br/>• Scalar mult]
            RSA[RSAKeyExchange<br/>━━━━━━━━━<br/>2048-bit<br/>• Future support]
            DH[DHKeyExchange<br/>━━━━━━━━━<br/>2048-bit<br/>• Future support]
        end

        subgraph "✍️ Signature Implementations"
            ECDSA[ECDSASignature<br/>━━━━━━━━━<br/>P-192 Curve<br/>• SHA-256 hash<br/>• <b>EPHEMERAL keys</b>]
            RSAPSS[RSAPSSSignature<br/>━━━━━━━━━<br/>2048-bit<br/>• Future support]
        end

        subgraph "🔒 Encryption"
            ENC[AES-256-GCM<br/>━━━━━━━━━<br/>• PBKDF2 derivation<br/>• Random IV per msg]
        end

        subgraph "💾 Storage"
            SP[SharedPreferences<br/>━━━━━━━━━<br/>• userId<br/>• sessionToken]
            MEM[Memory Cache<br/>━━━━━━━━━<br/>• CryptoManager<br/>• Keys in RAM]
        end

        subgraph "🌐 Network"
            OK[OkHttpClient<br/>━━━━━━━━━<br/>• SSL Pinning<br/>• Certificate validation]
        end

        LA --> CM
        CA --> CM
        CM --> CS
        CM --> KF
        CM --> SF
        CM --> ENC
        KF --> ECDH
        KF --> RSA
        KF --> DH
        SF --> ECDSA
        SF --> RSAPSS
        CS --> SP
        CS --> MEM
        LA --> OK
        CA --> OK
    end

    subgraph "☁️ CLOUDFLARE WORKER SERVER"
        subgraph "🚪 Entry Layer"
            EP[fetch handler<br/>━━━━━━━━━<br/>• Route matching<br/>• CORS handling]
            RL[rateLimits.js<br/>━━━━━━━━━<br/>• Quota: 16,600/day<br/>• Rate: per-minute<br/>• Whitelist: group-1]
        end

        subgraph "🎯 Handler Layer"
            RH[RequestHandler<br/>━━━━━━━━━<br/>• Route dispatcher<br/>• Business logic]
            RSP[ResponseHandler<br/>━━━━━━━━━<br/>• JSON formatter<br/>• Error handling]
        end

        subgraph "🎫 Session Layer"
            SM[SessionManager<br/>━━━━━━━━━<br/>• JWT stateless<br/>• <b>EPHEMERAL signer</b>]
            JWT[JWTManager<br/>━━━━━━━━━<br/>• HMAC-SHA256<br/>• AES-GCM encrypt<br/>• 120s TTL]
        end

        subgraph "🔐 Crypto Layer"
            KF2[KeyExchangeFactory<br/>━━━━━━━━━<br/>• ecdh → ECDH]
            SF2[SignatureFactory<br/>━━━━━━━━━<br/>• ecdh → ECDSA]

            subgraph "Key Exchange"
                ECDH2[ECDH P-192<br/>━━━━━━━━━<br/>• Same curve as client]
            end

            subgraph "Signatures"
                ECDSA2[ECDSASignature<br/>━━━━━━━━━<br/>• <b>EPHEMERAL mode</b><br/>• New keypair/sign]
            end

            ENC2[Encryption<br/>━━━━━━━━━<br/>• AES-256-GCM<br/>• PBKDF2]
        end

        EP --> RL
        RL --> RH
        RH --> SM
        RH --> RSP
        SM --> JWT
        SM --> KF2
        SM --> SF2
        SM --> ENC2
        KF2 --> ECDH2
        SF2 --> ECDSA2
    end

    OK -->|HTTPS/TLS 1.3<br/>Certificate Pinning| EP

    style LA fill:#e3f2fd
    style CA fill:#e3f2fd
    style CM fill:#fff9c4
    style SM fill:#fff9c4
    style ECDSA fill:#ffccbc
    style ECDSA2 fill:#ffccbc
    style JWT fill:#c8e6c9
    style OK fill:#ffebee
    style EP fill:#ffebee
```

---

## 🔄 2. LUỒNG HOÀN CHỈNH VỚI EPHEMERAL SIGNATURES

```mermaid
sequenceDiagram
    autonumber

    participant U as 👤 User
    participant C as 📱 Client
    participant CM as 🔐 CryptoManager
    participant N as 🌐 Network
    participant S as ☁️ Server
    participant SM as 🎫 SessionManager
    participant JWT as 🔑 JWTManager

    rect rgb(230, 245, 255)
    Note over U,JWT: 🎬 PHASE 1: SESSION CREATION

    U->>C: Enter userId: "group-1"
    C->>CM: initializeForUser("group-1")
    CM->>CM: ✅ Create ECDH instance<br/>✅ Create ECDSA instance

    C->>N: POST /session/create<br/>{algorithm: "ecdh",<br/>curveParameters: {...}}
    N->>S: HTTPS Request
    S->>S: ✅ checkQuota("group-1")<br/>16,600/day OK

    S->>SM: createSession("ecdh", params, "group-1")

    Note over SM: 🔑 Key Exchange Keys (long-term for session)
    SM->>SM: Generate ECDH keypair<br/>privateKey_server (fixed)<br/>publicKey_server

    Note over SM: ✍️ EPHEMERAL Signature Keys (1-time use)
    SM->>SM: 🆕 generateEphemeralSignatureKeyPair()<br/>signPriv_ephemeral_1<br/>signPub_ephemeral_1

    SM->>JWT: createEncryptedJWT({<br/>privateKey_server,<br/>sharedSecret: null,<br/>algorithmParams})
    JWT->>JWT: 🔐 AES-GCM encrypt sensitive data<br/>🔏 HMAC-SHA256 sign JWT
    JWT-->>SM: sessionToken (encrypted JWT)

    SM->>SM: Sign session data<br/>with signPriv_ephemeral_1
    SM->>SM: sessionSignature {r, s, hash}

    SM-->>S: {sessionToken,<br/>publicKey_server,<br/>signPub_ephemeral_1,<br/>sessionSignature}

    S-->>N: 200 OK Response
    N-->>C: Session created

    C->>C: ✅ Store sessionToken<br/>✅ Store publicKey_server<br/>✅ Store signPub_ephemeral_1

    C->>CM: verifyServerSignature(<br/>sessionData,<br/>sessionSignature,<br/>signPub_ephemeral_1)
    CM->>CM: ✅ ECDSA verify
    CM-->>C: ✅ VALID - Server authenticated
    end

    rect rgb(255, 250, 230)
    Note over U,JWT: 🔑 PHASE 2: KEY EXCHANGE

    C->>CM: generateKeyPair()
    CM->>CM: Generate ECDH keypair<br/>privateKey_client<br/>publicKey_client

    Note over CM: ✍️ NEW EPHEMERAL Signature Keys
    CM->>CM: 🆕 generateEphemeralSignatureKeyPair()<br/>signPriv_ephemeral_2<br/>signPub_ephemeral_2

    CM->>CM: Sign publicKey_client<br/>with signPriv_ephemeral_2
    CM-->>C: {publicKey_client,<br/>clientSignature,<br/>signPub_ephemeral_2}

    C->>N: POST /session/exchange<br/>{sessionToken,<br/>clientPublicKey,<br/>clientPublicKeySignature,<br/>clientSignaturePublicKey}
    N->>S: HTTPS Request

    S->>SM: getSession(sessionToken, "group-1")
    SM->>JWT: verifyToken(sessionToken)
    JWT->>JWT: ✅ HMAC verify<br/>✅ Check expiry<br/>🔓 Decrypt encrypted data
    JWT-->>SM: {privateKey_server, algorithmParams}

    S->>S: verifySignature(<br/>clientPublicKey,<br/>clientPublicKeySignature,<br/>clientSignaturePublicKey)
    S->>S: ✅ Client signature VALID

    SM->>SM: validatePublicKey(clientPublicKey)
    SM->>SM: ✅ Point on curve

    SM->>SM: computeSharedSecret<br/>= clientPublicKey × privateKey_server

    SM->>JWT: updateSession({<br/>...previousData,<br/>sharedSecret})
    JWT->>JWT: 🔐 Re-encrypt with sharedSecret
    JWT-->>SM: newSessionToken

    SM-->>S: {success: true,<br/>newSessionToken,<br/>clientSignatureVerified: true}
    S-->>N: 200 OK
    N-->>C: Key exchange complete

    C->>CM: computeSharedSecret(publicKey_server)
    CM->>CM: sharedSecret<br/>= publicKey_server × privateKey_client
    CM->>CM: ✅ SAME sharedSecret as server!

    CM->>CM: deriveAESKey(sharedSecret)<br/>PBKDF2 → AES-256 key

    C->>C: 💾 Save to CryptoSingleton<br/>✅ Encryption ready
    end

    rect rgb(230, 255, 230)
    Note over U,JWT: 💬 PHASE 3: SEND MESSAGE

    U->>C: Type: "hello"

    C->>CM: encrypt("hello")
    CM->>CM: AES-256-GCM encrypt<br/>IV = random(12 bytes)
    CM-->>C: encryptedMessage

    Note over CM: ✍️ NEW EPHEMERAL Signature Keys (#3)
    CM->>CM: 🆕 generateEphemeralSignatureKeyPair()<br/>signPriv_ephemeral_3<br/>signPub_ephemeral_3

    CM->>CM: Sign encryptedMessage<br/>with signPriv_ephemeral_3
    CM-->>C: {messageSignature,<br/>signPub_ephemeral_3}

    C->>N: POST /message/send<br/>{sessionToken,<br/>encryptedMessage,<br/>messageSignature,<br/>clientSignaturePublicKey}
    N->>S: HTTPS Request

    S->>SM: getSession(sessionToken, "group-1")
    SM->>JWT: 🔓 Decrypt JWT → sharedSecret

    S->>S: verifySignature(<br/>encryptedMessage,<br/>messageSignature,<br/>clientSignaturePublicKey)
    S->>S: ✅ Message signature VALID

    S->>S: deriveAESKey(sharedSecret)
    S->>S: 🔓 AES-256-GCM decrypt
    S->>S: Plaintext: "hello"

    S->>S: Generate response:<br/>"Hello! Nice to meet you 👋"

    S->>S: 🔐 AES-256-GCM encrypt response

    Note over SM: ✍️ NEW EPHEMERAL Signature Keys (#4)
    SM->>SM: 🆕 generateEphemeralSignatureKeyPair()<br/>signPriv_ephemeral_4<br/>signPub_ephemeral_4

    SM->>SM: Sign encryptedResponse<br/>with signPriv_ephemeral_4
    SM-->>S: {responseSignature,<br/>signPub_ephemeral_4}

    S->>SM: refreshSession(sessionToken)
    SM->>JWT: Update JWT (exp += 120s)
    JWT-->>SM: refreshedToken

    S-->>N: 200 OK<br/>{encryptedResponse,<br/>responseSignature,<br/>serverSignaturePublicKey,<br/>sessionToken}
    N-->>C: Response received

    C->>CM: verifySignatureWithPublicKey(<br/>encryptedResponse,<br/>responseSignature,<br/>serverSignaturePublicKey)
    CM->>CM: ✅ ECDSA verify with ephemeral key
    CM-->>C: ✅ Server response authentic

    C->>CM: decrypt(encryptedResponse)
    CM->>CM: 🔓 AES-256-GCM decrypt
    CM-->>C: "Hello! Nice to meet you 👋"

    C->>U: 💬 Display message
    C->>C: 💾 Update sessionToken
    end

    rect rgb(255, 235, 238)
    Note over U,JWT: 🚪 LOGOUT
    U->>C: Click Logout
    C->>N: POST /session/delete<br/>{sessionToken}
    N->>S: Delete session
    S-->>N: 200 OK
    C->>C: 🗑️ Clear CryptoSingleton<br/>🗑️ Clear SharedPreferences
    C->>U: Return to login
    end
```

---

## 🏗️ 3. MÔ HÌNH TỔNG QUÁT CHO MỌI THUẬT TOÁN

```mermaid
graph TB
    subgraph "🎭 GENERIC ALGORITHM MODEL"
        subgraph "📋 Abstract Base Classes"
            KE[KeyExchange<br/>━━━━━━━━━━━━<br/><i>Abstract Methods:</i><br/>• generatePrivateKey<br/>• generatePublicKey<br/>• computeSharedSecret<br/>• validatePublicKey<br/>• getKeySize<br/>• getParameters]

            SB[SignatureBase<br/>━━━━━━━━━━━━<br/><i>Abstract Methods:</i><br/>• generateSignatureKeyPair<br/>• signMessage<br/>• verifySignature<br/>• getSignatureSize<br/>• getParameters]
        end

        subgraph "🏭 Factory Pattern"
            KEF[KeyExchangeFactory<br/>━━━━━━━━━━━━<br/>Map algorithms<br/>━━━━━━━━━━━━<br/>'ecdh' → ECDH<br/>'rsa' → RSA<br/>'dh' → DH]

            SF[SignatureFactory<br/>━━━━━━━━━━━━<br/>Map keyExchange → Signature<br/>━━━━━━━━━━━━<br/>'ecdh' → ECDSA<br/>'rsa' → RSA-PSS<br/>'dh' → DSA]
        end

        subgraph "🔧 Concrete Implementations"
            subgraph 'Key Exchange Algorithms'
                IMPL_ECDH[ECDH<br/>━━━━━━━<br/>• P-192, P-256, P-384<br/>• Point operations<br/>• Curve validation]

                IMPL_RSA[RSA<br/>━━━━━━━<br/>• 2048, 3072, 4096 bits<br/>• Modular exponentiation<br/>• OAEP padding]

                IMPL_DH[Diffie-Hellman<br/>━━━━━━━<br/>• 2048, 3072 bits<br/>• Prime groups<br/>• Modular arithmetic]
            end

            subgraph 'Signature Algorithms'
                IMPL_ECDSA[ECDSA<br/>━━━━━━━<br/>• P-192, P-256<br/>• SHA-256 hash<br/>• <b>EPHEMERAL k</b>]

                IMPL_RSAPSS[RSA-PSS<br/>━━━━━━━<br/>• 2048, 3072 bits<br/>• SHA-256 hash<br/>• Salt: random]

                IMPL_DSA[DSA<br/>━━━━━━━<br/>• 2048/256 bits<br/>• SHA-256 hash<br/>• <b>EPHEMERAL k</b>]
            end
        end

        KE -.-> IMPL_ECDH
        KE -.-> IMPL_RSA
        KE -.-> IMPL_DH

        SB -.-> IMPL_ECDSA
        SB -.-> IMPL_RSAPSS
        SB -.-> IMPL_DSA

        KEF --> KE
        SF --> SB
    end

    subgraph "🔄 Algorithm Workflow"
        STEP1[1. User selects algorithm<br/>AlgorithmSelector.getAlgorithmForUser]
        STEP2[2. Factory creates instances<br/>KeyExchangeFactory.create<br/>SignatureFactory.create]
        STEP3[3. Initialize with params<br/>Curve/modulus/group parameters]
        STEP4[4. Generate keys<br/>Private + Public keys]
        STEP5[5. Perform operations<br/>Key exchange + Signatures]

        STEP1 --> STEP2 --> STEP3 --> STEP4 --> STEP5
    end

    subgraph "📊 Algorithm Selection Table"
        T[userId → algorithm<br/>━━━━━━━━━━━━<br/>'group-1' → 'ecdh'<br/>'group-2' → 'rsa'<br/>'group-3' → 'dh'<br/><br/>algorithm → signature<br/>━━━━━━━━━━━━<br/>'ecdh' → 'ecdsa'<br/>'rsa' → 'rsa-pss'<br/>'dh' → 'dsa']
    end

    STEP1 -.->|Uses| T

    style KE fill:#e3f2fd
    style SB fill:#e3f2fd
    style KEF fill:#fff9c4
    style SF fill:#fff9c4
    style IMPL_ECDH fill:#c8e6c9
    style IMPL_ECDSA fill:#ffccbc
    style T fill:#f0f4c3
```

---

## 🎯 4. ECDH P-192 - CHI TIẾT IMPLEMENTATION

```mermaid
graph TB
    subgraph "🔵 ECDH P-192 PARAMETERS"
        CURVE[NIST P-192 Curve<br/>━━━━━━━━━━━━━━━━<br/>Equation: y² = x³ + ax + b mod p]

        subgraph "Curve Constants"
            P[Prime p<br/>6277101735386680763835789423207666416083908700390324961279<br/>= 2^192 - 2^64 - 1]

            A[Coefficient a<br/>-3<br/>= p - 3]

            B[Coefficient b<br/>2455155546008943817740293915197451784769108058161191238065]

            G[Base Point G<br/>Gx = 3289624317623424368845348028842487418520868978772050262753<br/>Gy = 5673242899673324591834582889556471730778853907191064256384]

            ORDER[Order n<br/>6277101735386680763835789423176059013767194773182842284081<br/>Number of points on curve]
        end

        CURVE --> P
        CURVE --> A
        CURVE --> B
        CURVE --> G
        CURVE --> ORDER
    end

    subgraph "🔑 CLIENT KEY GENERATION"
        C1[Step 1: Generate Private Key<br/>━━━━━━━━━━━━━━━━<br/>privateKey_c = random 192 bits<br/>Constraint: 1 < privateKey_c < n]

        C2[Step 2: Compute Public Key<br/>━━━━━━━━━━━━━━━━<br/>publicKey_c = privateKey_c × G<br/>Result: Point Pc x_c, y_c]

        C3[Step 3: Validate<br/>━━━━━━━━━━━━━━━━<br/>Check: y_c² = x_c³ + ax_c + b mod p<br/>✅ Point on curve]

        C4["Step 4: Serialize\n━━━━━━━━━━━━━━━━\nJSON:\n  x: x_c.toString\n  y: y_c.toString"]

        C1 --> C2 --> C3 --> C4
    end

    subgraph "🔑 SERVER KEY GENERATION"
        S1[Step 1: Generate Private Key<br/>━━━━━━━━━━━━━━━━<br/>privateKey_s = fixed/random<br/>Constraint: 1 < privateKey_s < n]

        S2[Step 2: Compute Public Key<br/>━━━━━━━━━━━━━━━━<br/>publicKey_s = privateKey_s × G<br/>Result: Point Ps x_s, y_s]

        S3[Step 3: Store Privately<br/>━━━━━━━━━━━━━━━━<br/>🔐 Encrypt privateKey_s in JWT<br/>AES-256-GCM]

        S4["Step 4: Send Public Key
━━━━━━━━━━━━━━━━
JSON:
  x: x_s.toString
  y: y_s.toString"]

        S1 --> S2 --> S3 --> S4
    end

    subgraph "🔄 POINT OPERATIONS"
        subgraph "Point Addition P + Q"
            PA1[If P = Q → Point Doubling<br/>━━━━━━━━━━━━━━━━<br/>λ = 3x_p² + a / 2y_p mod p]

            PA2[If P ≠ Q → Point Addition<br/>━━━━━━━━━━━━━━━━<br/>λ = y_q - y_p / x_q - x_p mod p]

            PA3[Compute Result<br/>━━━━━━━━━━━━━━━━<br/>x_r = λ² - x_p - x_q mod p<br/>y_r = λx_p - x_r - y_p mod p]
        end

        subgraph "Scalar Multiplication k × P"
            SM1[Double-and-Add Algorithm<br/>━━━━━━━━━━━━━━━━<br/>Binary representation of k<br/>Q = O point at infinity<br/>R = P]

            SM2[For each bit of k<br/>━━━━━━━━━━━━━━━━<br/>If bit = 1: Q = Q + R<br/>R = 2R point doubling<br/>Shift to next bit]

            SM3[Return Q<br/>━━━━━━━━━━━━━━━━<br/>Result: k × P]

            SM1 --> SM2 --> SM3
        end
    end

    subgraph "🤝 SHARED SECRET COMPUTATION"
        subgraph "Client Side"
            CS1[Receive publicKey_s<br/>Point Ps x_s, y_s]
            CS2[Validate Ps<br/>y_s² = x_s³ + ax_s + b mod p]
            CS3[Compute Shared Point<br/>S_c = privateKey_c × Ps<br/>= privateKey_c × privateKey_s × G]
            CS4[Extract x-coordinate<br/>sharedSecret_c = S_c.x]

            CS1 --> CS2 --> CS3 --> CS4
        end

        subgraph "Server Side"
            SS1[Receive publicKey_c<br/>Point Pc x_c, y_c]
            SS2[Validate Pc<br/>y_c² = x_c³ + ax_c + b mod p]
            SS3[Retrieve privateKey_s<br/>🔓 Decrypt from JWT]
            SS4[Compute Shared Point<br/>S_s = privateKey_s × Pc<br/>= privateKey_s × privateKey_c × G]
            SS5[Extract x-coordinate<br/>sharedSecret_s = S_s.x]

            SS1 --> SS2 --> SS3 --> SS4 --> SS5
        end

        subgraph "Mathematical Proof"
            PROOF[S_c = S_s<br/>━━━━━━━━━━━━━━━━<br/>privateKey_c × privateKey_s × G<br/>= privateKey_s × privateKey_c × G<br/><br/>✅ Commutativity of scalar multiplication<br/>✅ Both parties have SAME sharedSecret]
        end

        CS4 -.->|Client result| PROOF
        SS5 -.->|Server result| PROOF
    end

    subgraph "🔐 AES KEY DERIVATION"
        D1[sharedSecret BigInt<br/>192 bits]
        D2[Convert to Bytes<br/>24 bytes big-endian]
        D3[PBKDF2-HMAC-SHA256<br/>━━━━━━━━━━━━━━━━<br/>Password: secretBytes<br/>Salt: 16 bytes of 0x00<br/>Iterations: 1,000<br/>Output: 32 bytes]
        D4[AES-256 Key<br/>256 bits]

        D1 --> D2 --> D3 --> D4
    end

    C4 -.->|Send to server| SS1
    S4 -.->|Send to client| CS1
    PROOF --> D1

    style CURVE fill:#e3f2fd
    style C1 fill:#fff9c4
    style S1 fill:#c8e6c9
    style CS4 fill:#ffccbc
    style SS5 fill:#ffccbc
    style PROOF fill:#f0f4c3
    style D4 fill:#c5e1a5
```

---

## ✍️ 5. EPHEMERAL SIGNATURE MODEL

```mermaid
graph TB
    subgraph "✍️ EPHEMERAL SIGNATURE ARCHITECTURE"
        subgraph "🔑 Key Types Comparison"
            subgraph "Traditional Model ❌ NOT USED"
                T1[Long-term Signature Keys<br/>━━━━━━━━━━━━━━━━<br/>Generated ONCE per session<br/>signPrivKey stored in memory<br/>signPubKey sent to other party<br/><br/>⚠️ Risk: Key compromise affects all messages<br/>⚠️ No forward secrecy for signatures]
            end

            subgraph "EPHEMERAL Model ✅ IMPLEMENTED"
                E1[Short-lived Signature Keys<br/>━━━━━━━━━━━━━━━━<br/>Generated for EACH signature operation<br/>signPrivKey used ONCE then discarded<br/>signPubKey sent WITH each signature<br/><br/>✅ Key compromise affects only 1 message<br/>✅ Forward secrecy for signatures<br/>✅ Better security properties]
            end
        end

        subgraph "📊 EPHEMERAL Usage Timeline"
            direction TB

            TIME1[Session Creation<br/>━━━━━━━━━━━━<br/>Server generates:<br/>• ephemeral_1_priv<br/>• ephemeral_1_pub<br/>Signs: sessionData<br/>🗑️ Discard ephemeral_1_priv]

            TIME2[Key Exchange<br/>━━━━━━━━━━━━<br/>Client generates:<br/>• ephemeral_2_priv<br/>• ephemeral_2_pub<br/>Signs: clientPublicKey<br/>🗑️ Discard ephemeral_2_priv]

            TIME3[Send Message #1<br/>━━━━━━━━━━━━<br/>Client generates:<br/>• ephemeral_3_priv<br/>• ephemeral_3_pub<br/>Signs: encryptedMessage<br/>🗑️ Discard ephemeral_3_priv<br/><br/>Server generates:<br/>• ephemeral_4_priv<br/>• ephemeral_4_pub<br/>Signs: encryptedResponse<br/>🗑️ Discard ephemeral_4_priv]

            TIME4[Send Message #2<br/>━━━━━━━━━━━━<br/>Client generates:<br/>• ephemeral_5_priv<br/>• ephemeral_5_pub<br/>Signs: encryptedMessage<br/>🗑️ Discard ephemeral_5_priv<br/><br/>Server generates:<br/>• ephemeral_6_priv<br/>• ephemeral_6_pub<br/>Signs: encryptedResponse<br/>🗑️ Discard ephemeral_6_priv]

            TIME1 --> TIME2 --> TIME3 --> TIME4
        end

        subgraph "🔄 EPHEMERAL Key Lifecycle"
            L1[🆕 GENERATE<br/>New random keypair<br/>SecureRandom]
            L2[✍️ SIGN<br/>Use private key ONCE<br/>Create signature]
            L3[📤 TRANSMIT<br/>Send signature + public key<br/>Together in same message]
            L4[✅ VERIFY<br/>Receiver validates<br/>with provided public key]
            L5[🗑️ DISCARD<br/>Private key destroyed<br/>Public key MAY be logged]

            L1 --> L2 --> L3 --> L4 --> L5
        end

        subgraph "🔐 Security Properties"
            P1[Forward Secrecy<br/>━━━━━━━━━━━━<br/>Compromising current key<br/>does NOT affect past signatures]

            P2[Isolation<br/>━━━━━━━━━━━━<br/>Each signature independent<br/>1 key compromise = 1 message risk]

            P3[Non-Reuse<br/>━━━━━━━━━━━━<br/>Private keys never reused<br/>Eliminates nonce reuse attacks]

            P4[Authenticity per Message<br/>━━━━━━━━━━━━<br/>Each message freshly signed<br/>Unique cryptographic proof]
        end

        subgraph "⚠️ Implementation Requirements"
            R1[MUST: Generate new keypair per sign operation<br/>━━━━━━━━━━━━━━━━━━━━━━━━━━━━]
            R2[MUST: Include public key with signature<br/>━━━━━━━━━━━━━━━━━━━━━━━━━━━━]
            R3[MUST: Verify with signature-specific public key<br/>━━━━━━━━━━━━━━━━━━━━━━━━━━━━]
            R4[MUST: Discard private key after signing<br/>━━━━━━━━━━━━━━━━━━━━━━━━━━━━]
            R5[MUST NOT: Store or reuse ephemeral private keys<br/>━━━━━━━━━━━━━━━━━━━━━━━━━━━━]
        end

        E1 --> TIME1
        L5 -.->|Ensures| P1
        L5 -.->|Ensures| P2
        L1 -.->|Ensures| P3
        L3 -.->|Ensures| P4
    end

    style E1 fill:#c8e6c9
    style T1 fill:#ffcdd2
    style L2 fill:#fff9c4
    style L5 fill:#ffccbc
    style P1 fill:#b2dfdb
    style P2 fill:#b2dfdb
    style P3 fill:#b2dfdb
    style P4 fill:#b2dfdb
    style R1 fill:#ffebee
    style R2 fill:#ffebee
    style R3 fill:#ffebee
    style R4 fill:#ffebee
    style R5 fill:#ffebee
```

---

## 🔒 6. ECDSA P-192 SIGNATURE - CHI TIẾT

```mermaid
graph TB
    subgraph "✍️ ECDSA P-192 SIGNATURE ALGORITHM"
        subgraph "📋 Parameters Same as ECDH"
            SP[Uses SAME P-192 Curve<br/>━━━━━━━━━━━━━━━━<br/>p, a, b, G, n identical<br/>Reuses curve arithmetic]
        end

        subgraph "🔑 EPHEMERAL Keypair Generation"
            EK1[Generate Random<br/>━━━━━━━━━━━━━━━━<br/>privateKey = random 192 bits<br/>1 < privateKey < n]

            EK2[Compute Public Key<br/>━━━━━━━━━━━━━━━━<br/>publicKey = privateKey × G<br/>Point x, y]

            EK3[🆕 NEW keypair for EACH signature<br/>━━━━━━━━━━━━━━━━<br/>Forward secrecy<br/>Non-reuse]

            EK1 --> EK2 --> EK3
        end

        subgraph "✍️ SIGNING PROCESS"
            SIGN1[Input: message string<br/>━━━━━━━━━━━━━━━━<br/>e.g., encryptedMessage]

            SIGN2[Step 1: Hash Message<br/>━━━━━━━━━━━━━━━━<br/>SHA-256 message<br/>hash = BigInt from bytes<br/>hash mod n]

            SIGN3[Step 2: Generate Random k<br/>━━━━━━━━━━━━━━━━<br/>k = SecureRandom 192 bits<br/>1 < k < n<br/><b>EPHEMERAL nonce</b>]

            SIGN4[Step 3: Compute r<br/>━━━━━━━━━━━━━━━━<br/>Point R = k × G<br/>r = R.x mod n<br/>If r = 0, regenerate k]

            SIGN5[Step 4: Compute s<br/>━━━━━━━━━━━━━━━━<br/>k_inv = k⁻¹ mod n<br/>s = k_inv × hash + r × privateKey mod n<br/>If s = 0, regenerate k]

            SIGN6[Output: Signature<br/>━━━━━━━━━━━━━━━━<br/>r, s, hash, algorithm]

            SIGN1 --> SIGN2 --> SIGN3 --> SIGN4 --> SIGN5 --> SIGN6
        end

        subgraph "✅ VERIFICATION PROCESS"
            VER1[Input: message, signature, publicKey<br/>━━━━━━━━━━━━━━━━<br/>signature: r, s<br/>publicKey: ephemeral from signer]

            VER2[Step 1: Validate r, s<br/>━━━━━━━━━━━━━━━━<br/>0 < r < n<br/>0 < s < n<br/>Reject if invalid]

            VER3[Step 2: Hash Message<br/>━━━━━━━━━━━━━━━━<br/>hash = SHA-256 message<br/>Same as signing]

            VER4[Step 3: Compute w<br/>━━━━━━━━━━━━━━━━<br/>w = s⁻¹ mod n]

            VER5[Step 4: Compute u1, u2<br/>━━━━━━━━━━━━━━━━<br/>u1 = hash × w mod n<br/>u2 = r × w mod n]

            VER6[Step 5: Compute Point<br/>━━━━━━━━━━━━━━━━<br/>P1 = u1 × G<br/>P2 = u2 × publicKey<br/>P = P1 + P2]

            VER7[Step 6: Verify<br/>━━━━━━━━━━━━━━━━<br/>v = P.x mod n<br/>✅ Valid if v = r<br/>❌ Invalid if v ≠ r]

            VER1 --> VER2 --> VER3 --> VER4 --> VER5 --> VER6 --> VER7
        end

        subgraph "🔐 Security Critical Points"
            SEC1[Random k Generation<br/>━━━━━━━━━━━━━━━━<br/>⚠️ MUST be random<br/>⚠️ MUST be unique per signature<br/>⚠️ Reusing k reveals privateKey]

            SEC2[Ephemeral Private Key<br/>━━━━━━━━━━━━━━━━<br/>✅ Generated fresh each time<br/>✅ Used once<br/>✅ Immediately discarded]

            SEC3[Public Key Distribution<br/>━━━━━━━━━━━━━━━━<br/>✅ Sent with signature<br/>✅ Receiver MUST use this key<br/>✅ NOT a stored/session key]
        end

        subgraph "📦 Data Structures"
            DS1["Signature Object
━━━━━━━━━━━━━━━━
{
  r: 'BigInt string',
  s: 'BigInt string',
  messageHash: 'BigInt string',
  algorithm: 'ECDSA-P192'
}"]
            DS2["Public Key Object
━━━━━━━━━━━━━━━━
{
  x: 'BigInt string',
  y: 'BigInt string'
}"]

            DS3["SignatureWithPublicKey
━━━━━━━━━━━━━━━━
{
  signature: Signature,
  publicKey: PublicKey
}

✅ Always sent together"]

        EK3 --> SIGN1
        SIGN6 --> DS1
        EK2 --> DS2
        DS1 --> DS3
        DS2 --> DS3
        DS3 --> VER1

        SIGN3 -.->|Critical| SEC1
        EK3 -.->|Ensures| SEC2
        DS3 -.->|Implements| SEC3
    end

    style SP fill:#e3f2fd
    style EK3 fill:#c8e6c9
    style SIGN3 fill:#fff9c4
    style SIGN6 fill:#ffccbc
    style VER7 fill:#c8e6c9
    style SEC1 fill:#ffebee
    style SEC2 fill:#c8e6c9
    style SEC3 fill:#c8e6c9
    end
    style DS3 fill:#fff9c4
```

---

## 🎫 7. JWT TOKEN STRUCTURE

```mermaid
graph TB
    subgraph "🎫 JWT TOKEN ANATOMY"
        JWT[<b>sessionToken</b><br/>━━━━━━━━━━━━<br/>header.payload.signature]

        subgraph "📋 Header base64url"
            H1["{ 'alg': 'HS256', 'typ': 'JWT' }"]
        end

        subgraph "📦 Payload base64url"
            P1[Public Claims<br/>━━━━━━━━━━━━]
            P2["iss: SecureChat<br/>sub: group-1"]
            P3["sid: c3c351f2a8d...<br/>sessionId random 64 hex chars"]
            P4["algorithm: ecdh<br/>publicKey: {x, y}"]
            P5["createdAt: timestamp<br/>lastActivity: timestamp"]
            P6["iat: issued at<br/>exp: iat + 120"]

            P7[🔐 Encrypted Data<br/>━━━━━━━━━━━━]
            P8["encryptedData: aW52YWxpZCB0b2tlbg..."]

            P1 --> P2
            P1 --> P3
            P1 --> P4
            P1 --> P5
            P1 --> P6
            P7 --> P8
        end

        subgraph "🔏 Signature"
            S1[HMAC-SHA256<br/>━━━━━━━━━━━━<br/>base64url header<br/>+ <br/>+ base64url payload<br/>+ jwtSecret]
        end

        H1 --> JWT
        P1 --> JWT
        P7 --> JWT
        S1 --> JWT
    end

    subgraph "🔐 Encrypted Data Contents"
        ED[Before Encryption - Sensitive Fields<br/>━━━━━━━━━━━━━━━━━━━━━━━━━]

        ED1["privateKey - BigInt string
Server's ECDH private key
⚠️ CRITICAL - must be encrypted"]

ED2["sharedSecret - BigInt string or null
Computed after key exchange
null before exchange
⚠️ CRITICAL - AES key derived from this"]

ED3["algorithmParams - p, a, b, Gx, Gy, order
Curve parameters if custom
null if using defaults"]

        ED --> ED1
        ED --> ED2
        ED --> ED3
    end

    subgraph "🔒 Encryption Process"
        ENC1[Step 1: Derive Encryption Key<br/>━━━━━━━━━━━━━━━━━━━<br/>keyMaterial = jwtSecret + userId<br/>encryptionKey = SHA-256keyMaterial<br/>Take first 32 bytes]

        ENC2["Step 2: Prepare Sensitive Data
━━━━━━━━━━━━━━━━━━━
sensitiveData =
- privateKey
- sharedSecret
- algorithmParams"]

        ENC3[Step 3: AES-256-GCM Encrypt<br/>━━━━━━━━━━━━━━━━━━━<br/>iv = random 12 bytes<br/>ciphertext = encrypt_and_auth<br/>tag = 16 bytes authentication tag]

        ENC4[Step 4: Concatenate & Encode<br/>━━━━━━━━━━━━━━━━━━━<br/>blob = iv + ciphertext + tag<br/>encryptedData = base64urlblob]

        ENC1 --> ENC2 --> ENC3 --> ENC4
        ENC4 -.->|Stored in| P8
    end

    subgraph "🔓 Decryption Process"
        DEC1[Step 1: Verify JWT HMAC<br/>━━━━━━━━━━━━━━━━━━━<br/>Recompute HMAC signature<br/>Compare with token signature<br/>✅ Reject if mismatch]

        DEC2[Step 2: Check Expiry<br/>━━━━━━━━━━━━━━━━━━━<br/>now = current timestamp<br/>✅ Valid if now < exp<br/>❌ Expired if now >= exp]

        DEC3[Step 3: Derive Decryption Key<br/>━━━━━━━━━━━━━━━━━━━<br/>SAME process as encryption<br/>encryptionKey = SHA-256jwtSecret + userId]

        DEC4["Step 4: Decode & Split
━━━━━━━━━━━━━━━━━━━
blob: base64url decode
iv: first 12 bytes
ciphertext: middle bytes
tag: last 16 bytes"]

        DEC5[Step 5: AES-256-GCM Decrypt<br/>━━━━━━━━━━━━━━━━━━━<br/>plaintext = decrypt_and_verify<br/>✅ Success: get sensitive data<br/>❌ Fail: authentication error]

        DEC1 --> DEC2 --> DEC3 --> DEC4 --> DEC5
    end

    subgraph "🔄 JWT Lifecycle"
        LIFE1[Creation<br/>━━━━━━━━━━━━<br/>POST /session/create<br/>privateKey encrypted<br/>sharedSecret = null<br/>exp = now + 120s]

        LIFE2[Update<br/>━━━━━━━━━━━━<br/>POST /session/exchange<br/>sharedSecret added<br/>Re-encrypt all data<br/>exp = now + 120s]

        LIFE3[Refresh<br/>━━━━━━━━━━━━<br/>POST /message/send<br/>lastActivity updated<br/>exp = now + 120s<br/>New token issued]

        LIFE4[Expiry<br/>━━━━━━━━━━━━<br/>After 120 seconds<br/>Token invalid<br/>Must re-login]

        LIFE1 --> LIFE2 --> LIFE3 --> LIFE4
    end

    ED1 -.->|Encrypted| ENC2
    ED2 -.->|Encrypted| ENC2
    ED3 -.->|Encrypted| ENC2
    P8 -.->|Contains| ENC4

    style JWT fill:#fff9c4
    style H1 fill:#e3f2fd
    style P1 fill:#e3f2fd
    style P7 fill:#ffccbc
    style S1 fill:#c8e6c9
    style ED1 fill:#ffebee
    style ED2 fill:#ffebee
    style ED3 fill:#ffebee
    style ENC4 fill:#ffccbc
    style DEC5 fill:#c8e6c9
    style LIFE4 fill:#ffccbc
```

---

## 💬 8. MESSAGE ENCRYPTION/DECRYPTION CHI TIẾT

```mermaid
graph LR
    subgraph "📤 CLIENT ENCRYPTION FLOW"
        CE1["👤 User Input
'hello'"]
        CE2[Get AES Key<br/>from CryptoManager<br/>Derived from sharedSecret]
        CE3[Generate IV<br/>Random 12 bytes<br/>crypto.getRandomValues]
        CE4[Prepare Cipher<br/>AES-256-GCM<br/>mode: ENCRYPT]
        CE5[Encrypt + Auth<br/>plaintext + AAD<br/>→ ciphertext + tag]
        CE6[Concatenate<br/>IV 12 + ciphertext + tag 16]
        CE7[Base64 Encode<br/>Final encryptedMessage]

        CE1 --> CE2 --> CE3 --> CE4 --> CE5 --> CE6 --> CE7
    end

    subgraph "✍️ CLIENT SIGNING"
        CS1[Input<br/>encryptedMessage]
        CS2[🆕 Generate<br/>EPHEMERAL keypair<br/>signPriv_eph<br/>signPub_eph]
        CS3[Hash Message<br/>SHA-256<br/>→ digest]
        CS4[ECDSA Sign<br/>with signPriv_eph<br/>→ r, s]
        CS5["Create Signature
r, s, hash, algorithm"]
        CS6["Package Result
signature
signPub_eph"]
        CS7[🗑️ Discard<br/>signPriv_eph]

        CS1 --> CS2 --> CS3 --> CS4 --> CS5 --> CS6 --> CS7
    end

    CE7 --> CS1

    subgraph "🌐 NETWORK TRANSMISSION"
        NT1[Build Request<br/>POST /message/send]
        NT2["JSON Body
sessionToken,
encryptedMessage,
messageSignature,
clientSignaturePublicKey"]
        NT3["HTTPS/TLS 1.3
Certificate Pinning
Verify SPKI hash"]
        NT4[Encrypted Tunnel<br/>TLS encryption layer]
        NT5[Cloudflare Worker<br/>Receives request]

        NT1 --> NT2 --> NT3 --> NT4 --> NT5
    end

    CS6 --> NT1

    subgraph "✅ SERVER SIGNATURE VERIFICATION"
        SV1[Extract Signature<br/>r, s, hash<br/>+ ephemeral publicKey]
        SV2[Hash Received Message<br/>SHA-256 encryptedMessage]
        SV3[Compare Hashes<br/>received hash = computed hash]
        SV4[ECDSA Verify<br/>with ephemeral publicKey<br/>NOT stored key]
        SV5{Signature<br/>Valid?}
        SV6[✅ ACCEPT<br/>Proceed to decryption]
        SV7[❌ REJECT<br/>Return 401 error]

        SV1 --> SV2 --> SV3 --> SV4 --> SV5
        SV5 -->|Yes| SV6
        SV5 -->|No| SV7
    end

    NT5 --> SV1

    subgraph "🔓 SERVER DECRYPTION"
        SD1[Get Session<br/>Verify JWT token<br/>🔓 Decrypt JWT]
        SD2[Extract sharedSecret<br/>from decrypted JWT]
        SD3[Derive AES Key<br/>PBKDF2 sharedSecret<br/>Same as client]
        SD4[Base64 Decode<br/>encryptedMessage]
        SD5["Extract Components
IV = bytes[0..11]
ciphertext = bytes[12..-17]
tag = bytes[-16..-1]"]
        SD6[AES-256-GCM Decrypt<br/>Verify authentication tag]
        SD7["🔓 Plaintext
hello"]

        SD1 --> SD2 --> SD3 --> SD4 --> SD5 --> SD6 --> SD7
    end

    SV6 --> SD1

    subgraph "🤖 SERVER RESPONSE GENERATION"
        SR1["Generate Response
Hello! Nice to meet you 👋"]
        SR2[AES-256-GCM Encrypt<br/>Same key as client]
        SR3[encryptedResponse<br/>base64]
        SR4[🆕 Generate NEW<br/>EPHEMERAL keypair<br/>signPriv_eph_resp<br/>signPub_eph_resp]
        SR5[ECDSA Sign<br/>encryptedResponse<br/>with signPriv_eph_resp]
        SR6["responseSignature
{
  r,
  s,
  hash
}"]
        SR7[🗑️ Discard<br/>signPriv_eph_resp]
        SR8[Refresh JWT<br/>exp += 120s<br/>newSessionToken]

        SR1 --> SR2 --> SR3 --> SR4 --> SR5 --> SR6 --> SR7 --> SR8
    end

    SD7 --> SR1

    subgraph "📥 CLIENT RESPONSE VERIFICATION"
        CV1["Receive Response
{
  encryptedResponse,
  responseSignature,
  serverSignaturePublicKey,
  newSessionToken
}"]
        CV2[Extract Signature<br/>+ ephemeral publicKey]
        CV3[ECDSA Verify<br/>with serverSignaturePublicKey<br/>NOT session creation key]
        CV4{Signature<br/>Valid?}
        CV5[✅ ACCEPT<br/>Decrypt response]
        CV6[❌ REJECT<br/>Show security alert]

        CV1 --> CV2 --> CV3 --> CV4
        CV4 -->|Yes| CV5
        CV4 -->|No| CV6
    end

    SR8 --> CV1

    subgraph "🔓 CLIENT DECRYPTION"
        CD1[Base64 Decode<br/>encryptedResponse]
        CD2[Extract IV + data + tag]
        CD3[AES-256-GCM Decrypt<br/>with same AES key]
        CD4["🔓 Plaintext
Hello! Nice to meet you 👋"]
        CD5[💬 Display in UI<br/>Chat message]
        CD6[💾 Update sessionToken<br/>Save newSessionToken]

        CD1 --> CD2 --> CD3 --> CD4 --> CD5 --> CD6
    end

    CV5 --> CD1

    style CE1 fill:#e3f2fd
    style CE7 fill:#ffccbc
    style CS2 fill:#fff9c4
    style CS6 fill:#ffccbc
    style CS7 fill:#ffebee
    style SV6 fill:#c8e6c9
    style SV7 fill:#ffcdd2
    style SD7 fill:#e1f5fe
    style SR4 fill:#fff9c4
    style SR6 fill:#ffccbc
    style SR7 fill:#ffebee
    style CV5 fill:#c8e6c9
    style CV6 fill:#ffcdd2
    style CD5 fill:#c8e6c9
```

---

## 🔒 9. SECURITY LAYERS

```mermaid
graph TB
    subgraph "🛡️ 7-LAYER SECURITY ARCHITECTURE"
        L1[<b>Layer 1: Transport Security</b><br/>━━━━━━━━━━━━━━━━━━━━━━━━<br/>🔒 HTTPS/TLS 1.3<br/>🔒 SSL Certificate Pinning<br/>🔒 SPKI SHA-256 Hash Validation<br/>🔒 Prevents MITM attacks]

        L2["Layer 2: Access Control
━━━━━━━━━━━━━━━━━━━━━━━━
🔒 Rate Limiting: per-minute via Cloudflare
🔒 Daily Quota: 16,600 requests/user/day
🔒 Whitelist: Only 'group-1' allowed
🔒 User authentication via userId"]

        L3[<b>Layer 3: Session Management</b><br/>━━━━━━━━━━━━━━━━━━━━━━━━<br/>🔒 JWT Stateless Tokens<br/>🔒 HMAC-SHA256 Signature<br/>🔒 120-second TTL Auto-expiry<br/>🔒 Refresh on each message]

        L4[<b>Layer 4: Key Exchange</b><br/>━━━━━━━━━━━━━━━━━━━━━━━━<br/>🔒 ECDH P-192 Ephemeral Keys<br/>🔒 Forward Secrecy<br/>🔒 192-bit shared secret<br/>🔒 Private keys never transmitted]

        L5[<b>Layer 5: Key Derivation</b><br/>━━━━━━━━━━━━━━━━━━━━━━━━<br/>🔒 PBKDF2-HMAC-SHA256<br/>🔒 1,000 iterations<br/>🔒 256-bit AES key output<br/>🔒 Unique per session]

        L6[<b>Layer 6: Message Encryption</b><br/>━━━━━━━━━━━━━━━━━━━━━━━━<br/>🔒 AES-256-GCM Authenticated Encryption<br/>🔒 Random IV per message 12 bytes<br/>🔒 128-bit Authentication Tag<br/>🔒 AEAD confidentiality + integrity]

        L7[<b>Layer 7: Digital Signatures</b><br/>━━━━━━━━━━━━━━━━━━━━━━━━<br/>🔒 ECDSA P-192 with SHA-256<br/>🔒 <b>EPHEMERAL Signature Keys</b><br/>🔒 Message Integrity + Authenticity<br/>🔒 Non-repudiation per message]

        L1 --> L2 --> L3 --> L4 --> L5 --> L6 --> L7
    end

    subgraph "✅ SECURITY PROPERTIES ACHIEVED"
        P1[<b>Confidentiality</b><br/>━━━━━━━━━━━━<br/>✅ TLS encryption<br/>✅ AES-256-GCM<br/>✅ No plaintext exposure]

        P2[<b>Integrity</b><br/>━━━━━━━━━━━━<br/>✅ GMAC tag verification<br/>✅ ECDSA signatures<br/>✅ JWT HMAC<br/>✅ Tamper detection]

        P3[<b>Authenticity</b><br/>━━━━━━━━━━━━<br/>✅ ECDSA signatures<br/>✅ JWT tokens<br/>✅ Certificate pinning<br/>✅ Verified identities]

        P4[<b>Non-Repudiation</b><br/>━━━━━━━━━━━━<br/>✅ ECDSA signatures<br/>✅ Unique per message<br/>✅ Cryptographic proof<br/>✅ Cannot deny sending]

        P5[<b>Forward Secrecy</b><br/>━━━━━━━━━━━━<br/>✅ Ephemeral ECDH keys<br/>✅ Ephemeral signature keys<br/>✅ Past messages safe<br/>✅ Key compromise isolation]

        P6[<b>Replay Prevention</b><br/>━━━━━━━━━━━━<br/>✅ JWT expiry 120s<br/>✅ Random IVs<br/>✅ Timestamp validation<br/>✅ Session freshness]

        P7[<b>Authentication</b><br/>━━━━━━━━━━━━<br/>✅ userId validation<br/>✅ Signature verification<br/>✅ Mutual authentication<br/>✅ Both parties verified]

        P8[<b>Authorization</b><br/>━━━━━━━━━━━━<br/>✅ Whitelist enforcement<br/>✅ Quota management<br/>✅ Rate limiting<br/>✅ Access control]
    end

    subgraph "🎯 THREAT MITIGATION"
        T1[<b>Man-in-the-Middle</b><br/>━━━━━━━━━━━━<br/>🛡️ TLS + Certificate Pinning<br/>🛡️ ECDSA signatures<br/>🛡️ ECDH key exchange]

        T2[<b>Replay Attacks</b><br/>━━━━━━━━━━━━<br/>🛡️ JWT expiry<br/>🛡️ Random IVs<br/>🛡️ Ephemeral keys]

        T3[<b>Eavesdropping</b><br/>━━━━━━━━━━━━<br/>🛡️ End-to-end encryption<br/>🛡️ AES-256-GCM<br/>🛡️ No plaintext storage]

        T4[<b>Tampering</b><br/>━━━━━━━━━━━━<br/>🛡️ Authentication tags<br/>🛡️ Digital signatures<br/>🛡️ HMAC validation]

        T5[<b>Key Compromise</b><br/>━━━━━━━━━━━━<br/>🛡️ Ephemeral keys<br/>🛡️ Forward secrecy<br/>🛡️ Limited impact]

        T6[<b>DoS/DDoS</b><br/>━━━━━━━━━━━━<br/>🛡️ Rate limiting<br/>🛡️ Daily quotas<br/>🛡️ Cloudflare protection]
    end

    L1 -.->|Ensures| P1
    L6 -.->|Ensures| P1
    L6 -.->|Ensures| P2
    L7 -.->|Ensures| P2
    L7 -.->|Ensures| P3
    L7 -.->|Ensures| P4
    L4 -.->|Ensures| P5
    L7 -.->|Ensures| P5
    L3 -.->|Ensures| P6
    L7 -.->|Ensures| P7
    L2 -.->|Ensures| P8

    P1 -.->|Mitigates| T3
    P2 -.->|Mitigates| T4
    P3 -.->|Mitigates| T1
    P5 -.->|Mitigates| T5
    P6 -.->|Mitigates| T2
    P8 -.->|Mitigates| T6

    style L1 fill:#ffebee
    style L2 fill:#fce4ec
    style L3 fill:#f3e5f5
    style L4 fill:#ede7f6
    style L5 fill:#e8eaf6
    style L6 fill:#e3f2fd
    style L7 fill:#e1f5fe
    style P1 fill:#c8e6c9
    style P2 fill:#c8e6c9
    style P3 fill:#c8e6c9
    style P4 fill:#c8e6c9
    style P5 fill:#c8e6c9
    style P6 fill:#c8e6c9
    style P7 fill:#c8e6c9
    style P8 fill:#c8e6c9
    style T1 fill:#fff9c4
    style T2 fill:#fff9c4
    style T3 fill:#fff9c4
    style T4 fill:#fff9c4
    style T5 fill:#fff9c4
    style T6 fill:#fff9c4
```

---

## 🎬 10. TỔNG KẾT - EPHEMERAL SIGNATURE WORKFLOW

```mermaid
graph TB
    subgraph "🎯 EPHEMERAL SIGNATURE - COMPLETE WORKFLOW"
        subgraph "📝 Traditional vs EPHEMERAL Comparison"
            TRAD["❌ TRADITIONAL MODEL (NOT USED)
━━━━━━━━━━━━━━━━━━━━━━
1. Generate keypair ONCE
2. Store private key in memory
3. Reuse for all signatures
4. Public key shared at start

⚠️ Risks:
• Key compromise affects ALL messages
• No forward secrecy for signatures
• Nonce reuse vulnerabilities possible"]
            EPHEM["✅ EPHEMERAL MODEL (IMPLEMENTED)
━━━━━━━━━━━━━━━━━━━━━━
1. Generate NEW keypair per signature
2. Sign ONCE with private key
3. Send signature + public key together
4. Immediately discard private key

✅ Benefits:
• 1 key compromise = 1 message risk
• Forward secrecy for signatures
• Eliminates nonce reuse attacks
• Independent cryptographic proof per message"]
        end

        subgraph "🔄 EPHEMERAL Key Lifecycle - Detailed"
            STEP1[<b>Step 1: GENERATION</b><br/>━━━━━━━━━━━━━━━━━━━━━━<br/>generateEphemeralSignatureKeyPair<br/>↓<br/>privateKey = SecureRandom 192 bits<br/>publicKey = privateKey × G<br/>↓<br/>🆕 NEW keypair created]

            STEP2["Step 2: SIGNING
━━━━━━━━━━━━━━━━━━━━━━
signMessage message, privateKey
↓
hash = SHA-256 message
k = SecureRandom nonce
r, s = ECDSA(privateKey, hash, k)
↓
signature = {r, s, hash}"]
            STEP3["Step 3: PACKAGING
━━━━━━━━━━━━━━━━━━━━━━
SignatureWithPublicKey:
  signature: {r, s, hash}
  publicKey: {x, y}
↓
Sent together in same message ✅"]

            STEP4["Step 4: TRANSMISSION
━━━━━━━━━━━━━━━━━━━━━━
JSON Request:
  encryptedMessage
  messageSignature: signature
  clientSignaturePublicKey: publicKey
↓
HTTPS POST to server 🌐"]

STEP5["Step 5: VERIFICATION
━━━━━━━━━━━━━━━━━━━━━━
verifySignatureWithPublicKey:
  message
  signature
  publicKey  ← ephemeral from request
↓
ECDSA verify with THIS public key
NOT stored/session key
↓
Valid ✅ or Reject ❌"]

STEP6["Step 6: DISPOSAL
━━━━━━━━━━━━━━━━━━━━━━
privateKey = null
Garbage collected
Never stored
Never reused
↓
Private key destroyed 🗑️
Forward secrecy maintained 🔒"]

            STEP1 --> STEP2 --> STEP3 --> STEP4 --> STEP5 --> STEP6
        end

        subgraph "📊 Usage Examples in Application"
            EX1[<b>Example 1: Session Creation</b><br/>━━━━━━━━━━━━━━━━━━━━━━<br/>Server:<br/>1. Generate ephemeral_1 keypair<br/>2. Sign sessionData with ephemeral_1_priv<br/>3. Send sessionSignature + ephemeral_1_pub<br/>4. Discard ephemeral_1_priv<br/><br/>Client:<br/>5. Verify with ephemeral_1_pub from response<br/>✅ Server authenticated]

            EX2[<b>Example 2: Key Exchange</b><br/>━━━━━━━━━━━━━━━━━━━━━━<br/>Client:<br/>1. Generate ephemeral_2 keypair<br/>2. Sign clientPublicKey with ephemeral_2_priv<br/>3. Send signature + ephemeral_2_pub<br/>4. Discard ephemeral_2_priv<br/><br/>Server:<br/>5. Verify with ephemeral_2_pub from request<br/>✅ Client authenticated]

            EX3[<b>Example 3: Send Message</b><br/>━━━━━━━━━━━━━━━━━━━━━━<br/>Client:<br/>1. Generate ephemeral_3 keypair<br/>2. Sign encryptedMessage with ephemeral_3_priv<br/>3. Send signature + ephemeral_3_pub<br/>4. Discard ephemeral_3_priv<br/><br/>Server:<br/>5. Verify with ephemeral_3_pub from request<br/>6. Generate ephemeral_4 keypair<br/>7. Sign encryptedResponse with ephemeral_4_priv<br/>8. Send signature + ephemeral_4_pub<br/>9. Discard ephemeral_4_priv<br/><br/>Client:<br/>10. Verify with ephemeral_4_pub from response<br/>✅ Mutual message authentication]
        end

        subgraph "🔐 Security Guarantees"
            G1[<b>Forward Secrecy</b><br/>━━━━━━━━━━━━━━━━━━━━━━<br/>Compromising current ephemeral key<br/>does NOT reveal past signatures<br/>Each signature independent]

            G2[<b>Key Isolation</b><br/>━━━━━━━━━━━━━━━━━━━━━━<br/>1 compromised ephemeral key<br/>= 1 compromised message<br/>NOT entire session]

            G3[<b>Non-Reuse</b><br/>━━━━━━━━━━━━━━━━━━━━━━<br/>Private keys never reused<br/>Nonce k always fresh<br/>Eliminates k-reuse attacks]

            G4[<b>Perfect Forward Secrecy</b><br/>━━━━━━━━━━━━━━━━━━━━━━<br/>Combined with ECDH ephemeral keys<br/>Double layer of forward secrecy:<br/>• Key exchange level<br/>• Signature level]
        end

        EPHEM --> STEP1
        STEP6 -.->|Ensures| G1
        STEP6 -.->|Ensures| G2
        STEP1 -.->|Ensures| G3
        STEP1 -.->|Combined with ECDH| G4
    end

    style TRAD fill:#ffcdd2
    style EPHEM fill:#c8e6c9
    style STEP1 fill:#e3f2fd
    style STEP2 fill:#fff9c4
    style STEP3 fill:#ffccbc
    style STEP4 fill:#e1f5fe
    style STEP5 fill:#c8e6c9
    style STEP6 fill:#ffebee
    style G1 fill:#b2dfdb
    style G2 fill:#b2dfdb
    style G3 fill:#b2dfdb
    style G4 fill:#b2dfdb
```

---

## 📚 LEGEND

```mermaid
graph LR
    subgraph "🎨 Color Coding"
        C1[Client Components]
        C2[Server Components]
        C3[Cryptographic Operations]
        C4[Security Properties]
        C5[Critical/Sensitive Data]
        C6[Success States]
        C7[Error/Warning States]
        C8[Data Flow]
    end

    subgraph "🔤 Terminology"
        T1[EPHEMERAL = One-time use, immediately discarded]
        T2[Forward Secrecy = Past security unaffected by future compromise]
        T3[AEAD = Authenticated Encryption with Associated Data]
        T4[ECDLP = Elliptic Curve Discrete Logarithm Problem]
        T5[PBKDF2 = Password-Based Key Derivation Function 2]
        T6[JWT = JSON Web Token stateless session]
    end

    style C1 fill:#e3f2fd
    style C2 fill:#c8e6c9
    style C3 fill:#fff9c4
    style C4 fill:#b2dfdb
    style C5 fill:#ffebee
    style C6 fill:#c8e6c9
    style C7 fill:#ffcdd2
    style C8 fill:#f0f4c3
```
