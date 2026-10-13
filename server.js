require("dotenv").config();

const express = require("express");
const session = require("express-session");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const { initializeApp, cert, getApps } = require("firebase-admin/app");
const {
    getAuth
} = require("firebase-admin/auth");

const {
    getFirestore,
    FieldValue
} = require("firebase-admin/firestore");

const { OAuth2Client } = require("google-auth-library");


// ============================================================
// AURA CLOUD SERVER
// ============================================================

const app = express();

const PORT = Number(process.env.PORT || 3000);

const PUBLIC_DIR = path.join(__dirname, "public");


// ============================================================
// BASIC EXPRESS CONFIG
// ============================================================

app.set("trust proxy", 1);

app.use(express.json({
    limit: "1mb"
}));

app.use(express.urlencoded({
    extended: true,
    limit: "1mb"
}));


// ============================================================
// FIREBASE ADMIN
// ============================================================

const serviceAccountPath = path.join(
    __dirname,
    "serviceAccountKey.json"
);

if (!fs.existsSync(serviceAccountPath)) {
    console.error("");
    console.error("==============================================");
    console.error("Firebase service account file not found.");
    console.error("");
    console.error("Expected:");
    console.error(serviceAccountPath);
    console.error("==============================================");
    console.error("");

    process.exit(1);
}

let firebaseApp;

try {
    if (getApps().length > 0) {
        firebaseApp = getApps()[0];
    } else {
        const serviceAccount = require(serviceAccountPath);

        firebaseApp = initializeApp({
            credential: cert(serviceAccount)
        });
    }

    console.log("[Firebase] Admin initialized successfully.");
} catch (error) {
    console.error("[Firebase] Failed to initialize:");
    console.error(error);

    process.exit(1);
}

const firebaseAuth = getAuth(firebaseApp);
const db = getFirestore(firebaseApp);


// ============================================================
// SESSION
// ============================================================

app.use(
    session({
        name: "aura.sid",

        secret:
            process.env.SESSION_SECRET ||
            "CHANGE_THIS_SESSION_SECRET",

        resave: false,

        saveUninitialized: false,

        cookie: {
            httpOnly: true,

            secure:
                String(process.env.COOKIE_SECURE).toLowerCase() ===
                "true",

            sameSite: "lax",

            maxAge: 7 * 24 * 60 * 60 * 1000
        }
    })
);


// ============================================================
// SMTP / NODEMAILER
// ============================================================

const SMTP_HOST =
    process.env.SMTP_HOST ||
    "smtp.gmail.com";

const SMTP_PORT =
    Number(process.env.SMTP_PORT || 465);

const SMTP_SECURE =
    String(
        process.env.SMTP_SECURE !== undefined
            ? process.env.SMTP_SECURE
            : "true"
    ).toLowerCase() === "true";

const SMTP_USER =
    process.env.SMTP_USER || "";

const SMTP_PASS =
    process.env.SMTP_PASS || "";

const SMTP_FROM =
    process.env.SMTP_FROM ||
    `"Aura Cloud Support" <${SMTP_USER}>`;

const SUPPORT_EMAIL =
    process.env.SUPPORT_EMAIL ||
    "auracloud.service@gmail.com";


const transporter = nodemailer.createTransport({
    host: SMTP_HOST,

    port: SMTP_PORT,

    secure: SMTP_SECURE,

    auth: {
        user: SMTP_USER,
        pass: SMTP_PASS
    }
});


// SMTP startup check
if (SMTP_USER && SMTP_PASS) {
    transporter.verify()
        .then(() => {
            console.log("[SMTP] SMTP connection verified.");
        })
        .catch((error) => {
            console.error("[SMTP] SMTP verification failed:");
            console.error(error.message);
        });
} else {
    console.warn(
        "[SMTP] SMTP_USER or SMTP_PASS is missing. Email sending will not work."
    );
}


// ============================================================
// GOOGLE OAUTH
// ============================================================

const GOOGLE_CLIENT_ID =
    process.env.GOOGLE_CLIENT_ID || "";

const GOOGLE_CLIENT_SECRET =
    process.env.GOOGLE_CLIENT_SECRET || "";

const GOOGLE_CALLBACK_URL =
    process.env.GOOGLE_CALLBACK_URL ||
    "http://localhost:3000/api/auth/google/callback";


let googleClient = null;

if (
    GOOGLE_CLIENT_ID &&
    GOOGLE_CLIENT_SECRET
) {
    googleClient = new OAuth2Client(
        GOOGLE_CLIENT_ID,
        GOOGLE_CLIENT_SECRET,
        GOOGLE_CALLBACK_URL
    );

    console.log("[Google] OAuth configured.");
} else {
    console.warn(
        "[Google] GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET not configured."
    );
}


// ============================================================
// FIREBASE WEB CONFIG
// ============================================================

const FIREBASE_WEB_CONFIG = {
    apiKey:
        process.env.FIREBASE_API_KEY ||
        process.env.FIREBASE_WEB_API_KEY ||
        "",

    authDomain:
        process.env.FIREBASE_AUTH_DOMAIN || "",

    projectId:
        process.env.FIREBASE_PROJECT_ID ||
        "aura-cloud-free",

    storageBucket:
        process.env.FIREBASE_STORAGE_BUCKET || "",

    messagingSenderId:
        process.env.FIREBASE_MESSAGING_SENDER_ID || "",

    appId:
        process.env.FIREBASE_APP_ID || ""
};

// ============================================================
// FIREBASE WEB CONFIG DIAGNOSTICS
// ============================================================

function logFirebaseWebConfigStatus() {
    const missing = [];

    if (!FIREBASE_WEB_CONFIG.apiKey) {
        missing.push("FIREBASE_API_KEY (or FIREBASE_WEB_API_KEY)");
    }

    if (!process.env.FIREBASE_PROJECT_ID) {
        missing.push("FIREBASE_PROJECT_ID");
    }

    if (!FIREBASE_WEB_CONFIG.authDomain) {
        missing.push("FIREBASE_AUTH_DOMAIN");
    }

    if (!FIREBASE_WEB_CONFIG.appId) {
        missing.push("FIREBASE_APP_ID");
    }

    if (missing.length > 0) {
        console.error("[Firebase Web] CONFIGURATION ISSUE: Missing environment variable(s):");
        for (const name of missing) {
            console.error(`[Firebase Web]   - ${name}`);
        }
        console.error("[Firebase Web] Check the hosting panel's environment variables or your local .env file, then restart the server.");
    } else {
        console.log("[Firebase Web] Required web config variables are present.");
    }

    // Never print the actual API key or other credential values.
}

logFirebaseWebConfigStatus();


// ============================================================
// RECAPTCHA
// ============================================================

const RECAPTCHA_SECRET_KEY =
    process.env.RECAPTCHA_SECRET_KEY || "";

const RECAPTCHA_SITE_KEY =
    process.env.RECAPTCHA_SITE_KEY || "";


async function verifyRecaptcha(token) {
    // If reCAPTCHA isn't configured, don't block the request.
    // Configure RECAPTCHA_SECRET_KEY in .env if you want
    // server-side verification.
    if (!RECAPTCHA_SECRET_KEY) {
        return true;
    }

    if (!token) {
        return false;
    }

    try {
        const response = await fetch(
            "https://www.google.com/recaptcha/api/siteverify",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/x-www-form-urlencoded"
                },

                body:
                    `secret=${encodeURIComponent(RECAPTCHA_SECRET_KEY)}` +
                    `&response=${encodeURIComponent(token)}`
            }
        );

        const result = await response.json();

        return result.success === true;

    } catch (error) {
        console.error(
            "[reCAPTCHA] Verification error:",
            error.message
        );

        return false;
    }
}


// ============================================================
// HELPER FUNCTIONS
// ============================================================

function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
        String(email || "").trim()
    );
}


function escapeHtml(value) {
    return String(value || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


function createOTP() {
    return String(
        crypto.randomInt(100000, 1000000)
    );
}


function hashOTP(otp) {
    return crypto
        .createHash("sha256")
        .update(String(otp))
        .digest("hex");
}


function getClientIP(req) {
    return (
        req.headers["cf-connecting-ip"] ||
        req.headers["x-real-ip"] ||
        req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
        req.socket?.remoteAddress ||
        "unknown"
    );
}


function requireLogin(req, res, next) {
    if (!req.session || !req.session.uid) {
        return res.status(401).json({
            success: false,
            message: "Authentication required."
        });
    }

    next();
}


// ============================================================
// SIMPLE SUPPORT RATE LIMITER
// ============================================================

const supportRateLimitStore = new Map();

function supportRateLimit(req, res, next) {
    const ip = getClientIP(req);

    const now = Date.now();

    const WINDOW =
        10 * 60 * 1000;

    const MAX_REQUESTS = 5;

    const existing =
        supportRateLimitStore.get(ip);

    if (
        !existing ||
        now - existing.start > WINDOW
    ) {
        supportRateLimitStore.set(ip, {
            start: now,
            count: 1
        });

        return next();
    }

    if (
        existing.count >= MAX_REQUESTS
    ) {
        return res.status(429).json({
            success: false,
            message:
                "Too many support requests. Please try again later."
        });
    }

    existing.count++;

    next();
}


// Periodically clean old rate-limit entries.
setInterval(() => {
    const now = Date.now();

    for (
        const [ip, data]
        of supportRateLimitStore.entries()
    ) {
        if (
            now - data.start >
            10 * 60 * 1000
        ) {
            supportRateLimitStore.delete(ip);
        }
    }
}, 10 * 60 * 1000).unref();


// ============================================================
// API CONFIG
// ============================================================

app.get("/api/config", (req, res) => {
    res.json({
        success: true,

        recaptchaSiteKey:
            RECAPTCHA_SITE_KEY,

        firebase: FIREBASE_WEB_CONFIG
    });
});


// ============================================================
// HEALTH CHECK
// ============================================================

app.get("/api/health", (req, res) => {
    res.json({
        success: true,
        status: "online",
        service: "Aura Cloud",
        time: new Date().toISOString()
    });
});


// ============================================================
// SESSION TEST
// ============================================================

app.get(
    "/api/auth/session-test",
    (req, res) => {
        res.json({
            success: true,

            authenticated:
                Boolean(
                    req.session &&
                    req.session.uid
                ),

            uid:
                req.session?.uid || null,

            email:
                req.session?.email || null
        });
    }
);


// ============================================================
// AUTH - ME
// ============================================================

app.get(
    "/api/auth/me",
    async (req, res) => {
        try {
            if (
                !req.session ||
                !req.session.uid
            ) {
                return res.json({
                    success: true,
                    authenticated: false,
                    user: null
                });
            }

            let user = null;

            try {
                user =
                    await firebaseAuth.getUser(
                        req.session.uid
                    );
            } catch (error) {
                console.error(
                    "[AUTH ME] Firebase user lookup failed:",
                    error.message
                );
            }

            let profile = {};

            try {
                const profileSnapshot =
                    await db
                        .collection("users")
                        .doc(req.session.uid)
                        .get();

                if (profileSnapshot.exists) {
                    profile =
                        profileSnapshot.data() || {};
                }
            } catch (error) {
                console.error(
                    "[AUTH ME] Firestore profile lookup failed:",
                    error.message
                );
            }

            return res.json({
                success: true,

                authenticated: true,

                user: {
                    uid:
                        req.session.uid,

                    email:
                        user?.email ||
                        req.session.email ||
                        profile.email ||
                        null,

                    displayName:
                        user?.displayName ||
                        profile.displayName ||
                        profile.name ||
                        null,

                    photoURL:
                        user?.photoURL ||
                        profile.photoURL ||
                        null,

                    emailVerified:
                        user?.emailVerified ??
                        profile.emailVerified ??
                        false
                }
            });

        } catch (error) {
            console.error(
                "[AUTH ME]",
                error
            );

            res.status(500).json({
                success: false,
                message: "Unable to load account."
            });
        }
    }
);


// ============================================================
// AUTH - SIGNUP
// ============================================================

app.post(
    "/api/auth/signup",
    async (req, res) => {
        try {
            const name =
                String(
                    req.body?.name || ""
                ).trim();

            const email =
                String(
                    req.body?.email || ""
                ).trim()
                .toLowerCase();

            const password =
                String(
                    req.body?.password || ""
                );

            const recaptchaToken =
                req.body?.recaptchaToken ||
                req.body?.captchaToken ||
                "";


            if (!name) {
                return res.status(400).json({
                    success: false,
                    message: "Name is required."
                });
            }


            if (!isValidEmail(email)) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Please enter a valid email address."
                });
            }


            if (password.length < 6) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Password must contain at least 6 characters."
                });
            }


            const captchaValid =
                await verifyRecaptcha(
                    recaptchaToken
                );

            if (!captchaValid) {
                return res.status(400).json({
                    success: false,
                    message:
                        "reCAPTCHA verification failed."
                });
            }


            let userRecord;

            try {
                userRecord =
                    await firebaseAuth.createUser({
                        email,
                        password,
                        displayName: name,
                        emailVerified: false
                    });

            } catch (error) {
                console.error(
                    "[SIGNUP] Firebase error:",
                    error
                );

                if (
                    error.code ===
                    "auth/email-already-exists"
                ) {
                    return res.status(409).json({
                        success: false,
                        message:
                            "An account with this email already exists."
                    });
                }

                return res.status(400).json({
                    success: false,
                    message:
                        error.message ||
                        "Unable to create account."
                });
            }


            await db
                .collection("users")
                .doc(userRecord.uid)
                .set(
                    {
                        uid:
                            userRecord.uid,

                        name,

                        displayName: name,

                        email,

                        emailVerified: false,

                        provider: "password",

                        createdAt:
                            FieldValue.serverTimestamp(),

                        updatedAt:
                            FieldValue.serverTimestamp()
                    },
                    {
                        merge: true
                    }
                );


            req.session.uid =
                userRecord.uid;

            req.session.email =
                email;


            try {
                await createAndSendOTP(
                    userRecord
                );
            } catch (error) {
                console.error(
                    "[SIGNUP] OTP email failed:",
                    error
                );
            }


            return res.status(201).json({
                success: true,

                message:
                    "Account created successfully. Please verify your email.",

                requiresVerification: true,

                uid:
                    userRecord.uid,

                email
            });

        } catch (error) {
            console.error(
                "[SIGNUP]",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to create your account."
            });
        }
    }
);


// ============================================================
// CREATE + SEND OTP
// ============================================================

async function createAndSendOTP(userRecord) {
    const uid =
        userRecord.uid;

    const email =
        userRecord.email;

    const otp =
        createOTP();

    const otpHash =
        hashOTP(otp);

    const expiresAt =
        Date.now() +
        10 * 60 * 1000;


    await db
        .collection("emailOtps")
        .doc(uid)
        .set({
            uid,

            email,

            otpHash,

            expiresAt,

            attempts: 0,

            createdAt:
                FieldValue.serverTimestamp()
        });


    await transporter.sendMail({
        from: SMTP_FROM,

        to: email,

        subject:
            "Your Aura Cloud verification code",

        text:
            `Your Aura Cloud verification code is ${otp}. ` +
            `This code expires in 10 minutes.`,

        html: `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Aura Cloud Verification</title>
</head>

<body style="
    margin:0;
    padding:30px;
    background:#08060d;
    font-family:Arial,Helvetica,sans-serif;
    color:#ffffff;
">

<div style="
    max-width:600px;
    margin:auto;
    background:#11101a;
    border:1px solid #292536;
    border-radius:16px;
    overflow:hidden;
">

<div style="
    padding:25px;
    border-bottom:1px solid #292536;
">

<h1 style="
    margin:0;
    color:#ffffff;
">
Aura Cloud
</h1>

<p style="
    margin:8px 0 0;
    color:#aaa4b5;
">
Email verification
</p>

</div>

<div style="padding:30px;">

<p style="color:#d5d0dc;">
Your verification code is:
</p>

<div style="
    margin:25px 0;
    padding:20px;
    text-align:center;
    background:#0b0a11;
    border:1px solid #302a3d;
    border-radius:12px;
    font-size:32px;
    font-weight:bold;
    letter-spacing:8px;
    color:#ffffff;
">
${escapeHtml(otp)}
</div>

<p style="
    color:#9993a4;
    line-height:1.6;
">
This code expires in 10 minutes.
</p>

</div>

</div>

</body>
</html>
        `
    });
}


// ============================================================
// AUTH - VERIFY OTP
// ============================================================

app.post(
    "/api/auth/verify-otp",
    async (req, res) => {
        try {
            const uid =
                String(
                    req.body?.uid ||
                    req.session?.uid ||
                    ""
                ).trim();

            const otp =
                String(
                    req.body?.otp || ""
                ).trim();


            if (!uid || !otp) {
                return res.status(400).json({
                    success: false,
                    message:
                        "UID and OTP are required."
                });
            }


            const otpRef =
                db
                    .collection("emailOtps")
                    .doc(uid);

            const otpSnapshot =
                await otpRef.get();


            if (!otpSnapshot.exists) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Verification code not found. Please request a new code."
                });
            }


            const otpData =
                otpSnapshot.data();


            if (
                Date.now() >
                Number(otpData.expiresAt)
            ) {
                await otpRef.delete();

                return res.status(400).json({
                    success: false,
                    message:
                        "Verification code has expired."
                });
            }


            const attempts =
                Number(
                    otpData.attempts || 0
                );


            if (attempts >= 5) {
                await otpRef.delete();

                return res.status(429).json({
                    success: false,
                    message:
                        "Too many incorrect attempts. Please request a new code."
                });
            }


            const suppliedHash =
                hashOTP(otp);


            if (
                suppliedHash !==
                otpData.otpHash
            ) {
                await otpRef.update({
                    attempts:
                        attempts + 1
                });

                return res.status(400).json({
                    success: false,
                    message:
                        "Incorrect verification code."
                });
            }


            await firebaseAuth.updateUser(
                uid,
                {
                    emailVerified: true
                }
            );


            await db
                .collection("users")
                .doc(uid)
                .set(
                    {
                        emailVerified: true,

                        updatedAt:
                            FieldValue.serverTimestamp()
                    },
                    {
                        merge: true
                    }
                );


            await otpRef.delete();


            req.session.uid =
                uid;


            try {
                const user =
                    await firebaseAuth.getUser(uid);

                req.session.email =
                    user.email || "";
            } catch (_) {}


            return res.json({
                success: true,
                message:
                    "Email verified successfully."
            });

        } catch (error) {
            console.error(
                "[VERIFY OTP]",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to verify the code."
            });
        }
    }
);


// ============================================================
// AUTH - RESEND OTP
// ============================================================

app.post(
    "/api/auth/resend-otp",
    async (req, res) => {
        try {
            const uid =
                String(
                    req.body?.uid ||
                    req.session?.uid ||
                    ""
                ).trim();


            if (!uid) {
                return res.status(400).json({
                    success: false,
                    message:
                        "User ID is required."
                });
            }


            const user =
                await firebaseAuth.getUser(
                    uid
                );


            if (user.emailVerified) {
                return res.json({
                    success: true,
                    message:
                        "Your email is already verified."
                });
            }


            await createAndSendOTP(
                user
            );


            return res.json({
                success: true,
                message:
                    "A new verification code has been sent."
            });

        } catch (error) {
            console.error(
                "[RESEND OTP]",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to resend verification code."
            });
        }
    }
);


// ============================================================
// AUTH - LOGIN
// ============================================================

app.post(
    "/api/auth/login",
    async (req, res) => {
        try {
            const email =
                String(
                    req.body?.email || ""
                ).trim()
                .toLowerCase();

            const password =
                String(
                    req.body?.password || ""
                );

            const recaptchaToken =
                req.body?.recaptchaToken ||
                req.body?.captchaToken ||
                "";


            if (!isValidEmail(email)) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Please enter a valid email address."
                });
            }


            if (!password) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Password is required."
                });
            }


            const captchaValid =
                await verifyRecaptcha(
                    recaptchaToken
                );

            if (!captchaValid) {
                return res.status(400).json({
                    success: false,
                    message:
                        "reCAPTCHA verification failed."
                });
            }


            const apiKey =
                FIREBASE_WEB_CONFIG.apiKey ||
                process.env.FIREBASE_API_KEY;


            if (!apiKey) {
                return res.status(500).json({
                    success: false,
                    message:
                        "Firebase API key is not configured."
                });
            }


            const response =
                await fetch(
                    `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${encodeURIComponent(apiKey)}`,
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json"
                        },

                        body: JSON.stringify({
                            email,
                            password,
                            returnSecureToken: true
                        })
                    }
                );


            const data =
                await response.json();


            if (!response.ok) {
                console.error(
                    "[LOGIN] Firebase error:",
                    data
                );

                let message =
                    "Invalid email or password.";

                if (
                    data?.error?.message ===
                    "EMAIL_NOT_FOUND"
                ) {
                    message =
                        "No account was found with this email.";
                }

                if (
                    data?.error?.message ===
                    "INVALID_PASSWORD"
                ) {
                    message =
                        "Incorrect password.";
                }

                if (
                    data?.error?.message ===
                    "USER_DISABLED"
                ) {
                    message =
                        "This account has been disabled.";
                }

                return res.status(401).json({
                    success: false,
                    message
                });
            }


            const uid =
                data.localId;


            let userRecord;

            try {
                userRecord =
                    await firebaseAuth.getUser(
                        uid
                    );
            } catch (_) {}


            req.session.uid =
                uid;

            req.session.email =
                email;


            return res.json({
                success: true,

                message:
                    "Login successful.",

                user: {
                    uid,

                    email,

                    displayName:
                        userRecord?.displayName ||
                        null,

                    emailVerified:
                        userRecord?.emailVerified ||
                        false
                }
            });

        } catch (error) {
            console.error(
                "[LOGIN]",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to log in right now."
            });
        }
    }
);


// ============================================================
// AUTH - FORGOT PASSWORD
// ============================================================

app.post(
    "/api/auth/forgot-password",
    async (req, res) => {
        try {
            const email =
                String(
                    req.body?.email || ""
                ).trim()
                .toLowerCase();


            if (!isValidEmail(email)) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Please enter a valid email address."
                });
            }


            const apiKey =
                FIREBASE_WEB_CONFIG.apiKey ||
                process.env.FIREBASE_API_KEY;


            if (!apiKey) {
                return res.status(500).json({
                    success: false,
                    message:
                        "Firebase API key is not configured."
                });
            }


            const response =
                await fetch(
                    `https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=${encodeURIComponent(apiKey)}`,
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json"
                        },

                        body: JSON.stringify({
                            requestType:
                                "PASSWORD_RESET",

                            email
                        })
                    }
                );


            const data =
                await response.json();


            if (!response.ok) {
                console.error(
                    "[FORGOT PASSWORD]",
                    data
                );

                return res.status(400).json({
                    success: false,
                    message:
                        "Unable to send password reset email."
                });
            }


            return res.json({
                success: true,

                message:
                    "If an account exists for this email, a password reset email has been sent."
            });

        } catch (error) {
            console.error(
                "[FORGOT PASSWORD]",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to process your request."
            });
        }
    }
);


// ============================================================
// GOOGLE LOGIN
// ============================================================

app.get(
    "/api/auth/google",
    (req, res) => {
        if (!googleClient) {
            return res.status(503).send(
                "Google login is not configured."
            );
        }


        const authorizationUrl =
            googleClient.generateAuthUrl({
                access_type: "offline",

                scope: [
                    "openid",
                    "email",
                    "profile"
                ],

                prompt: "select_account"
            });


        res.redirect(
            authorizationUrl
        );
    }
);


// ============================================================
// GOOGLE CALLBACK
// ============================================================

app.get(
    "/api/auth/google/callback",
    async (req, res) => {
        try {
            if (!googleClient) {
                return res.status(503).send(
                    "Google login is not configured."
                );
            }


            const code =
                req.query.code;


            if (!code) {
                return res.status(400).send(
                    "Google authorization code is missing."
                );
            }


            const { tokens } =
                await googleClient.getToken(
                    code
                );


            const ticket =
                await googleClient.verifyIdToken({
                    idToken:
                        tokens.id_token,

                    audience:
                        GOOGLE_CLIENT_ID
                });


            const payload =
                ticket.getPayload();


            const googleId =
                payload.sub;

            const email =
                String(
                    payload.email || ""
                )
                    .trim()
                    .toLowerCase();

            const name =
                payload.name ||
                email.split("@")[0];

            const photoURL =
                payload.picture ||
                null;


            if (!email) {
                return res.status(400).send(
                    "Google did not provide an email address."
                );
            }


            let userRecord;


            try {
                userRecord =
                    await firebaseAuth.getUserByEmail(
                        email
                    );

            } catch (error) {

                if (
                    error.code ===
                    "auth/user-not-found"
                ) {
                    userRecord =
                        await firebaseAuth.createUser({
                            email,

                            displayName:
                                name,

                            photoURL,

                            emailVerified: true
                        });

                } else {
                    throw error;
                }
            }


            await db
                .collection("users")
                .doc(userRecord.uid)
                .set(
                    {
                        uid:
                            userRecord.uid,

                        email,

                        name,

                        displayName:
                            name,

                        photoURL,

                        provider:
                            "google",

                        googleId,

                        emailVerified: true,

                        updatedAt:
                            FieldValue.serverTimestamp()
                    },
                    {
                        merge: true
                    }
                );


            req.session.uid =
                userRecord.uid;

            req.session.email =
                email;


            const dashboardUrl =
                process.env.DASHBOARD_URL ||
                "/dashboard.html";


            return res.redirect(
                dashboardUrl
            );

        } catch (error) {
            console.error(
                "[GOOGLE CALLBACK]",
                error
            );

            return res.status(500).send(
                "Google login failed. Please try again."
            );
        }
    }
);


// ============================================================
// AUTH - LOGOUT
// ============================================================

app.post(
    "/api/auth/logout",
    (req, res) => {
        req.session.destroy(
            (error) => {
                if (error) {
                    console.error(
                        "[LOGOUT]",
                        error
                    );

                    return res.status(500).json({
                        success: false,
                        message:
                            "Unable to log out."
                    });
                }


                res.clearCookie(
                    "aura.sid"
                );


                return res.json({
                    success: true,
                    message:
                        "Logged out successfully."
                });
            }
        );
    }
);


// Also support GET logout.
app.get(
    "/api/auth/logout",
    (req, res) => {
        req.session.destroy(
            () => {
                res.clearCookie(
                    "aura.sid"
                );

                res.redirect("/");
            }
        );
    }
);


// ============================================================
// SUPPORT EMAIL
// ============================================================
//
// Dashboard endpoint:
//
// POST /api/support/email
//
// JSON:
//
// {
//     "name": "...",
//     "email": "...",
//     "message": "..."
// }
//
// The email is sent to:
// auracloud.service@gmail.com
//
// ============================================================

app.post(
    "/api/support/email",
    supportRateLimit,
    async (req, res) => {
        try {
            const name =
                String(
                    req.body?.name || ""
                ).trim();

            const email =
                String(
                    req.body?.email || ""
                ).trim();

            const message =
                String(
                    req.body?.message || ""
                ).trim();


            if (!name) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Name is required."
                });
            }


            if (!email) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Email is required."
                });
            }


            if (!isValidEmail(email)) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Please enter a valid email address."
                });
            }


            if (!message) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Message is required."
                });
            }


            if (name.length > 100) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Name is too long."
                });
            }


            if (email.length > 320) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Email address is too long."
                });
            }


            if (message.length > 10000) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Message is too long."
                });
            }


            // Optional reCAPTCHA.
            const recaptchaToken =
                req.body?.recaptchaToken ||
                req.body?.captchaToken ||
                "";


            if (RECAPTCHA_SECRET_KEY) {
                const captchaValid =
                    await verifyRecaptcha(
                        recaptchaToken
                    );

                if (!captchaValid) {
                    return res.status(400).json({
                        success: false,
                        message:
                            "reCAPTCHA verification failed."
                    });
                }
            }


            const safeName =
                escapeHtml(name);

            const safeEmail =
                escapeHtml(email);

            const safeMessage =
                escapeHtml(message)
                    .replace(/\r?\n/g, "<br>");


            const submittedAt =
                new Date().toLocaleString(
                    "en-US",
                    {
                        timeZone:
                            "Asia/Colombo",

                        dateStyle:
                            "medium",

                        timeStyle:
                            "medium"
                    }
                );


            const ip =
                getClientIP(req);


            // ------------------------------------------------
            // SEND EMAIL
            // ------------------------------------------------

            await transporter.sendMail({
                from: SMTP_FROM,

                to: SUPPORT_EMAIL,

                replyTo: email,

                subject:
                    "[Aura Cloud Support] New Support Request",

                text: `
Aura Cloud Support Request

Name: ${name}
Email: ${email}

Message:
${message}

Submitted:
${submittedAt}
                `.trim(),

                html: `
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<title>
Aura Cloud Support Request
</title>

</head>

<body style="
    margin:0;
    padding:30px;
    background:#08060d;
    font-family:Arial,Helvetica,sans-serif;
    color:#ffffff;
">

<div style="
    width:100%;
    max-width:650px;
    margin:0 auto;
    background:#11101a;
    border:1px solid #292536;
    border-radius:16px;
    overflow:hidden;
">

    <div style="
        padding:26px;
        background:linear-gradient(
            135deg,
            #171022,
            #111827
        );
        border-bottom:1px solid #292536;
    ">

        <h1 style="
            margin:0;
            font-size:24px;
            color:#ffffff;
        ">
            Aura Cloud
        </h1>

        <p style="
            margin:8px 0 0;
            color:#aaa4b5;
            font-size:14px;
        ">
            New support request
        </p>

    </div>


    <div style="
        padding:26px;
    ">


        <div style="
            margin-bottom:16px;
            padding:16px;
            background:#0b0a11;
            border:1px solid #292536;
            border-radius:10px;
        ">

            <div style="
                color:#ffffff;
                font-weight:bold;
                margin-bottom:7px;
            ">
                Name
            </div>

            <div style="
                color:#c7c2d1;
            ">
                ${safeName}
            </div>

        </div>


        <div style="
            margin-bottom:16px;
            padding:16px;
            background:#0b0a11;
            border:1px solid #292536;
            border-radius:10px;
        ">

            <div style="
                color:#ffffff;
                font-weight:bold;
                margin-bottom:7px;
            ">
                Email
            </div>

            <div style="
                color:#c7c2d1;
            ">
                ${safeEmail}
            </div>

        </div>


        <div style="
            padding:18px;
            background:#0b0a11;
            border:1px solid #292536;
            border-radius:10px;
        ">

            <div style="
                color:#ffffff;
                font-weight:bold;
                margin-bottom:12px;
            ">
                Message
            </div>

            <div style="
                color:#d3cedd;
                line-height:1.7;
                word-break:break-word;
            ">
                ${safeMessage}
            </div>

        </div>


        <div style="
            margin-top:20px;
            color:#777180;
            font-size:12px;
            line-height:1.6;
        ">

            Submitted:
            ${escapeHtml(submittedAt)}

        </div>


    </div>

</div>

</body>

</html>
                `
            });


            console.log(
                `[SUPPORT] Message sent from ${email} to ${SUPPORT_EMAIL}`
            );


            return res.json({
                success: true,

                message:
                    "Your support request has been sent successfully."
            });

        } catch (error) {
            console.error(
                "[SUPPORT EMAIL ERROR]"
            );

            console.error(error);


            return res.status(500).json({
                success: false,

                message:
                    "Unable to send your support request right now."
            });
        }
    }
);


// ============================================================
// SUPPORT ALIAS
// ============================================================
//
// This also allows:
// POST /api/support
//
// ============================================================

app.post(
    "/api/support",
    supportRateLimit,
    async (req, res) => {

        // Re-use the main support endpoint
        // internally by duplicating the request URL.
        req.url =
            "/api/support/email";

        return app._router.handle(
            req,
            res,
            () => {}
        );
    }
);


// ============================================================
// AUTH - UPDATE PROFILE (PASSWORD REQUIRED)
// If the email changes, send an OTP to the NEW email address and
// only commit the email change after the OTP is verified.
// ============================================================
app.post("/api/auth/profile", requireLogin, async (req, res) => {
    try {
        const uid = req.session.uid;
        const fullName = String(req.body?.fullName || req.body?.name || "").trim();
        const email = String(req.body?.email || "").trim().toLowerCase();
        const currentPassword = String(req.body?.currentPassword || "");

        if (!fullName) return res.status(400).json({ success: false, message: "Name is required." });
        if (fullName.length > 100) return res.status(400).json({ success: false, message: "Name must be 100 characters or fewer." });
        if (!isValidEmail(email)) return res.status(400).json({ success: false, message: "Please enter a valid email address." });
        if (!currentPassword) return res.status(400).json({ success: false, message: "Enter your current password to update personal details." });

        const user = await firebaseAuth.getUser(uid);
        if (!user.email) return res.status(400).json({ success: false, message: "This account has no email address." });
        const hasPasswordProvider = (user.providerData || []).some(p => p.providerId === "password");
        if (!hasPasswordProvider) return res.status(400).json({ success: false, message: "This account uses Google sign-in and has no password to verify. Use the account recovery flow to set a password first." });

        const apiKey = process.env.FIREBASE_API_KEY || process.env.FIREBASE_WEB_API_KEY;
        if (!apiKey) return res.status(500).json({ success: false, message: "Password verification is not configured. Add FIREBASE_API_KEY to your .env file." });

        const verifyResponse = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${encodeURIComponent(apiKey)}`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: user.email, password: currentPassword, returnSecureToken: false })
        });
        const verifyData = await verifyResponse.json().catch(() => ({}));
        if (!verifyResponse.ok) {
            const reason = verifyData?.error?.message || "";
            if (["INVALID_PASSWORD", "INVALID_LOGIN_CREDENTIALS", "EMAIL_NOT_FOUND"].includes(reason)) return res.status(400).json({ success: false, message: "Your current password is incorrect." });
            console.error("[PROFILE] Password verification failed:", reason || verifyResponse.status);
            return res.status(502).json({ success: false, message: "Could not verify your password with Firebase. Check the Firebase Web API key and Authentication settings." });
        }

        const emailChanged = (user.email || "").toLowerCase() !== email;
        if (emailChanged) {
            try {
                await firebaseAuth.getUserByEmail(email);
                return res.status(409).json({ success: false, message: "That email address is already used by another account." });
            } catch (lookupError) {
                if (lookupError.code !== "auth/user-not-found") throw lookupError;
            }

            const otp = createOTP();
            const expiresAt = Date.now() + 10 * 60 * 1000;
            await db.collection("emailOtps").doc(uid).set({
                uid, email, otpHash: hashOTP(otp), expiresAt, attempts: 0,
                purpose: "profile-email-change", pendingEmail: email, pendingName: fullName,
                createdAt: FieldValue.serverTimestamp()
            });

            await transporter.sendMail({
                from: SMTP_FROM, to: email,
                subject: "Verify your new Aura Cloud email address",
                text: `Your Aura Cloud email-change verification code is ${otp}. It expires in 10 minutes. If you did not request this change, ignore this email.`,
                html: `<div style="font-family:Arial,sans-serif;background:#0b0a11;color:#fff;padding:28px;border-radius:12px;max-width:560px;margin:auto"><h2>Aura Cloud</h2><p>Use this code to verify your new email address:</p><div style="font-size:32px;letter-spacing:8px;font-weight:bold;padding:18px;background:#171322;border-radius:10px;text-align:center">${escapeHtml(otp)}</div><p style="color:#aaa">The code expires in 10 minutes. Your email will not change until verification is complete.</p></div>`
            });

            return res.json({ success: true, requiresOtp: true, message: `We sent a verification code to ${email}. Enter it below to finish updating your email.`, pendingEmail: email });
        }

        await firebaseAuth.updateUser(uid, { displayName: fullName });
        await db.collection("users").doc(uid).set({ uid, name: fullName, displayName: fullName, email: user.email, emailVerified: Boolean(user.emailVerified), updatedAt: FieldValue.serverTimestamp() }, { merge: true });
        req.session.email = user.email;
        return res.json({ success: true, message: "Personal details updated successfully.", user: { uid, name: fullName, displayName: fullName, email: user.email, emailVerified: Boolean(user.emailVerified), photoURL: user.photoURL || null } });
    } catch (error) {
        console.error("[PROFILE UPDATE]", error.code || "", error.message || error);
        const code = error.code || "";
        const status = code === "auth/email-already-exists" ? 409 : code === "auth/invalid-email" ? 400 : code === "auth/invalid-uid" ? 401 : 500;
        const message = code === "auth/email-already-exists" ? "That email address is already used by another account." : code === "auth/invalid-email" ? "Please enter a valid email address." : "Could not save profile. Check Firebase credentials and server logs.";
        return res.status(status).json({ success: false, message });
    }
});

// ============================================================
// AUTH - VERIFY OTP FOR EMAIL CHANGE
// ============================================================
app.post("/api/auth/profile/verify-email-otp", requireLogin, async (req, res) => {
    try {
        const uid = req.session.uid;
        const otp = String(req.body?.otp || "").trim();
        if (!/^\d{6}$/.test(otp)) return res.status(400).json({ success: false, message: "Enter the six-digit verification code." });

        const otpRef = db.collection("emailOtps").doc(uid);
        const snapshot = await otpRef.get();
        if (!snapshot.exists) return res.status(400).json({ success: false, message: "Verification code not found. Save your details again to request a new code." });
        const data = snapshot.data() || {};
        if (data.purpose !== "profile-email-change" || !data.pendingEmail) return res.status(400).json({ success: false, message: "This code is not for an email change." });
        if (Date.now() > Number(data.expiresAt || 0)) {
            await otpRef.delete();
            return res.status(400).json({ success: false, message: "Verification code expired. Save your details again to request a new code." });
        }
        const attempts = Number(data.attempts || 0);
        if (attempts >= 5) {
            await otpRef.delete();
            return res.status(429).json({ success: false, message: "Too many incorrect attempts. Request a new code." });
        }
        if (hashOTP(otp) !== data.otpHash) {
            await otpRef.update({ attempts: attempts + 1 });
            return res.status(400).json({ success: false, message: "Incorrect verification code." });
        }

        const updatedUser = await firebaseAuth.updateUser(uid, { email: data.pendingEmail, emailVerified: true, displayName: data.pendingName || undefined });
        await db.collection("users").doc(uid).set({ uid, email: updatedUser.email, emailVerified: true, name: updatedUser.displayName || data.pendingName || "", displayName: updatedUser.displayName || data.pendingName || "", updatedAt: FieldValue.serverTimestamp() }, { merge: true });
        await otpRef.delete();
        req.session.email = updatedUser.email;
        return res.json({ success: true, message: "Email address verified and personal details updated.", user: { uid, email: updatedUser.email, name: updatedUser.displayName || data.pendingName || "", displayName: updatedUser.displayName || data.pendingName || "", emailVerified: true, photoURL: updatedUser.photoURL || null } });
    } catch (error) {
        console.error("[PROFILE EMAIL OTP]", error.code || "", error.message || error);
        const code = error.code || "";
        const status = code === "auth/email-already-exists" ? 409 : code === "auth/invalid-email" ? 400 : 500;
        const message = code === "auth/email-already-exists" ? "That email address is already used by another account." : "Could not verify this email address. Please try again.";
        return res.status(status).json({ success: false, message });
    }
});


// ============================================================
// DASHBOARD API
// ============================================================

app.get(
    "/api/dashboard",
    requireLogin,
    async (req, res) => {
        try {
            const uid =
                req.session.uid;


            const user =
                await firebaseAuth.getUser(
                    uid
                );


            let profile = {};


            try {
                const snapshot =
                    await db
                        .collection("users")
                        .doc(uid)
                        .get();


                if (snapshot.exists) {
                    profile =
                        snapshot.data() || {};
                }

            } catch (error) {
                console.error(
                    "[DASHBOARD] Firestore:",
                    error.message
                );
            }


            return res.json({
                success: true,

                user: {
                    uid,

                    email:
                        user.email ||
                        profile.email ||
                        null,

                    name:
                        user.displayName ||
                        profile.name ||
                        profile.displayName ||
                        null,

                    displayName:
                        user.displayName ||
                        profile.displayName ||
                        profile.name ||
                        null,

                    photoURL:
                        user.photoURL ||
                        profile.photoURL ||
                        null,

                    emailVerified:
                        user.emailVerified ||
                        profile.emailVerified ||
                        false
                }
            });

        } catch (error) {
            console.error(
                "[DASHBOARD]",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to load dashboard."
            });
        }
    }
);



// FREE TRIAL: authenticated account -> bearer-token 3x-ui API
const TRIAL_ISP_PLANS = {
  "Dialog SIM":["TikTok"], "Dialog Router":["Zoom"], "Airtel":["TikTok","YouTube","Zoom"],
  "Hutch":["Zoom"], "SLT Fiber":["Netflix","Zoom"]
};
const TRIAL_SNI_ENV = { TikTok:"XUI_SNI_TIKTOK", YouTube:"XUI_SNI_YOUTUBE", Zoom:"XUI_SNI_ZOOM", Netflix:"XUI_SNI_NETFLIX" };
const TRIAL_GB = Math.max(1, Number(process.env.XUI_TRIAL_DATA_GB || 300));
const TRIAL_DAYS = Math.max(1, Number(process.env.XUI_TRIAL_DAYS || 3));
const TRIAL_BYTES = Math.round(TRIAL_GB * 1024 * 1024 * 1024);

async function trialXui(pathname, options) {
  const base = String(process.env.XUI_BASE_URL || "").trim().replace(/\/+$/, "");
  const token = String(process.env.XUI_API_TOKEN || "").trim();
  if (!base || !token) throw new Error("XUI_BASE_URL and XUI_API_TOKEN must be configured.");
  const u = new URL(base);
  if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error("XUI_BASE_URL must use HTTP or HTTPS.");
  const method = String((options && options.method) || "GET").toUpperCase();
  // Include the endpoint and HTTP status in diagnostics, but never log the bearer token.
  const response = await fetch(base + pathname, {
    ...(options || {}),
    signal: AbortSignal.timeout(15000),
    headers: { Accept:"application/json", Authorization:"Bearer " + token,
      ...((options && options.body) ? {"Content-Type":"application/json"} : {}),
      ...((options && options.headers) || {}) }
  });
  const raw = await response.text();
  let data;
  try { data = raw ? JSON.parse(raw) : {}; }
  catch {
    throw new Error(`3x-ui ${method} ${pathname} returned HTTP ${response.status} with a non-JSON response. Check XUI_BASE_URL, its panel base path, and the API endpoint.`);
  }
  if (!response.ok || data.success === false) {
    const reason = String(data.msg || data.message || data.error || response.status).slice(0, 240);
    throw new Error(`3x-ui ${method} ${pathname} failed (HTTP ${response.status}): ${reason}`);
  }
  return data;
}
function trialObj(v) {
  if (v && typeof v === "object") return v;
  if (typeof v === "string") { try { return JSON.parse(v); } catch (_) {} }
  return {};
}
function trialUnwrap(data) { return data && (data.obj !== undefined ? data.obj : data.data !== undefined ? data.data : data.client !== undefined ? data.client : data); }
async function trialInbound(id) {
  let data = await trialXui("/panel/api/inbounds/list");
  let obj = trialUnwrap(data);
  let list = Array.isArray(obj) ? obj : (Array.isArray(obj.inbounds) ? obj.inbounds : []);
  let inbound = list.find(x => Number(x.id) === Number(id));
  if (!inbound) {
    data = await trialXui("/panel/api/inbounds/" + encodeURIComponent(id));
    obj = trialUnwrap(data);
    inbound = Number(obj.id) === Number(id) ? obj : null;
  }
  if (!inbound) throw new Error("Configured 3x-ui inbound was not found.");
  return inbound;
}
function trialClient(inbound, email) {
  const settings = trialObj(inbound.settings);
  const clients = Array.isArray(settings.clients) ? settings.clients : [];
  const stats = Array.isArray(inbound.clientStats) ? inbound.clientStats : [];
  return {
    client: clients.find(c => String(c.email || "").toLowerCase() === email.toLowerCase()) || null,
    stat: stats.find(c => String(c.email || "").toLowerCase() === email.toLowerCase()) || null
  };
}
function trialConfig(inbound, client, email, plan, sni) {
  const protocol = String(inbound.protocol || "").toLowerCase();
  const port = Number(inbound.port);
  const host = String(process.env.XUI_PUBLIC_HOST || new URL(process.env.XUI_BASE_URL).hostname).trim();
  const stream = trialObj(inbound.streamSettings);
  const network = String(stream.network || "tcp").toLowerCase();
  const security = String(stream.security || "none").toLowerCase();
  const tls = trialObj(stream.tlsSettings);
  const reality = trialObj(stream.realitySettings);
  const realitySettings = trialObj(reality.settings);
  const id = client.id || client.password || client.auth;
  if (!id || !port || !host) throw new Error("Panel client ID, inbound port, or public host is missing.");
  const p = new URLSearchParams({ type:network, security:security, sni:sni });
  if (network === "tcp") {
    const tcp = trialObj(stream.tcpSettings);
    const header = trialObj(tcp.header);
    if (header.type) p.set("headerType", header.type);
  }
  if (network === "ws") {
    const ws = trialObj(stream.wsSettings);
    if (ws.path) p.set("path", ws.path);
    if (ws.host) p.set("host", ws.host);
  }
  if (network === "grpc") {
    const grpc = trialObj(stream.grpcSettings);
    if (grpc.serviceName) p.set("serviceName", grpc.serviceName);
  }
  if (security === "reality") {
    p.set("fp", "chrome");
    const pk = realitySettings.publicKey || realitySettings.serverPublicKey;
    if (pk) p.set("pbk", pk);
    if (Array.isArray(reality.shortIds) && reality.shortIds[0]) p.set("sid", reality.shortIds[0]);
    if (realitySettings.spiderX) p.set("spx", realitySettings.spiderX);
  } else if (security === "tls") {
    p.set("fp", tls.fingerprint || "chrome");
    if (Array.isArray(tls.alpn)) p.set("alpn", tls.alpn.join(","));
  }
  const label = encodeURIComponent(("Aura-Free-Trial-" + plan + "-" + email).replace(/[^a-zA-Z0-9._-]/g, "-"));
  if (protocol === "vless") return "vless://" + encodeURIComponent(id) + "@" + host + ":" + port + "?encryption=none&" + p.toString() + "#" + label;
  if (protocol === "trojan") return "trojan://" + encodeURIComponent(id) + "@" + host + ":" + port + "?" + p.toString() + "#" + label;
  if (protocol === "vmess") {
    const vmess = {v:"2",ps:"Aura-Free-Trial-" + plan,add:host,port:String(port),id:id,aid:String(client.alterId || 0),scy:client.security || "auto",net:network,type:"none",host:"",path:"",tls:security === "tls" ? "tls" : "",sni:sni};
    if (network === "ws") { const ws = trialObj(stream.wsSettings); vmess.path = ws.path || ""; vmess.host = ws.host || ""; }
    return "vmess://" + Buffer.from(JSON.stringify(vmess)).toString("base64");
  }
  throw new Error("Only VLESS, VMess, and Trojan inbound configurations can be generated automatically.");
}
async function trialStored(uid) {
  const snap = await db.collection("trialServices").doc(uid).get();
  return snap.exists ? snap.data() : null;
}
function trialPublic(data) {
  if (!data) return null;
  return { type:"Free Trial", plan:data.plan, isp:data.isp, email:data.email, status:data.status,
    dataLimitGB:data.dataLimitGB || TRIAL_GB, totalBytes:data.totalBytes || TRIAL_BYTES,
    usedBytes:data.usedBytes || 0, ipLimit:data.ipLimit || 1, days:data.days || TRIAL_DAYS,
    createdAt:data.createdAt || null, expiresAt:data.expiresAt || null };
}
app.get("/api/trial", requireLogin, async (req,res) => {
  try {
    const service = await trialStored(req.session.uid);
    res.json({success:true, claimed:!!(service && service.status !== "failed"), service:trialPublic(service)});
  } catch (e) { console.error("[TRIAL]",e.message); res.status(500).json({success:false,message:"Unable to load trial service."}); }
});
app.post("/api/trial/claim", requireLogin, async (req,res) => {
  const uid = req.session.uid;
  const ref = db.collection("trialServices").doc(uid);
  let reserved = false;
  const reservationId = crypto.randomUUID();
  try {
    const user = await firebaseAuth.getUser(uid);
    const email = String(user.email || req.session.email || "").trim().toLowerCase();
    const isp = String(req.body && req.body.isp || "").trim();
    const plan = String(req.body && req.body.plan || "").trim();
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({success:false,message:"A valid account email is required."});
    if (!Object.prototype.hasOwnProperty.call(TRIAL_ISP_PLANS,isp) || !TRIAL_ISP_PLANS[isp].includes(plan) || !TRIAL_SNI_ENV[plan]) return res.status(400).json({success:false,message:"Choose a valid ISP and package."});
    const inboundId = Number(process.env.XUI_INBOUND_ID || 1);
    const sni = String(process.env[TRIAL_SNI_ENV[plan]] || "").trim();
    if (!Number.isInteger(inboundId) || inboundId < 1 || !sni) return res.status(500).json({success:false,message:"XUI inbound or package SNI environment settings are missing."});
    await db.runTransaction(async tx => {
      const snap = await tx.get(ref);
      if (snap.exists && snap.data().status !== "failed") {
        const err = new Error(snap.data().status === "creating" ? "Your trial is already being created." : "You have already claimed your free trial.");
        err.statusCode = 409; throw err;
      }
      tx.set(ref,{uid:uid,email:email,isp:isp,plan:plan,sni:sni,inboundId:inboundId,status:"creating",reservationId:reservationId,createdAt:new Date().toISOString(),dataLimitGB:TRIAL_GB,totalBytes:TRIAL_BYTES,usedBytes:0,ipLimit:1,days:TRIAL_DAYS});
    });
    reserved = true;
    const inbound = await trialInbound(inboundId);
    const expiryTime = Date.now() + TRIAL_DAYS * 86400000;
    const created = await trialXui("/panel/api/clients", {method:"POST",body:JSON.stringify({
      email:email,inboundIds:[inboundId],enable:true,limitIp:1,totalGB:TRIAL_BYTES,expiryTime:expiryTime,
      remark:"Aura Cloud Free Trial - " + plan,reset:0
    })});
    let refreshed = inbound;
    try { refreshed = await trialInbound(inboundId); } catch (e) { console.warn("[TRIAL] Inbound refresh:",e.message); }
    let found = trialClient(refreshed,email);
    let client = found.client;
    if (!client) {
      const obj = trialUnwrap(created);
      client = obj.client || obj.obj && obj.obj.client || obj;
      if (Array.isArray(client)) client = client.find(c => String(c.email || "").toLowerCase() === email);
    }
    if (!client || !(client.id || client.password || client.auth)) {
      try {
        const lookup = trialUnwrap(await trialXui("/panel/api/clients/" + encodeURIComponent(email)));
        client = lookup.client || lookup.obj && lookup.obj.client || lookup;
      } catch (e) { console.warn("[TRIAL] Client lookup:",e.message); }
    }
    if (!client || !(client.id || client.password || client.auth)) throw new Error("Panel accepted the request but the client ID could not be read back. Verify the API's client response format.");
    const config = trialConfig(refreshed,client,email,plan,sni);
    const service = {uid:uid,email:email,isp:isp,plan:plan,sni:sni,inboundId:inboundId,clientId:client.id || null,status:"active",config:config,
      createdAt:new Date().toISOString(),expiresAt:new Date(expiryTime).toISOString(),dataLimitGB:TRIAL_GB,totalBytes:TRIAL_BYTES,
      usedBytes:Number(found.stat && found.stat.up || 0)+Number(found.stat && found.stat.down || 0),ipLimit:1,days:TRIAL_DAYS,reservationId:reservationId};
    await ref.set(service,{merge:true});
    res.status(201).json({success:true,claimed:true,service:trialPublic(service)});
  } catch (e) {
    if (reserved) {
      try { await ref.set({status:"failed",failureReason:String(e.message || "Provisioning failed").slice(0,250),failedAt:new Date().toISOString()},{merge:true}); } catch (_) {}
    }
    console.error("[TRIAL] Claim failed:",e.message);
    res.status(Number(e.statusCode) || 502).json({success:false,message:e.statusCode === 409 ? e.message : "Trial provisioning failed. Check the 3x-ui bearer-token API, inbound ID, and client API permissions."});
  }
});
app.get("/api/trial/service", requireLogin, async (req,res) => {
  try {
    const data = await trialStored(req.session.uid);
    if (!data || data.status !== "active" || !data.config) return res.status(404).json({success:false,message:"No active free trial found."});
    let usedBytes = Number(data.usedBytes || 0);
    try {
      const inbound = await trialInbound(data.inboundId || Number(process.env.XUI_INBOUND_ID || 1));
      const found = trialClient(inbound,data.email);
      if (found.stat) usedBytes = Number(found.stat.up || 0) + Number(found.stat.down || 0);
    } catch (e) { console.warn("[TRIAL] Usage refresh unavailable:",e.message); }
    res.json({success:true,service:{...trialPublic({...data,usedBytes}),sni:data.sni,config:data.config}});
  } catch (e) { console.error("[TRIAL] Service details:",e.message); res.status(500).json({success:false,message:"Unable to load trial details."}); }
});


// ============================================================
// SERVE PUBLIC FILES
// ============================================================

app.use(
    express.static(
        PUBLIC_DIR
    )
);


// ============================================================
// DASHBOARD PAGE
// ============================================================

app.get("/dashboard", (req,res) => {
    const pub = path.join(PUBLIC_DIR,"dashboard.html");
    res.sendFile(fs.existsSync(pub) ? pub : path.join(__dirname,"dashboard.html"));
});


app.get("/dashboard.html", (req,res) => {
    const pub = path.join(PUBLIC_DIR,"dashboard.html");
    res.sendFile(fs.existsSync(pub) ? pub : path.join(__dirname,"dashboard.html"));
});


// ============================================================
// AUTH PAGE
// ============================================================

app.get(
    "/auth",
    (req, res) => {
        const authPath =
            path.join(
                PUBLIC_DIR,
                "auth.html"
            );

        if (fs.existsSync(authPath)) {
            return res.sendFile(
                authPath
            );
        }

        return res.sendFile(
            path.join(
                PUBLIC_DIR,
                "index.html"
            )
        );
    }
);


// ============================================================
// ROOT
// ============================================================

app.get(
    "/",
    (req, res) => {
        const indexPath =
            path.join(
                PUBLIC_DIR,
                "index.html"
            );

        if (
            fs.existsSync(indexPath)
        ) {
            return res.sendFile(
                indexPath
            );
        }

        res.status(404).send(
            "Aura Cloud index.html not found."
        );
    }
);


// ============================================================
// API 404
// ============================================================

app.use(
    "/api",
    (req, res) => {
        console.log(
            `[API 404] ${req.method} ${req.originalUrl}`
        );

        res.status(404).json({
            success: false,

            error:
                "API endpoint not found.",

            path:
                req.originalUrl,

            method:
                req.method
        });
    }
);


// ============================================================
// GENERAL 404
// ============================================================

app.use(
    (req, res) => {
        res.status(404).send(
            "Page not found."
        );
    }
);


// ============================================================
// ERROR HANDLER
// ============================================================

app.use(
    (error, req, res, next) => {
        console.error(
            "[SERVER ERROR]",
            error
        );


        if (res.headersSent) {
            return next(error);
        }


        res.status(500).json({
            success: false,

            message:
                "Internal server error."
        });
    }
);


// ============================================================
// START SERVER
// ============================================================

app.listen(
    PORT,
    () => {
        console.log("");
        console.log("==============================================");
        console.log("        AURA CLOUD SERVER ONLINE");
        console.log("==============================================");
        console.log(
            `Local: http://localhost:${PORT}`
        );
        console.log(
            `Public: ${PUBLIC_DIR}`
        );
        console.log("");
        console.log(
            "Support endpoint:"
        );
        console.log(
            `POST http://localhost:${PORT}/api/support/email`
        );
        console.log("");
        console.log(
            `Support email: ${SUPPORT_EMAIL}`
        );
        console.log("==============================================");
        console.log("");
    }
);