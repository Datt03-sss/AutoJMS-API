const express = require("express");
const admin = require("firebase-admin");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const fs = require("fs");
const { GoogleAuth } = require("google-auth-library");
const rateLimit = require("express-rate-limit");
const NodeCache = require("node-cache");
const helmet = require("helmet");
const cors = require("cors");

const FIREBASE_TIMEOUT_MS = Number(process.env.FIREBASE_OPERATION_TIMEOUT_MS || 8000);
const GOOGLE_SHEETS_GRANT_TIMEOUT_MS = Number(process.env.GOOGLE_SHEETS_GRANT_TIMEOUT_MS || 8000);
const GOOGLE_SHEETS_SCOPE = "https://www.googleapis.com/auth/spreadsheets";
const DEFAULT_SUPABASE_PROJECT_REF = "bnsnnrlwfzxemmizknwy";
const DEFAULT_SUPABASE_BUCKET = "autojms-modules";

// ==========================================
// ERROR HANDLER
// ==========================================
process.on("uncaughtException", err => console.error("[FATAL]", err));
process.on("unhandledRejection", err => console.error("[FATAL]", err));

// ==========================================
// ENV CONFIG
// ==========================================
if (!process.env.JWT_PRIVATE_KEY || !process.env.JWT_PUBLIC_KEY) {
    console.error("Missing JWT keys in Environment Variables");
    process.exit(1);
}

const formatKey = (k) => {
    if (!k) return "";
    return k.replace(/^"|"$/g, "").replace(/\\n/g, "\n");
};

const toPublicStorageBase = (value) => {
    const raw = String(value || "").trim().replace(/\/+$/g, "");
    if (!raw) {
        return `https://${DEFAULT_SUPABASE_PROJECT_REF}.supabase.co/storage/v1/object/public/${DEFAULT_SUPABASE_BUCKET}`;
    }

    const dashboardMatch = raw.match(/supabase\.com\/dashboard\/project\/([^/]+)\/storage\/files\/buckets\/([^/]+)/i);
    if (dashboardMatch) {
        return `https://${dashboardMatch[1]}.supabase.co/storage/v1/object/public/${dashboardMatch[2]}`;
    }

    const projectMatch = raw.match(/^https:\/\/([a-z0-9-]+)\.supabase\.co$/i);
    if (projectMatch) {
        return `${raw}/storage/v1/object/public/${DEFAULT_SUPABASE_BUCKET}`;
    }

    return raw;
};

const CONFIG = {
    PRIVATE: formatKey(process.env.JWT_PRIVATE_KEY),
    PUBLIC: formatKey(process.env.JWT_PUBLIC_KEY),

    ISSUER: "autojms-license-server",
    AUDIENCE: "autojms-desktop-client",

    SUPABASE_PROJECT_URL:
        process.env.SUPABASE_PROJECT_URL ||
        `https://${DEFAULT_SUPABASE_PROJECT_REF}.supabase.co`,

    SUPABASE_BASE_URL:
        toPublicStorageBase(process.env.SUPABASE_BASE_URL),

    SUPABASE_ANON_KEY:
        process.env.SUPABASE_ANON_KEY || "",

    DEFAULT_CHANNEL:
        process.env.DEFAULT_UPDATE_CHANNEL || "stable"
};

const SUPABASE_MANIFESTS = {
    appManifest:
        `${CONFIG.SUPABASE_BASE_URL}/manifest/app-manifest.json`,

    versionLatest:
        `${CONFIG.SUPABASE_BASE_URL}/manifest/version-latest.json`,

    hashManifest:
        `${CONFIG.SUPABASE_BASE_URL}/manifest/hash-manifest.json`,

    selectorUpdateManifest:
        `${CONFIG.SUPABASE_BASE_URL}/selector-updates/selector-update-manifest.json`,

    smallUpdateManifest:
        `${CONFIG.SUPABASE_BASE_URL}/selector-updates/selector-update-manifest.json`,

    tierDefinitions:
        `${CONFIG.SUPABASE_BASE_URL}/manifest/tier-definitions.json`,

    publicConfig:
        `${CONFIG.SUPABASE_BASE_URL}/configs/public-config.json`,

    runtimePolicy:
        `${CONFIG.SUPABASE_BASE_URL}/configs/runtime-policy.json`
};

// ==========================================
// FIREBASE INIT
// ==========================================
function loadFirebaseServiceAccountFromFile() {
    const filePath = process.env.FIREBASE_SERVICE_ACCOUNT_FILE;

    if (!filePath || !filePath.trim()) {
        throw new Error("Missing FIREBASE_SERVICE_ACCOUNT_FILE in Environment Variables");
    }

    if (!fs.existsSync(filePath)) {
        throw new Error(`FIREBASE_SERVICE_ACCOUNT_FILE not found: ${filePath}`);
    }

    const json = fs.readFileSync(filePath, "utf8");
    const serviceAccount = JSON.parse(json);

    if (
        !serviceAccount.project_id ||
        !serviceAccount.client_email ||
        !serviceAccount.private_key
    ) {
        throw new Error("Firebase service account file is missing required fields");
    }

    return serviceAccount;
}

if (!process.env.FIREBASE_DATABASE_URL) {
    console.error("Missing FIREBASE_DATABASE_URL in Environment Variables");
    process.exit(1);
}

const serviceAccount = loadFirebaseServiceAccountFromFile();

console.log("[firebase] project_id:", serviceAccount.project_id);
console.log("[firebase] database_url:", process.env.FIREBASE_DATABASE_URL);

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: process.env.FIREBASE_DATABASE_URL
});

// ==========================================
// APP INIT
// ==========================================
const app = express();

app.set("trust proxy", 1);
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: "512kb" }));

const limiter = rateLimit({
    windowMs: 60_000,
    max: 20
});

const heartbeatLimiter = rateLimit({
    windowMs: 60_000,
    max: 120
});

const googleSheetsGrantLimiter = rateLimit({
    windowMs: 60_000,
    max: 60
});

const jtiCache = new NodeCache({ stdTTL: 3600 });
let googleSheetsAuthClient = null;
let googleSheetsServiceAccount = null;

// ==========================================
// HELPERS
// ==========================================
function withTimeout(promise, ms, label) {
    let timer;
    return Promise.race([
        promise,
        new Promise((_, reject) => {
            timer = setTimeout(() => reject(new Error(`${label}_TIMEOUT`)), ms);
        })
    ]).finally(() => clearTimeout(timer));
}

function isTimeoutError(error) {
    return typeof error?.message === "string" && error.message.endsWith("_TIMEOUT");
}

function maskLicenseKey(key) {
    const s = String(key || "");
    if (s.length <= 8) return "****";
    return `${s.slice(0, 4)}-****-${s.slice(-4)}`;
}

function sendTimeoutResponse(res) {
    return res.status(503).json({
        success: false,
        error: "FIREBASE_TIMEOUT",
        message: "License server timeout while verifying license."
    });
}

function normalizeTier(tier) {
    return String(tier || "BASE")
        .trim()
        .toUpperCase();
}

function getClientIp(req) {
    return (
        req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
        req.socket.remoteAddress ||
        ""
    );
}

function signAccessToken({ licenseKey, hwid, sessionId, tier }) {
    return jwt.sign(
        {
            key: licenseKey,
            hwid,
            sid: sessionId,
            tier,
            jti: crypto.randomUUID()
        },
        CONFIG.PRIVATE,
        {
            algorithm: "RS256",
            expiresIn: "60m",
            issuer: CONFIG.ISSUER,
            audience: CONFIG.AUDIENCE,
            keyid: "accessKey"
        }
    );
}

function createPublicError(statusCode, error, message) {
    const err = new Error(error);
    err.statusCode = statusCode;
    err.publicError = error;
    err.publicMessage = message;
    return err;
}

function loadGoogleSheetsServiceAccount() {
    if (googleSheetsServiceAccount) {
        return googleSheetsServiceAccount;
    }

    const filePath = process.env.GOOGLE_SHEETS_SERVICE_ACCOUNT_FILE;

    if (!filePath || !filePath.trim()) {
        throw new Error("Missing GOOGLE_SHEETS_SERVICE_ACCOUNT_FILE in Environment Variables");
    }

    if (!fs.existsSync(filePath)) {
        throw new Error("GOOGLE_SHEETS_SERVICE_ACCOUNT_FILE not found");
    }

    const json = fs.readFileSync(filePath, "utf8");
    const serviceAccount = JSON.parse(json);

    if (
        !serviceAccount.project_id ||
        !serviceAccount.client_email ||
        !serviceAccount.private_key
    ) {
        throw new Error("Google Sheets service account file is missing required fields");
    }

    googleSheetsServiceAccount = serviceAccount;
    console.log("[google-sheets] service account project_id:", serviceAccount.project_id);

    return googleSheetsServiceAccount;
}

async function getGoogleSheetsAccessGrant() {
    if (!googleSheetsAuthClient) {
        const googleSheetsCredential = loadGoogleSheetsServiceAccount();
        const auth = new GoogleAuth({
            credentials: googleSheetsCredential,
            scopes: [GOOGLE_SHEETS_SCOPE]
        });

        googleSheetsAuthClient = await withTimeout(
            auth.getClient(),
            GOOGLE_SHEETS_GRANT_TIMEOUT_MS,
            "GOOGLE_SHEETS_AUTH_CLIENT"
        );
    }

    const tokenResponse = await withTimeout(
        googleSheetsAuthClient.getAccessToken(),
        GOOGLE_SHEETS_GRANT_TIMEOUT_MS,
        "GOOGLE_SHEETS_ACCESS_TOKEN"
    );

    const accessToken = typeof tokenResponse === "string"
        ? tokenResponse
        : tokenResponse?.token;

    if (!accessToken) {
        throw new Error("GOOGLE_SHEETS_ACCESS_TOKEN_EMPTY");
    }

    const expiryMs = Number(googleSheetsAuthClient.credentials?.expiry_date || 0);
    const expiresAtMs = expiryMs > Date.now()
        ? expiryMs
        : Date.now() + 3600_000;

    return {
        accessToken,
        expiresAt: new Date(expiresAtMs).toISOString(),
        expiresInSeconds: Math.max(60, Math.floor((expiresAtMs - Date.now()) / 1000))
    };
}

async function verifyLicenseTokenAndSession(req) {
    const auth = req.headers.authorization || "";

    if (!auth.startsWith("Bearer ")) {
        throw createPublicError(401, "UNAUTHORIZED", "Missing license token.");
    }

    const token = auth.slice("Bearer ".length).trim();

    if (!token) {
        throw createPublicError(401, "UNAUTHORIZED", "Missing license token.");
    }

    let decoded;

    try {
        decoded = jwt.verify(token, CONFIG.PUBLIC, {
            algorithms: ["RS256"],
            issuer: CONFIG.ISSUER,
            audience: CONFIG.AUDIENCE
        });
    } catch {
        throw createPublicError(401, "UNAUTHORIZED", "Invalid or expired license token.");
    }

    const sessionRef = admin.database().ref(`sessions/${decoded.sid}`);
    const snap = await withTimeout(
        sessionRef.once("value"),
        FIREBASE_TIMEOUT_MS,
        "FIREBASE_GOOGLE_SHEETS_SESSION_READ"
    );

    if (!snap.exists()) {
        throw createPublicError(401, "SESSION_NOT_FOUND", "License session was revoked.");
    }

    const sessionData = snap.val();

    if (
        sessionData.status !== "active" ||
        sessionData.licenseKey !== decoded.key ||
        sessionData.hwid !== decoded.hwid
    ) {
        throw createPublicError(401, "SESSION_INACTIVE", "License session is not active.");
    }

    return { decoded, sessionData };
}

// ==========================================
// HEALTH CHECK
// ==========================================
app.get("/health", (req, res) => {
    res.json({
        ok: true,
        service: "autojms-license-server",
        time: Date.now()
    });
});

app.get("/health/firebase", async (req, res) => {
    const started = Date.now();

    try {
        await withTimeout(
            admin.database().ref(".info/connected").once("value"),
            FIREBASE_TIMEOUT_MS,
            "FIREBASE_HEALTH_READ"
        );

        return res.json({
            ok: true,
            service: "firebase",
            elapsedMs: Date.now() - started
        });
    } catch (err) {
        return res.status(503).json({
            ok: false,
            error: err.message,
            elapsedMs: Date.now() - started
        });
    }
});

app.get("/health/firebase/licenses", async (req, res) => {
    const started = Date.now();

    try {
        const snap = await withTimeout(
            admin.database().ref("Licenses").limitToFirst(1).once("value"),
            FIREBASE_TIMEOUT_MS,
            "FIREBASE_LICENSES_HEALTH_READ"
        );

        return res.json({
            ok: true,
            service: "firebase-licenses",
            exists: snap.exists(),
            elapsedMs: Date.now() - started
        });
    } catch (err) {
        return res.status(503).json({
            ok: false,
            error: err.message,
            elapsedMs: Date.now() - started
        });
    }
});

// ==========================================
// API 1: VERIFY LICENSE
// ==========================================
app.post("/api/verify-license", limiter, async (req, res) => {
    const requestId = crypto.randomUUID();
    const started = Date.now();

    try {
        const { licenseKey, hwid, exeHash, appVersion } = req.body || {};
        const maskedLicenseKey = maskLicenseKey(licenseKey);

        console.log(`[verify-license] start requestId=${requestId} license=${maskedLicenseKey}`);

        if (!licenseKey || !hwid) {
            return res.status(400).json({
                success: false,
                error: "MISSING_REQUIRED_FIELDS",
                message: "License key and HWID are required."
            });
        }

        const ref = admin.database().ref(`Licenses/${licenseKey}`);

        console.log("[verify-license] firebase license read start");
        const licenseReadStarted = Date.now();
        const snap = await withTimeout(
            ref.once("value"),
            FIREBASE_TIMEOUT_MS,
            "FIREBASE_LICENSE_READ"
        );
        console.log(`[verify-license] firebase license read done elapsedMs=${Date.now() - licenseReadStarted}`);

        const data = snap.val();

        if (!data) {
            console.log(`[verify-license] license not found requestId=${requestId} elapsedMs=${Date.now() - started}`);
            return res.status(404).json({
                success: false,
                error: "LICENSE_NOT_FOUND",
                message: "License key not found."
            });
        }

        if (data.status !== "active") {
            return res.status(401).json({
                success: false,
                error: "LICENSE_INACTIVE",
                message: "License key is inactive or locked."
            });
        }

        const tier = normalizeTier(data.tier);
        const skipHashCheck = data.skipHashCheck === true;
        const middleCode = data.middleCode || "";
        const modulePolicy = data.modulePolicy || {
            autoUpdate: true,
            silentUpdate: true,
            applyOnNextStartup: true
        };

        // Hash verification for protected builds.
        // Major update hash should be controlled by server env or future hash-manifest.
        if (!skipHashCheck) {
            const validHashesStr = process.env.VALID_EXE_HASHES || "";

            if (validHashesStr.trim() !== "") {
                const validHashes = validHashesStr
                    .split(",")
                    .map(h => h.trim().toLowerCase())
                    .filter(Boolean);

                const localHash = String(exeHash || "").toLowerCase();

                if (!localHash || !validHashes.includes(localHash)) {
                    console.warn("[HASH_INVALID]", {
                        licenseKey: maskedLicenseKey,
                        hasExeHash: Boolean(exeHash),
                        appVersion
                    });

                    return res.status(403).json({
                        success: false,
                        error: "HASH_INVALID",
                        message: "Application hash is invalid or outdated."
                    });
                }
            }
        }

        // HWID lock
        if (data.hwid && data.hwid !== hwid) {
            return res.status(401).json({
                success: false,
                error: "HWID_MISMATCH",
                message: "License key is already bound to another machine."
            });
        }

        if (!data.hwid) {
            const licenseUpdateStarted = Date.now();
            await withTimeout(
                ref.update({
                    hwid,
                    activatedAt: Date.now()
                }),
                FIREBASE_TIMEOUT_MS,
                "FIREBASE_LICENSE_UPDATE"
            );
            console.log(`[verify-license] firebase license update done elapsedMs=${Date.now() - licenseUpdateStarted}`);
        }

        // Clear old sessions of same license + same device
        const sessionsRef = admin.database().ref("sessions");
        const sessionsReadStarted = Date.now();
        const sessionsSnap = await withTimeout(
            sessionsRef
                .orderByChild("licenseKey")
                .equalTo(licenseKey)
                .once("value"),
            FIREBASE_TIMEOUT_MS,
            "FIREBASE_SESSIONS_READ"
        );
        console.log(`[verify-license] firebase sessions read done elapsedMs=${Date.now() - sessionsReadStarted}`);

        const updates = {};

        sessionsSnap.forEach(child => {
            const session = child.val();

            if (session.hwid === hwid) {
                updates[child.key] = null;
            }
        });

        if (Object.keys(updates).length > 0) {
            const sessionsUpdateStarted = Date.now();
            await withTimeout(
                sessionsRef.update(updates),
                FIREBASE_TIMEOUT_MS,
                "FIREBASE_SESSIONS_UPDATE"
            );
            console.log(`[verify-license] firebase sessions update done elapsedMs=${Date.now() - sessionsUpdateStarted}`);
        }

        // Create new session
        const sessionId = crypto.randomUUID();

        console.log("[verify-license] session write start");
        const sessionWriteStarted = Date.now();
        await withTimeout(
            admin.database().ref(`sessions/${sessionId}`).set({
                licenseKey,
                hwid,
                tier,
                middleCode,
                status: "active",
                appVersion: appVersion || "",
                ip: getClientIp(req),
                createdAt: Date.now(),
                lastPing: Date.now()
            }),
            FIREBASE_TIMEOUT_MS,
            "FIREBASE_SESSION_WRITE"
        );
        console.log(`[verify-license] session write done elapsedMs=${Date.now() - sessionWriteStarted}`);

        const token = signAccessToken({
            licenseKey,
            hwid,
            sessionId,
            tier
        });

        console.log(`[verify-license] success elapsedMs=${Date.now() - started} requestId=${requestId}`);

        return res.json({
            payload: token,
            sid: sessionId,
            tier,
            middleCode,
            skipHashCheck,
            modulePolicy,

            license: {
                status: data.status || "active",
                tier,
                middleCode,
                skipHashCheck,
                modulePolicy
            },

            cfg: {
                dataSpreadsheetId: data.dataSpreadsheetId || "",
                updateChannel: data.updateChannel || CONFIG.DEFAULT_CHANNEL
            },

            supabase: {
                baseUrl: CONFIG.SUPABASE_BASE_URL,
                projectUrl: CONFIG.SUPABASE_PROJECT_URL,
                anonKey: CONFIG.SUPABASE_ANON_KEY,
                manifests: SUPABASE_MANIFESTS
            }
        });
    } catch (e) {
        console.error(`[verify-license] error requestId=${requestId} elapsedMs=${Date.now() - started}`, {
            error: e.message
        });

        if (isTimeoutError(e)) {
            return sendTimeoutResponse(res);
        }

        return res.status(500).json({
            success: false,
            error: "INTERNAL_ERROR",
            message: "License server internal error."
        });
    }
});

// ==========================================
// API 2: GOOGLE SHEETS TOKEN BROKER
// ==========================================
app.post("/api/google-sheets/grant", googleSheetsGrantLimiter, async (req, res) => {
    const requestId = crypto.randomUUID();
    const started = Date.now();

    try {
        console.log(`[google-sheets-grant] start requestId=${requestId}`);

        const { decoded } = await verifyLicenseTokenAndSession(req);
        const maskedLicenseKey = maskLicenseKey(decoded.key);

        const licenseSnap = await withTimeout(
            admin.database().ref(`Licenses/${decoded.key}`).once("value"),
            FIREBASE_TIMEOUT_MS,
            "FIREBASE_GOOGLE_SHEETS_LICENSE_READ"
        );

        if (!licenseSnap.exists()) {
            return res.status(404).json({
                ok: false,
                error: "LICENSE_NOT_FOUND",
                message: "License key not found."
            });
        }

        const licenseData = licenseSnap.val() || {};

        if (licenseData.status !== "active") {
            return res.status(403).json({
                ok: false,
                error: "LICENSE_INACTIVE",
                message: "License key is inactive or locked."
            });
        }

        const grant = await getGoogleSheetsAccessGrant();

        console.log(
            `[google-sheets-grant] success requestId=${requestId} license=${maskedLicenseKey} elapsedMs=${Date.now() - started}`
        );

        return res.json({
            ok: true,
            provider: "google-sheets-token-broker",
            accessToken: grant.accessToken,
            expiresAt: grant.expiresAt,
            expiresInSeconds: grant.expiresInSeconds,
            spreadsheetId: licenseData.dataSpreadsheetId || "",
            scopes: [GOOGLE_SHEETS_SCOPE]
        });
    } catch (e) {
        console.error(`[google-sheets-grant] error requestId=${requestId} elapsedMs=${Date.now() - started}`, {
            error: e.message
        });

        if (isTimeoutError(e)) {
            return res.status(503).json({
                ok: false,
                error: "GOOGLE_SHEETS_TIMEOUT",
                message: "Google Sheets token broker timeout."
            });
        }

        if (e.statusCode) {
            return res.status(e.statusCode).json({
                ok: false,
                error: e.publicError || "GOOGLE_SHEETS_GRANT_FAILED",
                message: e.publicMessage || "Google Sheets grant failed."
            });
        }

        if (
            String(e.message || "").includes("GOOGLE_SHEETS_SERVICE_ACCOUNT_FILE") ||
            String(e.message || "").toLowerCase().includes("service account") ||
            String(e.message || "").includes("GOOGLE_SHEETS_ACCESS_TOKEN_EMPTY")
        ) {
            return res.status(503).json({
                ok: false,
                error: "GOOGLE_SHEETS_BROKER_UNAVAILABLE",
                message: "Google Sheets token broker is not configured."
            });
        }

        return res.status(500).json({
            ok: false,
            error: "GOOGLE_SHEETS_GRANT_FAILED",
            message: "Google Sheets grant failed."
        });
    }
});

// ==========================================
// API 3: HEARTBEAT
// ==========================================
app.post("/api/heartbeat", heartbeatLimiter, async (req, res) => {
    const requestId = crypto.randomUUID();
    const started = Date.now();

    try {
        const auth = req.headers.authorization;

        if (!auth || !auth.startsWith("Bearer ")) {
            return res.status(401).json({
                action: "kill",
                reason: "Từ chối truy cập: Không tìm thấy Token."
            });
        }

        const token = auth.split(" ")[1];

        let decoded;

        try {
            decoded = jwt.verify(token, CONFIG.PUBLIC, {
                algorithms: ["RS256"],
                issuer: CONFIG.ISSUER,
                audience: CONFIG.AUDIENCE
            });
        } catch {
            return res.status(401).json({
                action: "kill",
                reason: "Token đã hết hạn hoặc không khả dụng."
            });
        }

        if (jtiCache.has(decoded.jti)) {
            return res.status(401).json({
                action: "kill",
                reason: "Phát hiện nhân bản gói tin mạng."
            });
        }

        jtiCache.set(decoded.jti, true);

        const sessionRef = admin.database().ref(`sessions/${decoded.sid}`);
        const snap = await withTimeout(
            sessionRef.once("value"),
            FIREBASE_TIMEOUT_MS,
            "FIREBASE_SESSION_READ"
        );

        if (!snap.exists()) {
            return res.status(401).json({
                action: "kill",
                reason: "Phiên làm việc đã bị Admin thu hồi."
            });
        }

        const sessionData = snap.val();

        if (sessionData.status !== "active") {
            return res.status(401).json({
                action: "kill",
                reason: "Phiên làm việc đã bị khóa."
            });
        }

        await withTimeout(
            sessionRef.update({
                lastPing: Date.now()
            }),
            FIREBASE_TIMEOUT_MS,
            "FIREBASE_SESSION_UPDATE"
        );

        const newToken = signAccessToken({
            licenseKey: decoded.key,
            hwid: decoded.hwid,
            sessionId: decoded.sid,
            tier: decoded.tier || sessionData.tier || "BASE"
        });

        return res.json({
            action: "continue",
            payload: newToken,
            tier: decoded.tier || sessionData.tier || "BASE",
            middleCode: sessionData.middleCode || decoded.middleCode || ""
        });
    } catch (e) {
        console.error(`[heartbeat] error requestId=${requestId} elapsedMs=${Date.now() - started}`, {
            error: e.message
        });

        if (isTimeoutError(e)) {
            return sendTimeoutResponse(res);
        }

        return res.status(500).json({
            success: false,
            error: "INTERNAL_ERROR",
            message: "License server internal error."
        });
    }
});

// ==========================================
// API 4: LOGOUT SESSION
// ==========================================
app.post("/api/logout", async (req, res) => {
    const requestId = crypto.randomUUID();
    const started = Date.now();

    try {
        const { sid } = req.body || {};

        if (!sid) {
            return res.json({ ok: true });
        }

        await withTimeout(
            admin.database().ref(`sessions/${sid}`).remove(),
            FIREBASE_TIMEOUT_MS,
            "FIREBASE_SESSION_REMOVE"
        );

        return res.json({ ok: true });
    } catch (e) {
        console.error(`[logout] error requestId=${requestId} elapsedMs=${Date.now() - started}`, {
            error: e.message
        });

        if (isTimeoutError(e)) {
            return sendTimeoutResponse(res);
        }

        return res.status(500).json({
            success: false,
            error: "INTERNAL_ERROR",
            message: "License server internal error."
        });
    }
});

// ==========================================
// START SERVER
// ==========================================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log("AutoJMS Server Running port:", PORT);
});
