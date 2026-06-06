const express = require("express");
const admin = require("firebase-admin");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const NodeCache = require("node-cache");
const helmet = require("helmet");
const cors = require("cors");

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

const CONFIG = {
    PRIVATE: formatKey(process.env.JWT_PRIVATE_KEY),
    PUBLIC: formatKey(process.env.JWT_PUBLIC_KEY),

    ISSUER: "autojms-license-server",
    AUDIENCE: "autojms-desktop-client",

    SUPABASE_BASE_URL:
        process.env.SUPABASE_BASE_URL ||
        "https://supabase.com/dashboard/project/valmbajjpkjccqslsuou/storage/files/buckets/autojms-modules",

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

    smallUpdateManifest:
        `${CONFIG.SUPABASE_BASE_URL}/manifest/small-update-manifest.json`,

    tierDefinitions:
        `${CONFIG.SUPABASE_BASE_URL}/manifest/tier-definitions.json`
};

// ==========================================
// FIREBASE INIT
// ==========================================
const serviceAccount = require("./serviceAccountKey.json");

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL:
        "https://keyauthjms-default-rtdb.asia-southeast1.firebasedatabase.app/"
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

const jtiCache = new NodeCache({ stdTTL: 3600 });

// ==========================================
// HELPERS
// ==========================================
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

// ==========================================
// API 1: VERIFY LICENSE
// ==========================================
app.post("/api/verify-license", limiter, async (req, res) => {
    try {
        const { licenseKey, hwid, exeHash, appVersion } = req.body;

        if (!licenseKey || !hwid) {
            return res.status(400).json({
                error: "Vui lòng nhập Key."
            });
        }

        const ref = admin.database().ref(`Licenses/${licenseKey}`);
        const snap = await ref.once("value");
        const data = snap.val();

        if (!data) {
            return res.status(401).json({
                error: "Key bản quyền không tồn tại hoặc không còn khả dụng."
            });
        }

        if (data.status !== "active") {
            return res.status(401).json({
                error: "Key bản quyền đang bị khóa hoặc chưa được kích hoạt."
            });
        }

        const tier = normalizeTier(data.tier);
        const skipHashCheck = data.skipHashCheck === true;

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
                        licenseKey,
                        hwid,
                        exeHash,
                        appVersion
                    });

                    return res.status(403).json({
                        error:
                            "Phần mềm không nguyên bản hoặc phiên bản đã quá cũ. Vui lòng cập nhật bản mới nhất!"
                    });
                }
            }
        }

        // HWID lock
        if (data.hwid && data.hwid !== hwid) {
            return res.status(401).json({
                error: "Key này đang được sử dụng trên một máy tính khác."
            });
        }

        if (!data.hwid) {
            await ref.update({
                hwid,
                activatedAt: Date.now()
            });
        }

        // Clear old sessions of same license + same device
        const sessionsRef = admin.database().ref("sessions");
        const sessionsSnap = await sessionsRef
            .orderByChild("licenseKey")
            .equalTo(licenseKey)
            .once("value");

        const updates = {};

        sessionsSnap.forEach(child => {
            const session = child.val();

            if (session.hwid === hwid) {
                updates[child.key] = null;
            }
        });

        if (Object.keys(updates).length > 0) {
            await sessionsRef.update(updates);
        }

        // Create new session
        const sessionId = crypto.randomUUID();

        await admin.database().ref(`sessions/${sessionId}`).set({
            licenseKey,
            hwid,
            tier,
            status: "active",
            appVersion: appVersion || "",
            ip: getClientIp(req),
            createdAt: Date.now(),
            lastPing: Date.now()
        });

        const token = signAccessToken({
            licenseKey,
            hwid,
            sessionId,
            tier
        });

        const modulePolicy = data.modulePolicy || {
            autoUpdate: true,
            silentUpdate: true,
            applyOnNextStartup: true
        };
        const middleCode = data.middleCode || "";

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
                manifests: SUPABASE_MANIFESTS
            }
        });
    } catch (e) {
        console.error("Verify Error:", e);

        return res.status(500).json({
            error: "Lỗi máy chủ nội bộ. Vui lòng thử lại sau."
        });
    }
});

// ==========================================
// API 2: HEARTBEAT
// ==========================================
app.post("/api/heartbeat", heartbeatLimiter, async (req, res) => {
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
        const snap = await sessionRef.once("value");

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

        await sessionRef.update({
            lastPing: Date.now()
        });

        const newToken = signAccessToken({
            licenseKey: decoded.key,
            hwid: decoded.hwid,
            sessionId: decoded.sid,
            tier: decoded.tier || sessionData.tier || "BASE"
        });

        return res.json({
            action: "continue",
            payload: newToken,
            tier: decoded.tier || sessionData.tier || "BASE"
        });
    } catch (e) {
        console.error("Heartbeat Error:", e);

        return res.status(500).json({
            action: "kill",
            reason: "Lỗi nội bộ hệ thống trong quá trình duy trì ứng dụng."
        });
    }
});

// ==========================================
// API 3: LOGOUT SESSION
// ==========================================
app.post("/api/logout", async (req, res) => {
    try {
        const { sid } = req.body;

        if (!sid) {
            return res.json({ ok: true });
        }

        await admin.database().ref(`sessions/${sid}`).remove();

        return res.json({ ok: true });
    } catch (e) {
        console.error("Logout Error:", e);

        return res.status(500).json({
            ok: false
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
