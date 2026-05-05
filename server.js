const express = require('express');
const admin = require('firebase-admin');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const NodeCache = require('node-cache');
const helmet = require('helmet');
const cors = require('cors');

// ==========================================
// 🔴 1. GLOBAL ERROR HANDLERS (Chống chết ngầm)
// ==========================================
process.on("uncaughtException", err => {
    console.error("[FATAL] Uncaught Exception:", err);
    // Ghi log vào file hoặc monitor service ở đây
});
process.on("unhandledRejection", reason => {
    console.error("[FATAL] Unhandled Rejection:", reason);
});

// ==========================================
// 🔴 2. ENV VALIDATION (Fail-fast chống Crash)
// ==========================================
const requiredEnv = ["JWT_PUBLIC_KEY", "JWT_PRIVATE_KEY"];
requiredEnv.forEach(key => {
    if (!process.env[key]) {
        console.error(`❌ CRITICAL ERROR: Missing ENV variable: ${key}`);
        process.exit(1); // Ép Server dừng ngay lập tức nếu thiếu Key
    }
});

const formatKey = (key) => key.replace(/\\n/g, '\n');
const CONFIG = {
    JWT_PUBLIC: formatKey(process.env.JWT_PUBLIC_KEY),
    JWT_PRIVATE: formatKey(process.env.JWT_PRIVATE_KEY),
    JWT_ISSUER: "autojms-license-server",
    JWT_AUDIENCE: "autojms-desktop-client"
};

// ==========================================
// 🟠 3. KHỞI TẠO SERVICES
// ==========================================
const serviceAccount = require('./serviceAccountKey.json');
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://keyauthjms-default-rtdb.asia-southeast1.firebasedatabase.app/" 
});

const app = express();

// --- BẢO VỆ TẦNG NETWORK & HTTP ---
app.set('trust proxy', 1); // ⚠️ Rất quan trọng khi host trên Render/Heroku để Rate Limit hoạt động
app.disable("x-powered-by"); // Giấu thông tin Express
app.use(helmet()); // Thêm các Header bảo mật HTTP
app.use(cors()); // Cấu hình CORS nếu cần gọi từ Web (hiện tại cho phép tất cả)
app.use(express.json({ limit: "10kb" })); // Chống Payload quá khổ gây tràn RAM

// --- MIDDLEWARE: TIMEOUT (Chống treo Server) ---
app.use((req, res, next) => {
    req.setTimeout(5000, () => {
        const err = new Error('Request Timeout');
        err.status = 408;
        next(err);
    });
    res.setTimeout(5000, () => {
        const err = new Error('Service Unavailable');
        err.status = 503;
        next(err);
    });
    next();
});

// ==========================================
// 🟡 4. CACHE & RATE LIMIT
// ==========================================
const jtiCache = new NodeCache({ stdTTL: 900, checkperiod: 120 }); // Lưu JTI chống Replay Attack

const verifyLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    message: { code: "RATE_LIMIT_EXCEEDED", error: "Thao tác quá nhanh, vui lòng chậm lại." }
});

// Đọc danh sách Hash từ cấu hình (Anti-Tamper)
const VALID_EXE_HASHES = (process.env.VALID_EXE_HASHES || "").split(',').filter(Boolean).map(h => h.trim().toLowerCase());

// ==========================================
// 🟢 5. API ENDPOINTS
// ==========================================

// --- VALIDATION HELPER ---
const sanitizeInput = (key, hwid) => {
    if (typeof key !== "string" || key.length > 50 || key.length < 5) return false;
    if (typeof hwid !== "string" || hwid.length > 150 || hwid.length < 10) return false;
    return true;
};

// [API 1]: ĐĂNG NHẬP (VERIFY)
app.post('/api/verify-license', verifyLimiter, async (req, res, next) => {
    try {
        const { licenseKey, hwid, exeHash } = req.body;
        
        // Bổ sung thêm error để C# đọc được
        if (!sanitizeInput(licenseKey, hwid)) return res.status(400).json({ code: "INVALID_INPUT", error: "Định dạng Key không hợp lệ (Phải từ 5-50 ký tự)." });

        if (VALID_EXE_HASHES.length > 0 && (!exeHash || !VALID_EXE_HASHES.includes(exeHash.toLowerCase()))) {
            return res.status(401).json({ code: "CLIENT_MODIFIED", error: "Phiên bản phần mềm không hợp lệ hoặc đã bị can thiệp." });
        }

        const lockRef = admin.database().ref(`locks/${licenseKey}`);
        const { committed } = await lockRef.transaction((curr) => (curr === null || Date.now() - curr.lockedAt > 5000) ? { lockedAt: admin.database.ServerValue.TIMESTAMP } : undefined);
        if (!committed) return res.status(429).json({ code: "SYSTEM_BUSY", error: "Hệ thống đang bận, vui lòng thử lại sau 5 giây." });

        try {
            const ref = admin.database().ref(`Licenses/${licenseKey}`);
            const snapshot = await ref.once('value');
            const licenseData = snapshot.val();

            // Sửa lại các dòng này: Thêm error
            if (!licenseData) return res.status(401).json({ code: "LICENSE_NOT_FOUND", error: "Key này không tồn tại trên hệ thống!" });
            if (licenseData.isActive === false) return res.status(401).json({ code: "LICENSE_DISABLED", error: "Key đã bị Admin khóa." });
            if (new Date(licenseData.expireDate) < new Date()) return res.status(401).json({ code: "LICENSE_EXPIRED", error: "Key đã hết hạn sử dụng." });
            
            if (licenseData.hwid && licenseData.hwid !== hwid) return res.status(401).json({ code: "HWID_MISMATCH", error: "Key này đã được kích hoạt cho một máy tính khác." });
            if (!licenseData.hwid) await ref.update({ hwid: hwid });

            // 4. Check Max Devices (Mặc định là 1 nếu DB không khai báo)
            const maxDevices = licenseData.maxDevices || 1;
            const sessionsRef = admin.database().ref('sessions');
            const sessionsSnap = await sessionsRef.orderByChild('licenseKey').equalTo(licenseKey).once('value');
            
            let activeSessions = 0;
            const now = Date.now();
            const updates = {}; // Danh sách các phiên ảo cần dọn dẹp

            sessionsSnap.forEach(child => {
                const session = child.val();
                
                // 🔥 NẾU CÙNG 1 MÁY (Trùng HWID): Tự động thu hồi phiên cũ đang bị treo do Crash
                if (session.hwid === hwid && session.status === "active") {
                    updates[`${child.key}/status`] = "revoked_by_crash"; 
                }
                // KHÁC MÁY: Đếm số lượng phiên đang hoạt động trong 10 phút qua
                else if (session.status === "active" && (now - session.lastPing < 10 * 60 * 1000)) {
                    activeSessions++;
                }
            });

            // Thực thi dọn dẹp các phiên thừa trên Firebase
            if (Object.keys(updates).length > 0) {
                await sessionsRef.update(updates);
            }

            if (activeSessions >= maxDevices) return res.status(403).json({ code: "MAX_DEVICES_REACHED", error: "Tài khoản đã đạt giới hạn thiết bị đăng nhập cùng lúc." });

            const sessionId = crypto.randomUUID();
            await sessionsRef.child(sessionId).set({
                licenseKey: licenseKey,
                hwid: hwid,
                createdAt: admin.database.ServerValue.TIMESTAMP,
                lastPing: admin.database.ServerValue.TIMESTAMP,
                status: "active"
            });

            // Sign JWT Strict
            const jti = crypto.randomUUID();
            const accessToken = jwt.sign(
                { key: licenseKey, hwid: hwid, sid: sessionId, jti: jti }, 
                CONFIG.JWT_PRIVATE, 
                { algorithm: 'RS256', expiresIn: '15m', issuer: CONFIG.JWT_ISSUER, audience: CONFIG.JWT_AUDIENCE }
            );

            // ==========================================
            // 🔥 SỬA DÒNG NÀY: PHẢI CÓ TRƯỜNG "cfg"
            // ==========================================
            return res.json({ 
                payload: accessToken, 
                sid: sessionId, 
                cfg: { 
                    dataSpreadsheetId: licenseData.dataSpreadsheetId || "" 
                } 
            });
            // ==========================================

        } finally {
            await lockRef.remove(); 
        }
    } catch (error) { 
        console.error("Lỗi Verify:", error); // In ra log Render để debug
        next(error); 
    }
});

// [API 2]: DUY TRÌ SỰ SỐNG (HEARTBEAT)
app.post('/api/heartbeat', async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ action: "kill", code: "MISSING_TOKEN" });
        
        const token = authHeader.split(' ')[1];
        let decoded;
        try {
            decoded = jwt.verify(token, CONFIG.JWT_PUBLIC, { 
                algorithms: ['RS256'],
                issuer: CONFIG.JWT_ISSUER,
                audience: CONFIG.JWT_AUDIENCE
            });
        } catch (err) {
            return res.status(401).json({ action: "kill", code: "INVALID_TOKEN" });
        }

        // Anti-Replay Attack Check
        if (jtiCache.has(decoded.jti)) return res.status(401).json({ action: "kill", code: "TOKEN_REUSED" });
        jtiCache.set(decoded.jti, true);

        const { clientHwid, exeHash } = req.body;
        
        // Input Validation
        if (typeof clientHwid !== "string" || clientHwid.length < 10) return res.status(400).json({ action: "kill", code: "INVALID_INPUT" });

        // Integrity Check
        if (VALID_EXE_HASHES.length > 0 && (!exeHash || !VALID_EXE_HASHES.includes(exeHash.toLowerCase()))) {
            return res.status(401).json({ action: "kill", code: "CLIENT_MODIFIED" });
        }

        if (clientHwid !== decoded.hwid) return res.status(401).json({ action: "kill", code: "HWID_FORGED" });

        const sessionRef = admin.database().ref(`sessions/${decoded.sid}`);
        const sessionSnap = await sessionRef.once('value');
        const sessionData = sessionSnap.val();

        if (!sessionData || sessionData.status !== "active") return res.status(401).json({ action: "kill", code: "SESSION_REVOKED" });

        await sessionRef.update({ lastPing: admin.database.ServerValue.TIMESTAMP });

        const newJti = crypto.randomUUID();
        const newAccessToken = jwt.sign(
            { key: decoded.key, hwid: decoded.hwid, sid: decoded.sid, jti: newJti }, 
            CONFIG.JWT_PRIVATE, 
            { algorithm: 'RS256', expiresIn: '15m', issuer: CONFIG.JWT_ISSUER, audience: CONFIG.JWT_AUDIENCE }
        );

        return res.json({ action: "continue", payload: newAccessToken });
    } catch (error) { next(error); }
});

// --- ERROR HANDLING MIDDLEWARE ---
app.use((err, req, res, next) => {
    console.error("[SERVER ERROR]", err); // In ra log Render
    const status = err.status || 500;
    res.status(status).json({ code: "SERVER_ERROR", error: "Lỗi kết nối CSDL: " + err.message });
});

// ==========================================
// 🔵 6. KHỞI ĐỘNG SERVER
// ==========================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 AutoJMS Server is running on port ${PORT}`));
