const express = require('express');
const admin = require('firebase-admin');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const NodeCache = require('node-cache');

const serviceAccount = require('./serviceAccountKey.json');
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://keyauthjms-default-rtdb.asia-southeast1.firebasedatabase.app/" 
});

const app = express();
app.use(express.json());

const JWT_PRIVATE_KEY = process.env.JWT_PRIVATE_KEY.replace(/\\n/g, '\n');
const JWT_PUBLIC_KEY = process.env.JWT_PUBLIC_KEY.replace(/\\n/g, '\n');

// ĐỌC DANH SÁCH MÃ HASH HỢP LỆ TỪ BIẾN MÔI TRƯỜNG RENDER
// Ví dụ trên Render bạn điền: VALID_EXE_HASHES = "hash1,hash2"
const validHashesString = process.env.VALID_EXE_HASHES || "";
const VALID_EXE_HASHES = validHashesString.split(',').map(h => h.trim().toLowerCase());

const verifyLimiter = rateLimit({ windowMs: 60 * 1000, max: 10, message: { code: "RATE_LIMIT_EXCEEDED" } });
const jtiCache = new NodeCache({ stdTTL: 900, checkperiod: 120 });

setInterval(async () => {
    // Dọn rác Session
    try {
        const cutoff = Date.now() - (7 * 24 * 60 * 60 * 1000); 
        const sessionsRef = admin.database().ref('sessions');
        const snapshot = await sessionsRef.orderByChild('lastPing').endAt(cutoff).once('value');
        const updates = {};
        snapshot.forEach(child => { updates[child.key] = null; });
        if (Object.keys(updates).length > 0) await sessionsRef.update(updates);
    } catch (e) { }
}, 12 * 60 * 60 * 1000);

// ==========================================
// 🔐 API 1: VERIFY LICENSE
// ==========================================
app.post('/api/verify-license', verifyLimiter, async (req, res) => {
    try {
        const { licenseKey, hwid, exeHash } = req.body;
        if (!licenseKey || !hwid) return res.status(400).json({ code: "BAD_REQUEST" });

        // 🔥 KIỂM TRA MÃ BĂM PHẦN MỀM (INTEGRITY CHECK) 🔥
        if (VALID_EXE_HASHES.length > 0 && !VALID_EXE_HASHES.includes(exeHash?.toLowerCase())) {
            return res.status(401).json({ 
                code: "CLIENT_MODIFIED", 
                error: "Phiên bản phần mềm không hợp lệ, đã bị chỉnh sửa hoặc cần được cập nhật!" 
            });
        }

        const lockRef = admin.database().ref(`locks/${licenseKey}`);
        const { committed } = await lockRef.transaction((currentData) => {
            if (currentData === null || Date.now() - currentData.lockedAt > 5000) return { lockedAt: admin.database.ServerValue.TIMESTAMP };
            return; 
        });

        if (!committed) return res.status(429).json({ code: "SYSTEM_BUSY", error: "Hệ thống đang bận." });

        try {
            const ref = admin.database().ref(`licenses/${licenseKey}`);
            const snapshot = await ref.once('value');
            const licenseData = snapshot.val();

            if (!licenseData || licenseData.isActive === false) return res.status(401).json({ code: "LICENSE_INVALID", error: "Key không hợp lệ hoặc bị khóa." });
            if (new Date(licenseData.expireDate) < new Date()) return res.status(401).json({ code: "LICENSE_EXPIRED", error: "Key đã hết hạn." });
            if (licenseData.hwid && licenseData.hwid !== hwid) return res.status(401).json({ code: "HWID_MISMATCH", error: "Key này đã dùng cho máy khác." });
            
            if (!licenseData.hwid) await ref.update({ hwid: hwid });

            const maxDevices = licenseData.maxDevices || 1;
            const sessionsRef = admin.database().ref('sessions');
            const sessionsSnap = await sessionsRef.orderByChild('licenseKey').equalTo(licenseKey).once('value');
            
            let activeSessions = 0;
            const now = Date.now();
            sessionsSnap.forEach(child => {
                const sData = child.val();
                if (sData.status === "active" && (now - sData.lastPing < 10 * 60 * 1000)) activeSessions++;
            });

            if (activeSessions >= maxDevices) return res.status(403).json({ code: "MAX_DEVICES_REACHED", error: "Quá giới hạn số lượng thiết bị." });

            const sessionId = crypto.randomUUID();
            await sessionsRef.child(sessionId).set({
                licenseKey: licenseKey,
                hwid: hwid,
                createdAt: admin.database.ServerValue.TIMESTAMP,
                lastPing: admin.database.ServerValue.TIMESTAMP,
                status: "active"
            });

            const jti = crypto.randomUUID();
            const accessToken = jwt.sign(
                { key: licenseKey, hwid: hwid, sid: sessionId, jti: jti }, 
                JWT_PRIVATE_KEY, 
                { algorithm: 'RS256', expiresIn: '15m' }
            );

            return res.json({ payload: accessToken, sid: sessionId, cfg: licenseData.appConfig });
        } finally {
            await lockRef.remove(); 
        }
    } catch (error) { return res.status(500).json({ code: "INTERNAL_ERROR" }); }
});

// ==========================================
// ❤️ API 2: HEARTBEAT
// ==========================================
app.post('/api/heartbeat', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ action: "kill", code: "MISSING_TOKEN" });
        
        const token = authHeader.split(' ')[1];
        let decoded;
        try {
            decoded = jwt.verify(token, JWT_PUBLIC_KEY, { algorithms: ['RS256'] });
        } catch (err) {
            return res.status(401).json({ action: "kill", code: "INVALID_TOKEN" });
        }

        if (jtiCache.has(decoded.jti)) return res.status(401).json({ action: "kill", code: "TOKEN_REUSED" });
        jtiCache.set(decoded.jti, true);

        const { sid, key, hwid } = decoded;
        const { clientHwid, exeHash } = req.body;

        // 🔥 KIỂM TRA MÃ BĂM PHẦN MỀM TRONG LÚC CHẠY (Chống đổi file khi đang chạy) 🔥
        if (VALID_EXE_HASHES.length > 0 && !VALID_EXE_HASHES.includes(exeHash?.toLowerCase())) {
            return res.status(401).json({ action: "kill", reason: "Phát hiện mã nguồn bị can thiệp!" });
        }

        if (clientHwid !== hwid) return res.status(401).json({ action: "kill", code: "HWID_FORGED", reason: "Sai định danh phần cứng!" });

        const sessionRef = admin.database().ref(`sessions/${sid}`);
        const sessionSnap = await sessionRef.once('value');
        const sessionData = sessionSnap.val();

        if (!sessionData || sessionData.status !== "active") return res.status(401).json({ action: "kill", code: "SESSION_REVOKED", reason: "Session đã bị ngắt!" });

        await sessionRef.update({ lastPing: admin.database.ServerValue.TIMESTAMP });

        const newJti = crypto.randomUUID();
        const newAccessToken = jwt.sign(
            { key: key, hwid: hwid, sid: sid, jti: newJti }, 
            JWT_PRIVATE_KEY, 
            { algorithm: 'RS256', expiresIn: '15m' }
        );

        return res.json({ action: "continue", payload: newAccessToken });
    } catch (error) { return res.status(500).json({ code: "INTERNAL_ERROR" }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`AutoJMS Secure is running`));