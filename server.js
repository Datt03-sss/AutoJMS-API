const express = require('express');
const admin = require('firebase-admin');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const NodeCache = require('node-cache');
const helmet = require('helmet');
const cors = require('cors');

// ==========================================
// 🔴 ERROR HANDLER (Chống sập Server)
// ==========================================
process.on("uncaughtException", err => console.error("[FATAL]", err));
process.on("unhandledRejection", err => console.error("[FATAL]", err));

// ==========================================
// 🔴 ENV & CONFIGURATION
// ==========================================
if (!process.env.JWT_PRIVATE_KEY || !process.env.JWT_PUBLIC_KEY) {
    console.error("❌ Missing JWT keys in Environment Variables");
    process.exit(1);
}

// Xóa dấu ngoặc kép thừa (nếu có trên Render) và fix lỗi xuống dòng
const formatKey = (k) => {
    if (!k) return '';
    let key = k.replace(/^"|"$/g, ''); // Cắt sạch ngoặc kép ở 2 đầu
    return key.replace(/\\n/g, '\n');  // Trả lại đúng định dạng xuống dòng
};

const CONFIG = {
    PRIVATE: formatKey(process.env.JWT_PRIVATE_KEY),
    PUBLIC: formatKey(process.env.JWT_PUBLIC_KEY),
    ISSUER: "autojms-license-server",
    AUDIENCE: "autojms-desktop-client",
    // Ưu tiên lấy link từ biến môi trường của Render
    UPDATE_URL: process.env.UPDATE_XML_URL || "https://raw.githubusercontent.com/Datt03-sss/AutoJMS-Update/main/update.xml"
};

// ==========================================
// 🔴 FIREBASE INITIALIZATION
// ==========================================
const serviceAccount = require('./serviceAccountKey.json');

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: "https://keyauthjms-default-rtdb.asia-southeast1.firebasedatabase.app/"
});

const app = express();
app.set('trust proxy', 1);
app.use(helmet());
app.use(cors());
app.use(express.json());

// ==========================================
// RATE LIMIT & CACHE
// ==========================================
const limiter = rateLimit({ windowMs: 60000, max: 20 }); // Cho phép 20 request/phút (Nới lỏng cho Heartbeat)
const jtiCache = new NodeCache({ stdTTL: 900 });         // Lưu JTI trong 15 phút để chống Replay Attack

// ==========================================
// [API 1]: VERIFY LICENSE (ĐĂNG NHẬP)
// ==========================================
app.post('/api/verify-license', limiter, async (req, res) => {
    try {
        const { licenseKey, hwid, exeHash } = req.body; 

        if (!licenseKey || !hwid) {
            return res.status(400).json({ error: "Vui lòng nhập Key. Hệ thống không nhận diện được mã thiết bị." });
        }

        const ref = admin.database().ref(`Licenses/${licenseKey}`);
        const snap = await ref.once('value');
        const data = snap.val();

        if (!data) return res.status(401).json({ error: "Key bản quyền không tồn tại hoặc đã bị xóa." });

        // 1. Kiểm tra khóa thiết bị (HWID Lock)
        if (data.hwid && data.hwid !== hwid)
            return res.status(401).json({ error: "Key này đang được sử dụng trên một máy tính khác." });

        // Ghi nhận HWID nếu đây là lần đầu đăng nhập
        if (!data.hwid) await ref.update({ hwid });

        // 2. CHỐNG KẸT PHIÊN (DỌN RÁC DO CRASH)
        const sessionsRef = admin.database().ref('sessions');
        const sessionsSnap = await sessionsRef.orderByChild('licenseKey').equalTo(licenseKey).once('value');
        const updates = {};
        
        sessionsSnap.forEach(child => {
            const session = child.val();
            // Nếu có phiên cũ mang cùng HWID, tiến hành xóa sạch (gán = null)
            if (session.hwid === hwid) {
                updates[child.key] = null; 
            }
        });
        
        if (Object.keys(updates).length > 0) {
            await sessionsRef.update(updates);
        }

        // 3. Tạo Session mới
        const sessionId = crypto.randomUUID();
        await admin.database().ref(`sessions/${sessionId}`).set({
            licenseKey,
            hwid,
            status: "active",
            lastPing: Date.now()
        });

        // 4. Ký JWT Token với đầy đủ thông tin định danh
        const token = jwt.sign(
            {
                key: licenseKey,
                hwid,
                sid: sessionId,
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

        // 5. Trả dữ liệu về cho C# (Bao gồm Token, SessionID và Config)
        return res.json({ 
            payload: token, 
            sid: sessionId,
            cfg: {
                dataSpreadsheetId: data.dataSpreadsheetId || "",
                updateXmlUrl: data.updateXmlUrl || CONFIG.UPDATE_URL // Ưu tiên link riêng lẻ, nếu không thì lấy mặc định
            }
        });

    } catch (e) {
        console.error("Verify Error:", e);
        res.status(500).json({ error: "Lỗi máy chủ nội bộ. Vui lòng thử lại sau." });
    }
});

// ==========================================
// [API 2]: HEARTBEAT (NHỊP TIM)
// ==========================================
app.post('/api/heartbeat', async (req, res) => {
    try {
        const auth = req.headers.authorization;
        if (!auth || !auth.startsWith("Bearer ")) {
            return res.status(401).json({ action: "kill", reason: "Từ chối truy cập: Không tìm thấy Token." });
        }

        const token = auth.split(" ")[1];

        // 1. Giải mã và xác thực Token
        let decoded;
        try {
            decoded = jwt.verify(token, CONFIG.PUBLIC, {
                algorithms: ["RS256"],
                issuer: CONFIG.ISSUER,
                audience: CONFIG.AUDIENCE
            });
        } catch (err) {
            return res.status(401).json({ action: "kill", reason: "Token đã hết hạn hoặc bị làm giả." });
        }

        // 2. Chống Replay Attack (Một Token chỉ được dùng 1 lần)
        if (jtiCache.has(decoded.jti)) {
            return res.status(401).json({ action: "kill", reason: "Phát hiện nhân bản gói tin mạng (Replay Attack)." });
        }
        jtiCache.set(decoded.jti, true);

        // 3. Kiểm tra tính hợp lệ của Session trên Firebase
        const sessionRef = admin.database().ref(`sessions/${decoded.sid}`);
        const snap = await sessionRef.once('value');

        if (!snap.exists()) {
            return res.status(401).json({ action: "kill", reason: "Phiên làm việc đã bị Admin thu hồi." });
        }

        const sessionData = snap.val();
        if (sessionData.status !== "active") {
            return res.status(401).json({ action: "kill", reason: "Phiên làm việc đã bị khóa." });
        }

        // 4. Cập nhật nhịp tim (Thời gian ping cuối)
        await sessionRef.update({ lastPing: Date.now() });

        // 5. Ký Token mới (Gia hạn vòng đời)
        const newToken = jwt.sign(
            {
                key: decoded.key,
                hwid: decoded.hwid,
                sid: decoded.sid,
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

        // 6. Gửi lệnh Continue và Token mới về cho C#
        return res.json({ action: "continue", payload: newToken });

    } catch (e) {
        console.error("Heartbeat Error:", e);
        res.status(500).json({ action: "kill", reason: "Lỗi nội bộ hệ thống trong quá trình duy trì nhịp tim." });
    }
});

// ==========================================
// START SERVER
// ==========================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("🚀 Server Enterprise chạy trên Port:", PORT));
