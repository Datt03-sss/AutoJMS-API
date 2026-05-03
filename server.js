const express = require('express');
const admin = require('firebase-admin');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Đọc file Secret của Firebase (Render sẽ tự động tiêm file này vào hệ thống)
const serviceAccount = require('./serviceAccountKey.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://<TEN-PROJECT-CUA-BAN>.firebaseio.com" // QUAN TRỌNG: Sửa lại link này theo Firebase của bạn
});

const app = express();
app.use(express.json());

// Đọc các khóa bảo mật từ Biến môi trường của Render
const API_SIGNATURE_SECRET = process.env.API_SIGNATURE_SECRET;
// Xử lý lỗi xuống dòng khi copy RSA Key vào Biến môi trường
const JWT_PRIVATE_KEY = process.env.JWT_PRIVATE_KEY ? process.env.JWT_PRIVATE_KEY.replace(/\\n/g, '\n') : '';

// Middleware: Chống Spam & Kiểm tra chữ ký bảo mật
function verifyClientSignature(req, res, next) {
    const clientSign = req.headers['x-request-sign'];
    const timestamp = req.headers['x-timestamp'];

    if (!clientSign || !timestamp) {
        return res.status(403).json({ error: "Missing signature" });
    }

    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - parseInt(timestamp)) > 120) {
        return res.status(403).json({ error: "Request expired" });
    }

    const payloadString = JSON.stringify(req.body) + timestamp;
    const serverSign = crypto.createHmac('sha256', API_SIGNATURE_SECRET)
                             .update(payloadString)
                             .digest('hex');

    if (clientSign !== serverSign) {
        return res.status(403).json({ error: "Invalid signature" });
    }
    next();
}

// Endpoint Xác thực Bản quyền
app.post('/api/verify-license', verifyClientSignature, async (req, res) => {
    try {
        const { licenseKey, hwid } = req.body;

        const ref = admin.database().ref(`licenses/${licenseKey}`);
        const snapshot = await ref.once('value');
        const licenseData = snapshot.val();

        if (!licenseData || licenseData.isActive === false) {
            return res.status(401).json({ error: "Invalid Key" });
        }

        if (new Date(licenseData.expireDate) < new Date()) {
            return res.status(401).json({ error: "Expired" });
        }

        if (licenseData.hwid && licenseData.hwid !== hwid) {
            return res.status(401).json({ error: "HWID Mismatch" });
        }

        if (!licenseData.hwid) {
            await ref.update({ hwid: hwid });
        }

        const token = jwt.sign(
            { key: licenseKey, hwid: hwid, rnd: crypto.randomBytes(4).toString('hex') }, 
            JWT_PRIVATE_KEY, 
            { algorithm: 'RS256', expiresIn: '12h' }
        );

        const checksum = crypto.createHash('sha256').update(token + hwid).digest('hex');

        return res.json({
            payload: token,
            chk: checksum,
            cfg: licenseData.appConfig
        });

    } catch (error) {
        console.error(error);
        return res.status(500).json({ error: "Internal Server Error" });
    }
});

// Port mặc định của Render
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`AutoJMS Secure Gateway is running on port ${PORT}`));