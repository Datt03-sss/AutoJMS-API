# AutoJMS API

Node.js API for AutoJMS license verification and heartbeat.

## Render Environment Variables

Required:

- `FIREBASE_SERVICE_ACCOUNT_FILE` (Render Secret File path, for example `/etc/secrets/serviceAccountKey.json`)
- `FIREBASE_DATABASE_URL`
- `JWT_PRIVATE_KEY`
- `JWT_PUBLIC_KEY`
- `SUPABASE_ANON_KEY`

Optional/current:

- `FIREBASE_OPERATION_TIMEOUT_MS` (recommended: `8000`)
- `SUPABASE_PROJECT_URL` (default: `https://bnsnnrlwfzxemmizknwy.supabase.co`)
- `SUPABASE_BASE_URL`
- `DEFAULT_UPDATE_CHANNEL`
- `VALID_EXE_HASHES`

Current Supabase storage base:

```text
https://bnsnnrlwfzxemmizknwy.supabase.co/storage/v1/object/public/autojms-modules
```

Create a Render Secret File named `serviceAccountKey.json` with the Firebase Admin SDK JSON.
Set the environment variable:

```env
FIREBASE_SERVICE_ACCOUNT_FILE=/etc/secrets/serviceAccountKey.json
FIREBASE_DATABASE_URL=https://keyauthjms-default-rtdb.asia-southeast1.firebasedatabase.app/
FIREBASE_OPERATION_TIMEOUT_MS=8000
```

Do not commit `serviceAccountKey.json`, `service_account.json`, or any Firebase Admin SDK key file.

## Checks

```powershell
npm run check
Invoke-RestMethod "https://autojms-api.onrender.com/health"
Invoke-RestMethod "https://autojms-api.onrender.com/health/firebase"
Invoke-RestMethod "https://autojms-api.onrender.com/health/firebase/licenses"
```

Fake license should return `404` JSON with `error: "LICENSE_NOT_FOUND"` quickly, not timeout.
