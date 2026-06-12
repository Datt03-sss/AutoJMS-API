# AutoJMS API

Node.js API for AutoJMS license verification and heartbeat.

## Render Environment Variables

Required:

- `FIREBASE_SERVICE_ACCOUNT_BASE64`
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

Generate `FIREBASE_SERVICE_ACCOUNT_BASE64` on PowerShell:

```powershell
$json = Get-Content .\serviceAccountKey.json -Raw
$bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
[Convert]::ToBase64String($bytes)
```

Do not commit `serviceAccountKey.json`, `service_account.json`, or any Firebase Admin SDK key file.

## Checks

```powershell
npm run check
Invoke-RestMethod "https://autojms-api.onrender.com/health"
Invoke-RestMethod "https://autojms-api.onrender.com/health/firebase"
```

Fake license should return `404` JSON with `error: "LICENSE_NOT_FOUND"` quickly, not timeout.
