# AutoJMS API

Node.js API for AutoJMS license verification and heartbeat.

## Render Environment Variables

Required:

- `FIREBASE_SERVICE_ACCOUNT_BASE64`
- `FIREBASE_DATABASE_URL`
- `JWT_PRIVATE_KEY`
- `JWT_PUBLIC_KEY`

Optional/current:

- `SUPABASE_BASE_URL`
- `DEFAULT_UPDATE_CHANNEL`
- `VALID_EXE_HASHES`

Generate `FIREBASE_SERVICE_ACCOUNT_BASE64` on PowerShell:

```powershell
$json = Get-Content .\serviceAccountKey.json -Raw
$bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
[Convert]::ToBase64String($bytes)
```

Do not commit `serviceAccountKey.json`, `service_account.json`, or any Firebase Admin SDK key file.
