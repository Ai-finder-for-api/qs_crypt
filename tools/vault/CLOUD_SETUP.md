# qsenc cloud layer: setup

The cloud layer is an optional fifth layer. It is **off** in the default build.

## What the cloud service stores

Not keys. The client sends a one-way commitment, `SHA-256("QSV1-cloud-commit" || ckey)`, and the
service stores only that. It can answer "is this commitment registered, and is it revoked?" but
cannot recover a key or decrypt anything. Storing the raw `.qs.ckey` material in the database
would make the database a single point of decryption, so this build does not do it.

## Endpoints

Under one base URL, `POST` with JSON `{"commitment":"<64 lowercase hex>"}`:

- `/register`: store the commitment. Reply `{"ok":true}`.
- `/validate`: reply `{"ok":true}` only if the commitment is registered and not revoked.

The CLI accepts a reply only if it contains `"ok":true`. Anything else is a rejection.

## Supabase (current setup)

- Table `commitments`: `id`, `created_at`, `commitment` (text, unique, not nullable),
  `revoked` (bool, default false). Row Level Security on, no public policies.
- Edge function `qsv` with JWT verification **off**. It reads the secret key from the
  `QSV_SECRET_KEY` secret. The vault cannot send a user JWT, so the function checks commitments
  itself.
- Revoke a key: set `revoked = true` on its row. Every file that uses that key then fails
  validation.

## Turning the cloud layer on

1. Make sure `curl` works in a terminal (Windows 10 and later include it).
2. Build the cloud-enabled CLI:

   ```
   build_vault.bat cloud
   ```

   This builds `build\qsenc.exe` with the cloud layer on, and skips the offline unit tests.
3. Set the endpoint and use the tool as normal:

   ```
   set "QSV_CLOUD_URL=https://<project>.supabase.co/functions/v1/qsv"
   qsenc encrypt notes.txt notes.qsv --ckey home.qs.ckey --usb E:\usb.qs.ckey
   ```

   `encrypt` registers each key's commitment. `decrypt` validates it before it does any password
   work. If the URL is missing or the server can't be reached, the command fails and says so.

4. To go back to the default (cloud off), run `build_vault.bat` with no argument.

Files written with the cloud flag cannot be opened by a build that has the cloud layer off. That
is intentional: the file requires validation, and the build refuses to skip it.

## Security notes

- The URL must start with `https://` and contain no spaces or shell metacharacters. The tool
  refuses anything else.
- Only the commitment leaves the machine. The `.qs.ckey` file and its secret never do.
- Keep `QSV_SECRET_KEY` (the service key) out of the vault, the repo, and any client. Only the
  edge function may read it.
