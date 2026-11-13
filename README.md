# EDC Fit Check

An invite-only outfit board. The organizer can set a submission deadline in Singapore time. Friends can add ideas with optional inspiration photos.

The Vercel project runs the board in a Node.js function and uses a connected private Vercel Blob store. Vercel provides the store credentials to the function. The store holds the board and its photos, and the function checks the invite before serving them.

Run `npm ci` and `npm run build` to check the application before deployment.

Set `EDC_ADMIN_SESSION_SALT` and `EDC_ADMIN_VERIFY` in the server environment to enable Admin sign-in. Generate a random salt and compute the verifier as SHA-256 of `edc-admin-verify:<session>`, where the session is the hexadecimal SHA-256 of `edc-admin-session:<salt>:<password>`. Legacy invite links use the optional `EDC_INVITE_HASH` and `EDC_SHORT_INVITE_HASH` settings, each holding the hexadecimal SHA-256 of the corresponding invite code.
