# Email Forensics Platform — Email Information Module

This is the first module of the Email Threat Detection & Digital Forensics
Platform. It lets an analyst upload a `.eml` file and view its core header
metadata (From, To, Subject, Date & Time, Reply-To, Return-Path,
Message-ID) in a clean, enterprise-style workspace.

No threat detection, AI analysis, geolocation, or scoring is implemented
yet — this stage is metadata extraction only.

## Project structure

```
email-forensics-platform/
├── backend/          Node.js + Express API that parses .eml files
│   ├── server.js
│   ├── routes/
│   ├── controllers/
│   ├── services/      ← emailParser.js does all the .eml parsing
│   └── middleware/     ← upload.js validates file type/size
└── frontend/         Plain HTML/CSS/JS single-page app (no build step)
    ├── index.html
    ├── css/style.css
    └── js/
```

The backend also serves the frontend, so the whole app runs from one
process during development.

## Running it

1. Install dependencies:

   ```bash
   cd backend
   npm install
   ```

2. (Optional) copy `.env.example` to `.env` and adjust the port or
   upload size limit:

   ```bash
   cp .env.example .env
   ```

3. Start the server:

   ```bash
   npm start
   ```

4. Open your browser to:

   ```
   http://localhost:4000
   ```

5. Upload any `.eml` file and click **Analyze Email**.

## API

```
POST /api/email/analyze
Content-Type: multipart/form-data
Body: file = <your .eml file>
```

Successful response:

```json
{
  "success": true,
  "filename": "invoice.eml",
  "email": {
    "from": "Security Team <security@example.com>",
    "to": ["user@example.com"],
    "subject": "Important Account Notification",
    "dateTime": "11 Sep 2026, 10:42:15 +0530",
    "replyTo": "support@example.com",
    "returnPath": "bounce@example.com",
    "messageId": "<abc123@example.com>"
  }
}
```

Error response (invalid file, wrong type, or file too large):

```json
{
  "success": false,
  "error": "INVALID_EML",
  "message": "The selected file could not be parsed as a valid EML message."
}
```

## Notes on the parsing behavior

- Missing headers (Reply-To, Return-Path, Message-ID) are returned as
  `null` and shown in the UI as "Not specified" — they are never
  treated as errors.
- The Date & Time field preserves the sender's original UTC offset
  (e.g. `+0530`) instead of silently converting it to the server's
  local time.
- Display names in address headers (e.g. `Security Team
  <security@example.com>`) are preserved.
- Uploaded files are validated by extension and size before parsing,
  stored only temporarily on disk, and deleted immediately after
  processing. No attachments, scripts, or embedded content are ever
  executed.

## What's next

Future stages will add to the same tab structure already in place
(Headers, Authentication, Routing, Indicators, Intelligence, Report)
without needing to rebuild this foundation.
