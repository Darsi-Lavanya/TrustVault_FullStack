# TrustVault — Full-Stack Secure Document Sharing

TrustVault is a Flask + SQLite web application for document upload, document-level access control, and audit logging. It is a learning/demo project; it is not a substitute for a security review before handling real company documents.

## Features

- Authentication with password hashing and server-side session identity.
- Three roles: **Administrator**, **Document Owner**, and **Viewer**.
- Upload, search, view metadata, download, edit metadata, and delete documents.
- Per-document permissions for named users: `read` or `edit`.
- Owners can grant, change, and revoke access.
- Search by filename/description, owner username, category, and upload date.
- Allowlist file extensions and enforce a 10 MB upload limit.
- Admin dashboard for role management and recent audit events.
- Access checks are enforced server-side on document detail, download, edit, delete, and permission routes.
- Automated tests for cross-user access and permissions.

## Tech stack

- Frontend: HTML, CSS, Jinja templates
- Backend: Python, Flask
- Database: SQLite
- Authentication: Werkzeug password hashing and Flask sessions
- Tests: Python `unittest`

## Folder structure

```text
TrustVault_FullStack/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── private_uploads/
│   └── .gitkeep
├── static/
│   └── style.css
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── documents.html
│   ├── upload.html
│   ├── document_detail.html
│   ├── admin.html
│   └── error.html
└── tests/
    └── test_access_control.py
```

## Run on Windows / VS Code

1. Install Python 3.10+.
2. Open this folder in VS Code.
3. Open Terminal and run:

```bash
python -m venv venv
venv\\Scripts\\activate
pip install -r requirements.txt
python app.py
```

4. Visit `http://127.0.0.1:5000`.
5. Initial administrator credentials (development only):
   - Username: `admin`
   - Password: `ChangeMe!123`
6. **Immediately change the demo password strategy before real use.** The initial admin credentials can be configured before the first run with environment variables:

```bat
set TRUSTVAULT_ADMIN_USER=myadmin
set TRUSTVAULT_ADMIN_PASSWORD=use-a-long-unique-password
set TRUSTVAULT_SECRET_KEY=replace-with-a-long-random-secret
python app.py
```

The database and first admin are initialized on first start. If you already created `trustvault.db`, changing the initial-admin environment variables will not reset an existing account. Use a new/empty database for a clean setup.

## User workflow

1. Register a user account; new accounts default to `viewer`.
2. Sign in as admin and open **Admin**.
3. Change a user's role to `owner` so they can upload and own documents.
4. Sign in as that owner and upload a document.
5. Open the document and grant `read` or `edit` access to another registered username.
6. Sign in as the recipient to view/download the document.
7. The owner can revoke access from the same page.
8. The administrator can review activity and permission-change records in the Admin view.

## Role and permission matrix

| Action | Administrator | Owner | Viewer / shared user |
|---|---|---|---|
| Manage user roles | Yes | No | No |
| Upload documents | Yes | Yes | No |
| View own documents | Yes, only if owner/granted | Yes | If granted |
| Download a document | Only if owner/granted | If owner/granted | If read/edit access granted |
| Edit metadata | Only if owner/granted edit access | Owner or edit grant | Only with edit grant |
| Delete document | No global bypass | Owner only | No |
| Grant/revoke access | No global bypass | Owner only | No |
| View audit dashboard | Yes | No | No |

**Security choice:** administrator status does not automatically grant access to every document. This follows least privilege.

## Run tests

```bash
python -m unittest discover -s tests -v
```

The tests use a temporary database and storage folder. They verify that unshared users cannot view or download documents, non-owners cannot delete, and read-only access does not permit edits.

## Important security notes / limitations

This is a student project baseline, not production-ready secure storage.

- File extension checks are not malware scanning and do not verify file contents/MIME types. Add content inspection, antivirus scanning, and safe file preview handling for production.
- Add CSRF protection (e.g. Flask-WTF), rate limiting, account recovery policy, password reset, MFA, and login throttling before deployment.
- Use HTTPS, a strong persistent `TRUSTVAULT_SECRET_KEY`, secure cookies, secret management, backups, and a production WSGI server. Never use Flask debug mode in production.
- Audit records are stored in SQLite and are not tamper-proof. For stronger evidence, send logs to an append-only remote log service and add integrity protection and retention policies.
- Current audit logs retain event history, but deleting a document leaves the document ID in historical audit entries rather than a full immutable document snapshot.
- The upload directory is intentionally outside `static/`; files are returned only by a route that checks permissions.
- The demo uses SQLite. For multiple concurrent users and enterprise deployment, use a managed database and private object storage with access policies.
- Do not commit real confidential documents, database files, `.env` files, or production secrets to GitHub.

## Suggested next improvements

CSRF protection, MFA, immutable audit log hashing, document version history, expiring grants, bulk admin reporting, malware scanning, email invitations, and PostgreSQL/object-storage support.
