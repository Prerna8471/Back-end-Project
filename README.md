# File Sharing System

Secure file-sharing system for Ops and Client users, built with Flask and MongoDB.

## Setup
1. Install Python 3.9+ and MongoDB.
2. Run `pip install -r requirements.txt`.
3. Start the app: `python app.py`.
4. Import `postman_collection.json` into Postman for testing.

## APIs
- Ops: `/login`, `/upload`
- Client: `/signup`, `/verify/<token>`, `/login`, `/download-file/<file_id>`, `/files`

## Notes
- Uses JWT for authentication and Fernet for encrypted URLs.
- Files stored locally in `uploads/` (use S3 in production).
- Postman collection included as `postman_collection.json`.
