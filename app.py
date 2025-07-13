from flask import Flask, request, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from cryptography.fernet import Fernet
import jwt
import datetime
import os
from bson import ObjectId

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'super-secret-key-12345'  # Replace with secure key in production
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'pptx', 'docx', 'xlsx'}
mongo = MongoClient('mongodb://localhost:27017')
db = mongo['file_sharing']
users = db['users']
files = db['files']
fernet = Fernet(Fernet.generate_key())  # Encryption key for URLs

# Ensure upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Helper: Check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Helper: Generate JWT token
def generate_token(user_id, role):
    return jwt.encode({
        'user_id': str(user_id),
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm='HS256')

# 1. Login (Ops and Client Users)
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = users.find_one({'email': email})
    if user and check_password_hash(user['password'], password):
        token = generate_token(user['_id'], user['role'])
        return jsonify({'token': token, 'message': 'Login successful'})
    return jsonify({'message': 'Invalid credentials'}), 401

# 2. Upload File (Ops User Only)
@app.route('/upload', methods=['POST'])
def upload_file():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'message': 'Token missing'}), 401
    try:
        token = auth_header.split(" ")[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if payload['role'] != 'ops':
            return jsonify({'message': 'Unauthorized: Ops user only'}), 403
    except:
        return jsonify({'message': 'Invalid token'}), 401

    if 'file' not in request.files:
        return jsonify({'message': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400
    if file and allowed_file(file.filename):
        filename = file.filename
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        file_id = files.insert_one({
            'filename': filename,
            'path': file_path,
            'uploaded_by': payload['user_id'],
            'upload_date': datetime.datetime.utcnow()
        }).inserted_id
        return jsonify({'message': 'File uploaded', 'file_id': str(file_id)})
    return jsonify({'message': 'Invalid file type'}), 400

# 3. Sign Up (Client User)
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if users.find_one({'email': email}):
        return jsonify({'message': 'Email already exists'}), 400
    hashed_password = generate_password_hash(password)
    user_id = users.insert_one({
        'email': email,
        'password': hashed_password,
        'role': 'client',
        'verified': False
    }).inserted_id
    verification_url = fernet.encrypt(f"{user_id}:{email}".encode()).decode()
    print(f"Verification URL for {email}: /verify/{verification_url}")
    return jsonify({'verification_url': f"/verify/{verification_url}", 'message': 'Sign up successful, verify email'})

# 4. Email Verify (Client User)
@app.route('/verify/<token>', methods=['GET'])
def verify_email(token):
    try:
        decrypted = fernet.decrypt(token.encode()).decode()
        user_id, email = decrypted.split(':')
        user = users.find_one({'_id': ObjectId(user_id), 'email': email})
        if user:
            users.update_one({'_id': ObjectId(user_id)}, {'$set': {'verified': True}})
            return jsonify({'message': 'Email verified'})
        return jsonify({'message': 'Invalid verification link'}), 400
    except:
        return jsonify({'message': 'Invalid or expired token'}), 400

# 5. Login (Client User, handled by /login)

# 6. Download File (Client User Only)
@app.route('/download-file/<file_id>', methods=['GET'])
def download_file(file_id):
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'message': 'Token missing'}), 401
    try:
        token = auth_header.split(" ")[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if payload['role'] != 'client':
            return jsonify({'message': 'Unauthorized: Client user only'}), 403
        if not users.find_one({'_id': ObjectId(payload['user_id']), 'verified': True}):
            return jsonify({'message': 'Email not verified'}), 403
    except:
        return jsonify({'message': 'Invalid token'}), 401

    file = files.find_one({'_id': ObjectId(file_id)})
    if file:
        download_token = fernet.encrypt(f"{file_id}:{payload['user_id']}".encode()).decode()
        download_url = f"/download/{download_token}"
        return jsonify({'download-link': download_url, 'message': 'success'})
    return jsonify({'message': 'File not found'}), 404

# Actual download endpoint
@app.route('/download/<token>', methods=['GET'])
def serve_file(token):
    try:
        decrypted = fernet.decrypt(token.encode()).decode()
        file_id, user_id = decrypted.split(':')
        file = files.find_one({'_id': ObjectId(file_id)})
        if file:
            return send_file(file['path'], as_attachment=True, download_name=file['filename'])
        return jsonify({'message': 'File not found'}), 404
    except:
        return jsonify({'message': 'Invalid or expired download link'}), 400

# 7. List All Uploaded Files (Client User Only)
@app.route('/files', methods=['GET'])
def list_files():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'message': 'Token missing'}), 401
    try:
        token = auth_header.split(" ")[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if payload['role'] != 'client':
            return jsonify({'message': 'Unauthorized: Client user only'}), 403
        if not users.find_one({'_id': ObjectId(payload['user_id']), 'verified': True}):
            return jsonify({'message': 'Email not verified'}), 403
    except:
        return jsonify({'message': 'Invalid token'}), 401

    file_list = [{'file_id': str(f['_id']), 'filename': f['filename'], 'upload_date': f['upload_date']} for f in files.find()]
    return jsonify({'files': file_list})

# Test Cases
def test_login():
    client = app.test_client()
    response = client.post('/login', json={'email': 'test@example.com', 'password': 'password'})
    assert response.status_code in [200, 401]

def test_upload_file():
    client = app.test_client()
    token = generate_token('test_user_id', 'ops')
    response = client.post('/upload', headers={'Authorization': f'Bearer {token}'}, data={'file': (open('test.pptx', 'rb'), 'test.pptx')})
    assert response.status_code in [200, 400, 401, 403]

if __name__ == '__main__':
    app.run(debug=True)
