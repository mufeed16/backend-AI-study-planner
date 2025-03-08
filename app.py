from flask import Flask, request, jsonify, send_from_directory
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from flask_uploads import UploadSet, configure_uploads, ALL
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from flask_cors import CORS
import fitz  # PyMuPDF
from datetime import timedelta, datetime
import os
import json
import magic
from model import final_result
from datacreate import create_vector_db  # Import the function

from dotenv import load_dotenv
import logging
import sys

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config.from_pyfile('config.py')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB max file size
CORS(app, origins=["http://localhost:3000"])  # Allow requests from frontend

# Allowed file types
ALLOWED_EXTENSIONS = {'pdf'}
ALLOWED_MIMETYPES = {'application/pdf'}

# Configure file uploads
uploads = UploadSet('uploads', ALL)
configure_uploads(app, uploads)

# Initialize MongoDB
try:
    mongo = PyMongo(app)
    # Test the connection
    mongo.db.command('ping')
    logger.info("MongoDB connection successful")
except Exception as e:
    logger.error(f"MongoDB connection failed: {str(e)}")
    sys.exit(1)

jwt = JWTManager(app)

# Error handlers
@app.errorhandler(500)
def handle_500_error(e):
    return jsonify(error="Internal server error"), 500

@app.errorhandler(404)
def handle_404_error(e):
    return jsonify(error="Resource not found"), 404
# a_key = ADMIN_KEY(app)

# Ensure upload directory exists
if not os.path.exists(app.config['UPLOADS_DEFAULT_DEST']):
    os.makedirs(app.config['UPLOADS_DEFAULT_DEST'])


@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')
    role = request.json.get('role', 'user')  # Default to user if not specified
    
    # Check if username already exists
    if mongo.db.users.find_one({'username': username}):
        return jsonify(message="Username already exists"), 400

    hashed_password = generate_password_hash(password)
    mongo.db.users.insert_one({
        'username': username, 
        'password': hashed_password,
        'role': role
    })
    return jsonify(message="User registered successfully"), 201

@app.route('/admin/register', methods=['POST'])
def admin_register():
    username = request.json.get('username')
    password = request.json.get('password')
    admin_key = request.json.get('admin_key')
    
    # Verify admin key (you should change this to a secure key)
    if admin_key != "adminkey":
        return jsonify(message="Invalid admin key"), 403
    
    # Check if username already exists
    if mongo.db.users.find_one({'username': username}):
        return jsonify(message="Username already exists"), 400

    hashed_password = generate_password_hash(password)
    mongo.db.users.insert_one({
        'username': username, 
        'password': hashed_password,
        'role': 'admin'
    })
    return jsonify(message="Admin registered successfully"), 201

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    user = mongo.db.users.find_one({'username': username})

    if user and check_password_hash(user['password'], password):
        access_token = create_access_token(identity={
            'username': username,
            'role': user['role']
        })
        return jsonify(access_token=access_token, role=user['role']), 200
    return jsonify(message="Invalid credentials"), 401

@app.route('/documents', methods=['GET'])
@jwt_required()
def get_documents():
    try:
        documents = list(mongo.db.documents.find({}, {'_id': False}))
        return jsonify(documents)
    except Exception as e:
        return jsonify({'message': str(e)}), 500

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_file_type(file_stream):
    # Read the first 2048 bytes to determine file type
    file_head = file_stream.read(2048)
    # Return pointer to start of file
    file_stream.seek(0)
    mime_type = magic.from_buffer(file_head, mime=True)
    logger.info(f"Detected MIME type: {mime_type}")  # Log detected MIME type
    is_valid_mime_type = mime_type in ALLOWED_MIMETYPES
    logger.info(f"Is valid MIME type: {is_valid_mime_type}") # Log if valid
    return is_valid_mime_type

@app.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify(message="No file uploaded"), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify(message="No selected file"), 400
            
        logger.info("Checking allowed_file...")
        if not allowed_file(file.filename):
            logger.info("allowed_file check failed.")
            return jsonify(message="Invalid file type. Only PDF files are allowed."), 400

        logger.info("Checking validate_file_type...")
        if not validate_file_type(file):
            logger.info("validate_file_type check failed.")
            return jsonify(message="Invalid file content. File must be a valid PDF."), 400

        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOADS_DEFAULT_DEST'], filename)

        logger.info("Checking if file exists...")
        if os.path.exists(file_path):
            logger.info("File exists check failed.")
            return jsonify(message="A file with this name already exists"), 409

        # Save file
        file.save(file_path)

        logger.info("Verifying PDF readability with PyMuPDF...")
        # Verify file is readable as PDF
        try:
            with fitz.open(file_path) as pdf:
                # Just checking if it can be opened as PDF
                pass
        except Exception as pdf_error:  # Capture specific exception
            os.remove(file_path)  # Clean up invalid file
            logger.error(f"PDF validation error: {pdf_error}") # Log PDF validation error
            logger.info("PyMuPDF check failed.")
            return jsonify(message="The file is not a valid PDF document"), 400
        
        # Store document info in MongoDB
        mongo.db.documents.insert_one({
            'filename': filename,
            'uploadDate': datetime.now().isoformat(),
            'uploader': get_jwt_identity()['username'],
            'fileSize': os.path.getsize(file_path)
        })

        # Recreate vector database
        create_vector_db()
        
        return jsonify(message="File uploaded successfully"), 201
            
    except RequestEntityTooLarge:
        return jsonify(message="File is too large. Maximum size is 10MB"), 413
    except Exception as e:
        logger.error(f"Upload error: {str(e)}", exc_info=True) # Log full exception info
        return jsonify(message="An error occurred while uploading the file"), 500

@app.route('/chat-history', methods=['GET'])
@jwt_required()
def get_chat_history():
    try:
        user_identity = get_jwt_identity()
        if user_identity['role'] == 'admin':
            # Admins can see all chat history
            chat_history = list(mongo.db.chat_history.find({}, {'_id': 0}).sort('timestamp', -1))
        else:
            # Users can only see their own chat history
            chat_history = list(mongo.db.chat_history.find(
                {'user': user_identity['username']},
                {'_id': 0}
            ).sort('timestamp', -1))
        
        return jsonify(chat_history), 200
    except Exception as e:
        logger.error(f"Error fetching chat history: {str(e)}")
        return jsonify(message="Error fetching chat history"), 500

@app.route('/query', methods=['POST'])
@jwt_required()
def query():
    try:
        user_query = request.json.get('query')
        if not user_query:
            return jsonify(message="No query provided"), 400

        response = final_result(user_query)
        
        # Store chat history
        mongo.db.chat_history.insert_one({
            'user': get_jwt_identity()['username'],
            'query': user_query,
            'response': response.get('result', 'No result found'),
            'timestamp': datetime.now().isoformat(),
            'sources': [str(doc) for doc in response.get('source_documents', [])]
        })

        # Return response in format expected by frontend
        return jsonify({
            'results': [{
                'text': response.get('result', 'No result found'),
                'sources': [str(doc) for doc in response.get('source_documents', [])]
            }]
        }), 200
    except Exception as e:
        return jsonify(message=str(e)), 500

def extract_text_from_pdf(filename):
    text = ""
    with fitz.open(filename) as doc:
        for page in doc:
            text += page.get_text()
    return text

if __name__ == '__main__':
    app.run(debug=True)
