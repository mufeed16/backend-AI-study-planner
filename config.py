import os
from datetime import timedelta

# MongoDB Configuration
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/chatbot_db")

# JWT Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", os.urandom(24).hex())
JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)

# Qdrant Configuration
QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
QDRANT_COLLECTION = "study_materials"

# File Uploads
UPLOADS_DEFAULT_DEST = os.getenv("UPLOADS_DIR", "./uploads")
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB

# AI Model
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

# Admin Configuration
ADMIN_KEY = os.getenv("ADMIN_KEY", "adminkey") # You can change this to a more secure key

# Data Directory
DATA_DIR = os.getenv("DATA_DIR", "uploads/")
