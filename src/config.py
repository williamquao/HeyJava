import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # File upload settings
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'uploads')
    OUTPUT_FOLDER = os.getenv('OUTPUT_FOLDER', 'decompiled')
    MAX_FILE_SIZE = int(os.getenv('MAX_FILE_SIZE', 100 * 1024 * 1024))  # 100MB default
    ALLOWED_EXTENSIONS = {'apk'}
    
    # Flask settings
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here')
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    FLASK_DEBUG = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
    
    # Tool paths (will be set during installation)
    APKTOOL_PATH = os.getenv('APKTOOL_PATH', 'apktool')
    JADX_PATH = os.getenv('JADX_PATH', 'jadx')
    DEX2JAR_PATH = os.getenv('DEX2JAR_PATH', 'd2j-dex2jar.sh')
    
    # Processing settings
    MAX_CONCURRENT_JOBS = int(os.getenv('MAX_CONCURRENT_JOBS', 3))
    JOB_TIMEOUT = int(os.getenv('JOB_TIMEOUT', 300))  # 5 minutes 