from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import subprocess
import threading
import tempfile
import shutil
from werkzeug.utils import secure_filename
import jwt
import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# Configuration from environment variables
UPLOAD_FOLDER = '/tmp/uploads'
RESULTS_FOLDER = '/tmp/results'
JWT_SECRET = os.getenv('JWT_SECRET', 'fallback-secret-key')
STATIC_AUTH_TOKEN = os.getenv('STATIC_AUTH_TOKEN', 'fallback-token')
JWT_EXPIRATION_HOURS = int(os.getenv('JWT_EXPIRATION_HOURS', '24'))
MAX_CONTENT_LENGTH = int(os.getenv('MAX_CONTENT_LENGTH', '524288000'))  # 500MB default

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULTS_FOLDER, exist_ok=True)

def verify_jwt(token):
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def require_auth(f):
    """Decorator to require JWT authentication"""
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid token'}), 401
        
        token = auth_header.split(' ')[1]
        payload = verify_jwt(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

def decompile_with_ghidra(file_path, output_dir):
    """Decompile binary using Ghidra CLI"""
    try:
        # Get the script directory (where Decompile.java is located)
        script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Ghidra headless command with -scriptPath to specify where Decompile.java is
        cmd = [
            '/ghidra_11.4.2_PUBLIC/support/analyzeHeadless',
            output_dir,
            'TempProject',
            '-import', file_path,
            '-scriptPath', script_dir,
            '-postScript', 'Decompile.java',
            output_dir,
            '-deleteProject'
        ]
        
        print(f"Running Ghidra command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        print(f"Ghidra stdout: {result.stdout}")
        print(f"Ghidra stderr: {result.stderr}")
        print(f"Ghidra return code: {result.returncode}")
        
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return None, "Decompilation timed out", 1
    except Exception as e:
        return None, str(e), 1

@app.route('/api/login', methods=['POST'])
def login():
    """Login endpoint that generates JWT token"""
    data = request.get_json()
    if not data or 'token' not in data:
        return jsonify({'error': 'Token required'}), 400
    
    # Check against static token from environment
    if data['token'] == STATIC_AUTH_TOKEN:
        payload = {
            'user': 'authenticated_user',
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=JWT_EXPIRATION_HOURS)
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
        return jsonify({'token': token})
    
    return jsonify({'error': 'Invalid token'}), 401

@app.route('/api/decompile', methods=['POST'])
@require_auth
def decompile():

    if 'files' not in request.files:
        return jsonify({'error': 'No files provided'}), 400

    files = request.files.getlist('files')
    if not files or files[0].filename == '':
        return jsonify({'error': 'No files selected'}), 400

    results = []
    temp_dir = tempfile.mkdtemp()

    try:
        for file in files:
            if file:  # Removed extension check
                filename = secure_filename(file.filename)
                file_path = os.path.join(temp_dir, filename)
                file.save(file_path)

                # Create output directory for this file
                output_dir = os.path.join(RESULTS_FOLDER, os.path.splitext(filename)[0])
                os.makedirs(output_dir, exist_ok=True)

                # Decompile in background thread
                def process_file():
                    stdout, stderr, returncode = decompile_with_ghidra(file_path, output_dir)
                    
                    # Look for the decompiled file
                    base_name = os.path.splitext(filename)[0]
                    possible_files = [
                        os.path.join(output_dir, f"{base_name}_decompiled.c"),
                        os.path.join(output_dir, f"{base_name}.c"),
                    ]
                    
                    # Also check all .c files in output directory
                    try:
                        for file in os.listdir(output_dir):
                            if file.endswith('.c'):
                                possible_files.append(os.path.join(output_dir, file))
                    except Exception:
                        pass
                    
                    decompiled_code = None
                    decompiled_file = None
                    
                    for possible_file in possible_files:
                        if os.path.exists(possible_file):
                            decompiled_file = possible_file
                            with open(possible_file, 'r', encoding='utf-8', errors='ignore') as f:
                                decompiled_code = f.read()
                            break
                    
                    if decompiled_code and len(decompiled_code.strip()) > 0:
                        results.append({
                            'filename': filename,
                            'status': 'success',
                            'decompiled_code': decompiled_code
                        })
                    else:
                        error_msg = f"Decompiled file not found. Searched in: {output_dir}\n"
                        error_msg += f"Files in directory: {os.listdir(output_dir) if os.path.exists(output_dir) else 'Directory does not exist'}\n"
                        error_msg += f"Ghidra output:\n{stdout}\n{stderr}"
                        results.append({
                            'filename': filename,
                            'status': 'error',
                            'error': error_msg
                        })

                thread = threading.Thread(target=process_file)
                thread.start()
                thread.join()  # Wait for completion

        # Clean up uploaded files
        shutil.rmtree(temp_dir)

        return jsonify({'results': results})

    except Exception as e:
        shutil.rmtree(temp_dir)
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)