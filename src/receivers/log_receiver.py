"""
SSH Log Receiver
Receives SSH logs from remote agents via HTTP POST
Saves to temporary streaming files
"""
from flask import Flask, request, jsonify
import os
from datetime import datetime

app = Flask(__name__)

# Configuration
RECEIVING_DIR = "data/receiving_stream"
os.makedirs(RECEIVING_DIR, exist_ok=True)

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "service": "ssh_log_receiver"}), 200

@app.route('/logs/upload', methods=['POST'])
def receive_logs():
    """
    Receive SSH logs from agents
    Expected JSON: {
        "server_name": "hostname",
        "logs": ["log line 1", "log line 2", ...]
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'server_name' not in data or 'logs' not in data:
            return jsonify({"error": "Missing server_name or logs"}), 400
        
        server_name = data['server_name']
        logs = data['logs']
        
        # Validate
        if not isinstance(logs, list):
            return jsonify({"error": "logs must be an array"}), 400
        
        # Save to streaming file
        log_file = f"{RECEIVING_DIR}/authlog_{server_name}.log"
        
        with open(log_file, 'a') as f:
            for log_line in logs:
                f.write(log_line + '\n')
        
        return jsonify({
            "status": "success",
            "server_name": server_name,
            "logs_received": len(logs),
            "timestamp": datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/logs/status', methods=['GET'])
def get_status():
    """Get status of all receiving streams"""
    files = {}
    for filename in os.listdir(RECEIVING_DIR):
        if filename.startswith('authlog_'):
            filepath = os.path.join(RECEIVING_DIR, filename)
            size = os.path.getsize(filepath)
            files[filename] = {
                "size_bytes": size,
                "size_kb": round(size / 1024, 2)
            }
    
    return jsonify({
        "active_streams": len(files),
        "files": files
    }), 200

if __name__ == '__main__':
    print("=" * 70)
    print("🌐 SSH LOG RECEIVER STARTING")
    print("=" * 70)
    print(f"📁 Receiving directory: {RECEIVING_DIR}")
    print(f"🔗 Endpoints:")
    print(f"   - POST /logs/upload")
    print(f"   - GET  /logs/status")
    print(f"   - GET  /health")
    print("=" * 70)
    app.run(host='0.0.0.0', port=5000, debug=True)