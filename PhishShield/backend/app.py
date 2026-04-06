from flask import Flask, request, jsonify
from flask_cors import CORS
from scanner import URLScanner
from blacklist import BlacklistDB
import time
import sqlite3
import os
import urllib.parse

app = Flask(__name__)
CORS(app)

# Initialize the scanner and the JSON-based blacklist
scanner = URLScanner()
blacklist = BlacklistDB()

# Force Python to look in the exact same folder where app.py lives
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'phishshield_blacklist.db')

# ==========================================
# 🗄️ SQLITE HELPER FUNCTION
# ==========================================
def log_to_sqlite_blacklist(url):
    """Logs reported URLs directly into the main SQLite 'blacklist' table."""
    try:
        # Extract the domain to satisfy your 'domain TEXT NOT NULL' constraint
        parsed = urllib.parse.urlparse(url if url.startswith('http') else 'http://' + url)
        domain = parsed.netloc.lower()

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # 1. Insert into the main 'blacklist' table
        # INSERT OR IGNORE safely skips the query if the URL is already in the database
        cursor.execute('''
            INSERT OR IGNORE INTO blacklist (url, domain, source, note) 
            VALUES (?, ?, ?, ?)
        ''', (url, domain, 'user_report', 'Reported via Web UI'))
        
        # 2. Insert into the 'reported_urls' table
        cursor.execute('''
            INSERT OR IGNORE INTO reported_urls (url) VALUES (?)
        ''', (url,))

        conn.commit()
        conn.close()
        
        print(f"✅ SUCCESS: Logged '{url}' to SQLite database.")
        return "Success"
        
    except Exception as e:
        error_msg = str(e)
        print(f"❌ FATAL SQL ERROR: {error_msg}")
        return error_msg

# ==========================================
# 🔌 API ROUTES
# ==========================================

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "service": "PhishShield API"})

@app.route('/scan', methods=['POST'])
def scan_url():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "Missing 'url' field"}), 400

    url = data['url'].strip()
    if not url:
        return jsonify({"error": "URL cannot be empty"}), 400

    start = time.time()
    result = scanner.scan(url, blacklist)
    elapsed = round((time.time() - start) * 1000, 2)

    result['scan_time_ms'] = elapsed
    return jsonify(result)

@app.route('/blacklist/add', methods=['POST'])
def add_to_blacklist():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "Missing 'url' field"}), 400
        
    reported_url = data['url']
    
    # 1. Update the JSON file (This calls your BlacklistDB class)
    blacklist.add(reported_url)
    
    # 2. Update the SQLite database and capture the result
    db_status = log_to_sqlite_blacklist(reported_url)
    
    # 3. Send the exact DB status back to the frontend
    return jsonify({
        "message": "Report processed", 
        "url": reported_url,
        "sqlite_status": db_status
    })

@app.route('/blacklist/list', methods=['GET'])
def list_blacklist():
    return jsonify({"blacklist": blacklist.get_all(), "count": len(blacklist.get_all())})

@app.route('/stats', methods=['GET'])
def stats():
    return jsonify(scanner.get_stats())

if __name__ == '__main__':
    print("🛡️  PhishShield API starting on http://localhost:5000")
    print(f"📂 Connected to SQLite Database at: {DB_PATH}")
    app.run(debug=True, port=5000)
