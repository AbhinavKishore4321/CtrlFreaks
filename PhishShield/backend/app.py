from flask import Flask, request, jsonify
from flask_cors import CORS
from scanner import URLScanner
from blacklist import BlacklistDB
import time

app = Flask(__name__)
CORS(app)

scanner = URLScanner()
blacklist = BlacklistDB()

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
    blacklist.add(data['url'])
    return jsonify({"message": "Added to blacklist", "url": data['url']})

@app.route('/blacklist/list', methods=['GET'])
def list_blacklist():
    return jsonify({"blacklist": blacklist.get_all(), "count": len(blacklist.get_all())})

@app.route('/stats', methods=['GET'])
def stats():
    return jsonify(scanner.get_stats())

if __name__ == '__main__':
    print("🛡️  PhishShield API starting on http://localhost:5000")
    app.run(debug=True, port=5000)
