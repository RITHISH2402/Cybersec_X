import os
import ssl
import socket
import base64
import requests
import traceback
from datetime import datetime
from io import BytesIO
from PIL import Image
from flask import Flask, request, jsonify, render_template, send_from_directory

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload

# ─────────────────────────────────────────────
#  Steganography helpers (from steg.py)
# ─────────────────────────────────────────────
END_MARKER = "####END####"

def text_to_binary(text):
    return ''.join(format(ord(c), '08b') for c in text)

def binary_to_text(binary):
    chars = []
    for i in range(0, len(binary), 8):
        byte = binary[i:i + 8]
        if len(byte) == 8:
            chars.append(chr(int(byte, 2)))
    return ''.join(chars)

def encode_image(img, message):
    img = img.convert("RGB")
    pixels = img.load()
    full_message = message + END_MARKER
    binary_message = text_to_binary(full_message)
    max_capacity = img.width * img.height * 3

    if len(binary_message) > max_capacity:
        return None, "Message too large for this image."

    index = 0
    for y in range(img.height):
        for x in range(img.width):
            r, g, b = pixels[x, y]
            if index < len(binary_message):
                r = (r & ~1) | int(binary_message[index]); index += 1
            if index < len(binary_message):
                g = (g & ~1) | int(binary_message[index]); index += 1
            if index < len(binary_message):
                b = (b & ~1) | int(binary_message[index]); index += 1
            pixels[x, y] = (r, g, b)
            if index >= len(binary_message):
                break
        if index >= len(binary_message):
            break

    out = BytesIO()
    img.save(out, format='PNG')
    out.seek(0)
    return out, None

def decode_image(img):
    img = img.convert("RGB")
    pixels = img.load()
    binary_data = ""
    for y in range(img.height):
        for x in range(img.width):
            r, g, b = pixels[x, y]
            binary_data += str(r & 1)
            binary_data += str(g & 1)
            binary_data += str(b & 1)
    text = binary_to_text(binary_data)
    if END_MARKER in text:
        return text.split(END_MARKER)[0], None
    return None, "No hidden message found in this image."

# ─────────────────────────────────────────────
#  Routes
# ─────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

# ── Steganography ──
@app.route('/api/steg/capacity', methods=['POST'])
def steg_capacity():
    try:
        file = request.files.get('image')
        if not file:
            return jsonify({'error': 'No image uploaded'}), 400
        img = Image.open(file.stream)
        bits = img.width * img.height * 3
        chars = bits // 8
        return jsonify({
            'width': img.width,
            'height': img.height,
            'format': img.format or 'Unknown',
            'capacity_chars': chars,
            'capacity_kb': round(chars / 1024, 1)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/steg/encode', methods=['POST'])
def steg_encode():
    try:
        file = request.files.get('image')
        message = request.form.get('message', '')
        if not file:
            return jsonify({'error': 'No image uploaded'}), 400
        if not message:
            return jsonify({'error': 'No message provided'}), 400
        img = Image.open(file.stream)
        out, err = encode_image(img, message)
        if err:
            return jsonify({'error': err}), 400
        b64 = base64.b64encode(out.read()).decode('utf-8')
        return jsonify({'success': True, 'image_b64': b64})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/steg/decode', methods=['POST'])
def steg_decode():
    try:
        file = request.files.get('image')
        if not file:
            return jsonify({'error': 'No image uploaded'}), 400
        img = Image.open(file.stream)
        hidden, err = decode_image(img)
        if err:
            return jsonify({'error': err}), 400
        return jsonify({'success': True, 'message': hidden})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── Web Scanner ──
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
]

@app.route('/api/scan', methods=['POST'])
def web_scan():
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        if not url:
            return jsonify({'error': 'No URL provided'}), 400
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        response = requests.get(url, timeout=10, allow_redirects=True,
                                headers={"User-Agent": "CyberSecDashboard/1.0"})

        headers_result = []
        for h in SECURITY_HEADERS:
            headers_result.append({
                'header': h,
                'present': h in response.headers,
                'value': response.headers.get(h, '')
            })

        # Directory listing
        indicators = ["Index of /", "Directory listing for", "Parent Directory"]
        dir_listing = any(i.lower() in response.text.lower() for i in indicators)

        # Info disclosure
        server = response.headers.get("Server", "")
        powered_by = response.headers.get("X-Powered-By", "")

        missing_count = sum(1 for h in headers_result if not h['present'])
        risk_score = min(100, missing_count * 15 + (20 if dir_listing else 0) +
                         (10 if server else 0) + (10 if powered_by else 0))

        return jsonify({
            'success': True,
            'url': url,
            'status_code': response.status_code,
            'headers': headers_result,
            'directory_listing': dir_listing,
            'server_header': server,
            'powered_by': powered_by,
            'risk_score': risk_score
        })
    except requests.exceptions.ConnectionError:
        return jsonify({'error': 'Could not connect to the target URL.'}), 400
    except requests.exceptions.Timeout:
        return jsonify({'error': 'Request timed out.'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── SSL Checker ──
@app.route('/api/ssl', methods=['POST'])
def ssl_check():
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()
        domain = domain.replace('https://', '').replace('http://', '').split('/')[0]
        if not domain:
            return jsonify({'error': 'No domain provided'}), 400

        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                ssl_version = ssock.version()

                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])
                expiry_str = cert['notAfter']
                expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                remaining = (expiry_date - datetime.utcnow()).days

                san = [item[1] for item in cert.get("subjectAltName", []) if item[0] == "DNS"]

                status = "expired" if remaining < 0 else ("warning" if remaining < 30 else "valid")

                return jsonify({
                    'success': True,
                    'domain': domain,
                    'ssl_version': ssl_version,
                    'common_name': subject.get('commonName', 'N/A'),
                    'issuer': issuer.get('commonName', 'N/A'),
                    'serial': cert.get('serialNumber', 'N/A'),
                    'valid_until': expiry_date.strftime('%Y-%m-%d %H:%M:%S UTC'),
                    'days_remaining': remaining,
                    'status': status,
                    'san': san
                })
    except ssl.SSLError as e:
        return jsonify({'error': f'SSL Error: {e}'}), 400
    except socket.gaierror:
        return jsonify({'error': 'Domain not found. Check the domain name.'}), 400
    except ConnectionRefusedError:
        return jsonify({'error': 'Connection refused. Port 443 may be closed.'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    import socket
    import subprocess
    import threading
    import re

    PORT = 5000

    # ── Detect local network IP ──
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = '127.0.0.1'

    # ── Start localhost.run SSH tunnel in background thread ──
    tunnel_url = [None]

    def start_tunnel():
        try:
            proc = subprocess.Popen(
                ['ssh', '-o', 'StrictHostKeyChecking=no',
                 '-R', f'80:localhost:{PORT}',
                 'nokey@localhost.run'],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            for line in proc.stdout:
                match = re.search(r'https://[a-z0-9\-]+\.lhr\.life', line)
                if match:
                    tunnel_url[0] = match.group(0)
                    print(f"\n  [+] Public URL : {tunnel_url[0]}   << share this!\n")
                    break
        except FileNotFoundError:
            print("\n  [SSH] ssh not found - install OpenSSH or use local network URL only.\n")
        except Exception as e:
            print(f"\n  [tunnel] Error: {e}\n")

    t = threading.Thread(target=start_tunnel, daemon=True)
    t.start()

    print("\n" + "="*60)
    print("  CyberSec Dashboard")
    print("="*60)
    print(f"  Local URL        : http://127.0.0.1:{PORT}")
    print(f"  Network URL      : http://{local_ip}:{PORT}   << same WiFi devices")
    print(f"  Public URL       : (generating via SSH tunnel...)")
    print("="*60)
    print("  Press CTRL+C to stop\n")

    app.run(debug=False, host='0.0.0.0', port=PORT, use_reloader=False)

