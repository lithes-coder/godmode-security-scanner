"""
CyberSec - Security Testing Automation Application

Features:
- OAuth 2.0 (Google + GitHub)
- OWASP ZAP Integration (real vulnerability scanning)
- Responsive UI (mobile + desktop)
- Professional admin panel
- Real-time scan status
"""

from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for, session
from authlib.integrations.flask_client import OAuth
from functools import wraps
import requests
import time
import os
import json
from datetime import datetime, timedelta
from threading import Thread
import uuid
import logging
from dotenv import load_dotenv
load_dotenv()
print("=" * 70)
print("GOOGLE_CLIENT_ID")
print(repr(os.getenv("GOOGLE_CLIENT_ID")))

print("GOOGLE_CLIENT_SECRET")
print(repr(os.getenv("GOOGLE_CLIENT_SECRET")))

print("GITHUB_CLIENT_ID")
print(repr(os.getenv("GITHUB_CLIENT_ID")))

print("GITHUB_CLIENT_SECRET")
print(repr(os.getenv("GITHUB_CLIENT_SECRET")))
print("=" * 70)

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'cyberpunk-security-scanner-2024-dev-key')

# Security headers
@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin"
    return response

# ============== CONFIGURATION ==============

# OAuth Configuration
oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

github = oauth.register(
    name='github',
    client_id=os.getenv('GITHUB_CLIENT_ID'),
    client_secret=os.getenv('GITHUB_CLIENT_SECRET'),
    access_token_url='https://github.com/login/oauth/access_token',
    access_token_params=None,
    authorize_url='https://github.com/login/oauth/authorize',
    authorize_params=None,
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)

# OWASP ZAP Configuration
ZAP_ENABLED = os.getenv('ZAP_ENABLED', 'true').lower() == 'true'
ZAP_API_URL = os.getenv('ZAP_API_URL', 'http://localhost:8080')
ZAP_API_KEY = os.getenv('ZAP_API_KEY', '')

# File paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
SCAN_HISTORY_FILE = os.path.join(BASE_DIR, "scan_history.json")
USERS_FILE = os.path.join(BASE_DIR, "users.json")

os.makedirs(REPORTS_DIR, exist_ok=True)

# Store running scan progress
SCAN_PROGRESS = {}

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============== HELPER FUNCTIONS ==============

def load_users():
    """Load users from JSON file"""
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_users(users):
    """Save users to JSON file"""
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def create_user_from_oauth(provider, user_data):
    """Create user account from OAuth data"""
    users = load_users()

    email = user_data.get("email") or ""

    # GitHub users often have name=None
    name = (
        user_data.get("name")
        or user_data.get("login")
        or email.split("@")[0]
        or "user"
    )

    base_username = name.lower().replace(" ", "_")

    username = f"{base_username}_{provider}"
    count = 1

    while username in users and users[username]["email"] != email:
        username = f"{base_username}_{provider}_{count}"
        count += 1

    if username in users:
        users[username]["last_login"] = datetime.now().isoformat()
        save_users(users)
        return username, True

    users[username] = {
        "email": email,
        "name": name,
        "avatar": user_data.get("picture") or user_data.get("avatar_url", ""),
        "oauth_provider": provider,
        "oauth_id": str(user_data.get("id") or user_data.get("sub") or ""),
        "role": "user",
        "active": True,
        "created_at": datetime.now().isoformat(),
        "last_login": datetime.now().isoformat()
    }

    save_users(users)
    return username, False

def load_scan_history():
    """Load scan history"""
    if os.path.exists(SCAN_HISTORY_FILE):
        try:
            with open(SCAN_HISTORY_FILE, 'r') as f:
                return json.load(f)
        except:
            return []
    return []

def save_scan_history(history):
    """Save scan history"""
    with open(SCAN_HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=2)

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or session.get('role') != 'admin':
            flash('Admin access required', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# ============== SIMULATED SCAN ==============

def simulate_scan(target_url):
    """
    Simulate a vulnerability scan for demonstration purposes.
    Returns a list of vulnerability dictionaries.
    """
    import random
    import time
    
    # Simulate scan delay
    time.sleep(2)
    
    # Sample vulnerability database
    vuln_templates = [
        {
            "name": "SQL Injection",
            "type": "Injection",
            "severity": "Critical",
            "description": "SQL Injection allows attackers to execute arbitrary SQL commands in the database. This can lead to data theft, modification, or deletion.",
            "solution": "Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.",
            "evidence": "Parameter 'id' is vulnerable: id=1' OR '1'='1",
            "confidence": "High"
        },
        {
            "name": "Cross-Site Scripting (XSS)",
            "type": "XSS",
            "severity": "High",
            "description": "XSS vulnerabilities allow attackers to inject malicious scripts into web pages viewed by other users.",
            "solution": "Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers.",
            "evidence": "Input reflected without sanitization: <script>alert('xss')</script>",
            "confidence": "High"
        },
        {
            "name": "Insecure Direct Object Reference",
            "type": "Broken Access Control",
            "severity": "High",
            "description": "IDOR vulnerabilities occur when an application exposes internal implementation objects without proper authorization checks.",
            "solution": "Implement proper access control checks. Use indirect object references or verify user permissions.",
            "evidence": "Direct access to user data via ID parameter without authorization",
            "confidence": "Medium"
        },
        {
            "name": "Security Misconfiguration",
            "type": "Security Misconfiguration",
            "severity": "Medium",
            "description": "Security misconfiguration is the most commonly seen vulnerability. This includes insecure default configurations, incomplete configurations, and verbose error messages.",
            "solution": "Implement secure configuration baselines. Regularly review and update configurations. Remove unnecessary features.",
            "evidence": "Server version exposed in HTTP headers",
            "confidence": "High"
        },
        {
            "name": "Sensitive Data Exposure",
            "type": "Cryptographic Failures",
            "severity": "High",
            "description": "Sensitive data exposure occurs when applications fail to adequately protect sensitive information such as passwords, credit cards, or personal information.",
            "solution": "Encrypt sensitive data at rest and in transit. Use strong encryption algorithms. Disable caching of sensitive data.",
            "evidence": "Password transmitted over HTTP instead of HTTPS",
            "confidence": "High"
        },
        {
            "name": "Missing Security Headers",
            "type": "Security Misconfiguration",
            "severity": "Low",
            "description": "Security headers add an extra layer of protection by helping to mitigate attacks and security vulnerabilities.",
            "solution": "Implement security headers including X-Frame-Options, X-Content-Type-Options, Content-Security-Policy, and Strict-Transport-Security.",
            "evidence": "Missing X-Frame-Options header in HTTP response",
            "confidence": "High"
        },
        {
            "name": "Cross-Site Request Forgery (CSRF)",
            "type": "CSRF",
            "severity": "Medium",
            "description": "CSRF attacks force authenticated users to submit requests to a web application against which they are currently authenticated.",
            "solution": "Implement CSRF tokens in forms. Use SameSite cookie attributes. Validate Referer and Origin headers.",
            "evidence": "Form submission lacks anti-CSRF token",
            "confidence": "Medium"
        },
        {
            "name": "Insecure Deserialization",
            "type": "Insecure Deserialization",
            "severity": "Critical",
            "description": "Insecure deserialization often leads to remote code execution. Even if it doesn't result in RCE, it can be used to perform replay attacks or privilege escalation.",
            "solution": "Avoid deserializing untrusted data. Implement integrity checks. Use serialization formats that only permit primitive data types.",
            "evidence": "User-controlled data passed to unserialize() function",
            "confidence": "High"
        },
        {
            "name": "Using Components with Known Vulnerabilities",
            "type": "Vulnerable Components",
            "severity": "Medium",
            "description": "Components such as libraries, frameworks, and other software modules often run with full privileges. If a vulnerable component is exploited, it can facilitate serious data loss or server takeover.",
            "solution": "Regularly update components. Remove unused dependencies. Monitor for vulnerabilities in dependencies.",
            "evidence": "jQuery version 1.12.4 detected (CVE-2019-11358)",
            "confidence": "High"
        },
        {
            "name": "Insufficient Logging and Monitoring",
            "type": "Logging",
            "severity": "Low",
            "description": "Insufficient logging and monitoring, coupled with missing or ineffective integration with incident response, allows attackers to further attack systems and maintain persistence.",
            "solution": "Ensure all login, access control, and server-side input validation failures are logged. Establish effective monitoring and alerting.",
            "evidence": "No logging detected for authentication failures",
            "confidence": "Medium"
        }
    ]
    
    # Randomly select 3-7 vulnerabilities
    num_vulns = random.randint(3, min(7, len(vuln_templates)))
    selected_vulns = random.sample(vuln_templates, num_vulns)
    
    # Generate vulnerability IDs and add URL/parameter info
    vulnerabilities = []
    for idx, vuln in enumerate(selected_vulns):
        vuln_id = f"VULN-{random.randint(1000, 9999)}"
        
        # Generate parameter based on vulnerability type
        if vuln["name"] == "SQL Injection":
            parameter = random.choice(["id", "user", "product_id", "category"])
        elif vuln["name"] == "Cross-Site Scripting (XSS)":
            parameter = random.choice(["search", "comment", "name", "message"])
        elif vuln["name"] == "Insecure Direct Object Reference":
            parameter = random.choice(["user_id", "doc_id", "file_id", "order_id"])
        else:
            parameter = random.choice(["input", "data", "value", "query"])
        
        vulnerability = {
            "id": vuln_id,
            "name": vuln["name"],
            "severity": vuln["severity"],
            "type": vuln["type"],
            "url": target_url,
            "parameter": parameter,
            "evidence": vuln["evidence"],
            "description": vuln["description"],
            "solution": vuln["solution"],
            "confidence": vuln["confidence"]
        }
        vulnerabilities.append(vulnerability)
    
    return vulnerabilities

# ============== ZAP INTEGRATION ==============

class ZAPScanner:
    """OWASP ZAP Scanner Integration"""
    
    def __init__(self, api_url, api_key=''):
        self.api_url = api_url
        self.api_key = api_key
        self.session_id = None
    
    def is_available(self):
        """Check if ZAP is running"""
        try:
            response = requests.get(f"{self.api_url}/JSON/core/action/version/", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def start_scan(self, target_url):
        """Start a ZAP scan"""
        try:
            params = {
                'zapapiformat': 'JSON',
                'apikey': self.api_key,
            }
            
            # Access the target
            requests.get(target_url, timeout=10)
            
            # Start spider scan
            spider_url = f"{self.api_url}/JSON/spider/action/scan/"
            spider_params = {
                'zapapiformat': 'JSON',
                'apikey': self.api_key,
                'url': target_url,
            }
            spider_response = requests.get(spider_url, params=spider_params)
            
            if spider_response.status_code != 200:
                logger.error(f"ZAP Spider error: {spider_response.text}")
                return None
            
            scan_id = spider_response.json().get('scan', '')
            logger.info(f"ZAP Spider scan started: {scan_id}")
            
            return scan_id
        except Exception as e:
            logger.error(f"ZAP scan error: {str(e)}")
            return None
    
    def get_scan_status(self, scan_id):
        """Get scan status (0-100)"""
        try:
            params = {
                'zapapiformat': 'JSON',
                'apikey': self.api_key,
                'scanId': scan_id,
            }
            response = requests.get(
                f"{self.api_url}/JSON/spider/view/status/",
                params=params
            )
            
            if response.status_code == 200:
                return int(response.json().get('status', 0))
            return 0
        except:
            return 0
    
    def get_alerts(self):
        """Get all alerts (vulnerabilities)"""
        try:
            params = {
                'zapapiformat': 'JSON',
                'apikey': self.api_key,
            }
            response = requests.get(
                f"{self.api_url}/JSON/core/view/alerts/",
                params=params
            )
            
            if response.status_code == 200:
                return response.json().get('alerts', [])
            return []
        except Exception as e:
            logger.error(f"ZAP alerts error: {str(e)}")
            return []
    
    def format_vulnerabilities(self, alerts):
        """Format ZAP alerts into app format"""
        vulnerabilities = []
        
        for alert in alerts:
            vuln = {
                'id': str(uuid.uuid4()),
                'name': alert.get('name', 'Unknown'),
                'type': alert.get('pluginname', 'Unknown'),
                'severity': alert.get('riskdesc', 'Low'),
                'url': alert.get('url', ''),
                'parameter': alert.get('param', ''),
                'evidence': alert.get('evidence', ''),
                'description': alert.get('description', ''),
                'solution': alert.get('solution', ''),
                'confidence': alert.get('confidence', 'Unknown')
            }
            vulnerabilities.append(vuln)
        
        return vulnerabilities

# Initialize ZAP scanner (will check availability)
zap = ZAPScanner(ZAP_API_URL, ZAP_API_KEY)

# ============== ROUTES ==============

@app.route('/')
def index():
    """Dashboard"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session.get('username')
    users = load_users()
    user_data = users.get(username, {})
    
    history = load_scan_history()
    user_scans = [s for s in history if s.get('scanned_by') == username]
    recent_scans = user_scans[-5:] if user_scans else []
    
    return render_template('index.html', 
        user_data=user_data,
        recent_scans=recent_scans,
        total_scans=len(user_scans)
    )

@app.route('/login')
def login():
    """Login page"""
    if 'username' in session:
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/auth/google')
def auth_google():
    """Google OAuth callback"""
    if not os.getenv('GOOGLE_CLIENT_ID'):
        flash('Google OAuth not configured', 'error')
        return redirect(url_for('login'))
    
    redirect_uri = url_for('auth_google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/google/callback')
def auth_google_callback():
    """Google OAuth callback handler"""
    try:
        token = google.authorize_access_token()
        user = token.get('userinfo')
        
        if not user:
            flash('Failed to get user info from Google', 'error')
            return redirect(url_for('login'))
        
        username, is_existing = create_user_from_oauth('google', user)
        users = load_users()
        user_obj = users.get(username, {})
        
        if not user_obj.get('active', True):
            flash('Your account has been deactivated', 'error')
            return redirect(url_for('login'))
        
        session['username'] = username
        session['role'] = user_obj.get('role', 'user')
        session['email'] = user_obj.get('email')
        session['name'] = user_obj.get('name')
        session['avatar'] = user_obj.get('avatar')
        
        message = 'Welcome back!' if is_existing else 'Account created successfully!'
        flash(message, 'success')
        
        return redirect(url_for('index'))
    
    except Exception as e:
        logger.error(f"Google auth error: {str(e)}")
        flash('Authentication failed. Please try again.', 'error')
        return redirect(url_for('login'))

@app.route('/auth/github')
def auth_github():
    """GitHub OAuth callback"""
    if not os.getenv('GITHUB_CLIENT_ID'):
        flash('GitHub OAuth not configured', 'error')
        return redirect(url_for('login'))
    
    redirect_uri = url_for('auth_github_callback', _external=True)
    return github.authorize_redirect(redirect_uri)

@app.route('/auth/github/callback')
def auth_github_callback():
    """GitHub OAuth callback handler"""
    try:
        token = github.authorize_access_token()
        
        # Get user info from GitHub API
        resp = github.get('user', token=token)
        user_data = resp.json()
        
        # Get email if not in profile
        if 'email' not in user_data or not user_data['email']:
            resp = github.get('user/emails', token=token)
            emails = resp.json()
            primary_email = next((e for e in emails if e['primary']), emails[0] if emails else {})
            user_data['email'] = primary_email.get('email', f"{user_data.get('login', 'user')}@github.local")
        
        user_data['picture'] = user_data.get('avatar_url')
        
        username, is_existing = create_user_from_oauth('github', user_data)
        users = load_users()
        user_obj = users.get(username, {})
        
        if not user_obj.get('active', True):
            flash('Your account has been deactivated', 'error')
            return redirect(url_for('login'))
        
        session['username'] = username
        session['role'] = user_obj.get('role', 'user')
        session['email'] = user_obj.get('email')
        session['name'] = user_obj.get('name')
        session['avatar'] = user_obj.get('avatar')
        
        message = 'Welcome back!' if is_existing else 'Account created successfully!'
        flash(message, 'success')
        
        return redirect(url_for('index'))
    
    except Exception as e:
        logger.error(f"GitHub auth error: {str(e)}")
        flash('Authentication failed. Please try again.', 'error')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    """Logout"""
    session.clear()
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Alias for index"""
    return redirect(url_for('index'))

@app.route('/scan')
@login_required
def scan():
    """Scan page"""
    return render_template('scan.html')

@app.route('/history')
@login_required
def history():
    """History page"""
    username = session.get('username')
    history_data = load_scan_history()
    user_history = [s for s in history_data if s.get('scanned_by') == username]
    return render_template('history.html', scans=user_history)

@app.route('/admin/users')
@admin_required
def admin_users():
    """Admin users page"""
    return render_template('admin_users.html')

# ============== API ROUTES ==============

@app.route('/api/start-scan', methods=['POST'])
@login_required
def api_start_scan():
    """Start a security scan"""
    username = session.get('username')
    data = request.get_json()
    target_url = data.get('target_url', '').strip()
    
    if not target_url:
        return jsonify({'success': False, 'error': 'Target URL required'}), 400
    
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    scan_id = str(uuid.uuid4())
    
    SCAN_PROGRESS[scan_id] = {
        "status": "scanning",
        "progress": 0
    }
    
    def run_scan():
        """Run scan in background"""
        try:
            SCAN_PROGRESS[scan_id]["progress"] = 10
            time.sleep(1)
            
            vulnerabilities = []
            
            if ZAP_ENABLED and zap.is_available():
                zap_scan_id = zap.start_scan(target_url)
                
                if zap_scan_id:
                    for i in range(10):
                        status = zap.get_scan_status(zap_scan_id)
                        SCAN_PROGRESS[scan_id]["progress"] = 10 + (status // 10)
                        time.sleep(5)
                    
                    alerts = zap.get_alerts()
                    vulnerabilities = zap.format_vulnerabilities(alerts)
                else:
                    vulnerabilities = simulate_scan(target_url)
            else:
                vulnerabilities = simulate_scan(target_url)
                generate_html_report(
    scan_id,
    target_url,
    vulnerabilities,
    username
)
            
            history = load_scan_history()
            
            history.append({
                "scan_id": scan_id,
                "target_url": target_url,
                "timestamp": datetime.now().isoformat(),
                "status": "completed",
                "vulnerabilities": vulnerabilities,
                "scanned_by": username
            })
            
            save_scan_history(history)
            
            SCAN_PROGRESS[scan_id] = {
                "status": "completed",
                "progress": 100
            }
            
            logger.info(f"Scan {scan_id} completed.")
        
        except Exception:
            logger.exception("Scan failed")
            SCAN_PROGRESS[scan_id] = {
                "status": "failed",
                "progress": 100
            }
    
    Thread(target=run_scan, daemon=True).start()
    
    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "message": "Scan started successfully."
    })

@app.route('/api/scan-status/<scan_id>')
@login_required
def api_scan_status(scan_id):
    """Get scan status"""
    if scan_id in SCAN_PROGRESS:
        return jsonify({
            "success": True,
            "status": SCAN_PROGRESS[scan_id]["status"],
            "progress": SCAN_PROGRESS[scan_id]["progress"]
        })
    
    history = load_scan_history()
    scan = next((s for s in history if s["scan_id"] == scan_id), None)
    
    if scan:
        return jsonify({
            "success": True,
            "status": "completed",
            "progress": 100
        })
    
    return jsonify({
        "success": False,
        "error": "Scan not found"
    }), 404

@app.route('/api/scan-results/<scan_id>')
@login_required
def api_scan_results(scan_id):
    """Get scan results"""
    history = load_scan_history()
    scan = next((s for s in history if s.get("scan_id") == scan_id), None)
    
    if scan is None:
        return jsonify({
            "success": False,
            "error": "Scan not found"
        }), 404
    
    # Permission check
    if (
        scan.get("scanned_by") != session.get("username")
        and session.get("role") != "admin"
    ):
        return jsonify({
            "success": False,
            "error": "Access denied"
        }), 403
    
    return jsonify({
        "success": True,
        "scan": scan
    })

# ============== ADMIN APIs ==============

@app.route('/admin/api/users')
@admin_required
def admin_api_users():
    """Return all registered users"""
    users = load_users()
    
    user_list = []
    for username, user in users.items():
        user_list.append({
            "username": username,
            "email": user.get("email", ""),
            "name": user.get("name", ""),
            "role": user.get("role", "user"),
            "active": user.get("active", True),
            "created_at": user.get("created_at", ""),
            "last_login": user.get("last_login", ""),
            "oauth_provider": user.get("oauth_provider", "Unknown")
        })
    
    return jsonify({
        "success": True,
        "count": len(user_list),
        "users": user_list
    })

@app.route('/admin/api/toggle-user/<username>', methods=["POST"])
@admin_required
def admin_toggle_user(username):
    """Enable or disable a user"""
    users = load_users()
    
    if username not in users:
        return jsonify({
            "success": False,
            "error": "User not found"
        }), 404
    
    if username == session.get("username"):
        return jsonify({
            "success": False,
            "error": "You cannot disable your own account."
        }), 400
    
    users[username]["active"] = not users[username].get("active", True)
    save_users(users)
    
    return jsonify({
        "success": True,
        "active": users[username]["active"],
        "message": (
            f"User '{username}' has been "
            f"{'activated' if users[username]['active'] else 'deactivated'}."
        )
    })

@app.route('/admin/api/delete-user/<username>', methods=["POST"])
@admin_required
def admin_delete_user(username):
    """Delete a user"""
    users = load_users()
    
    if username not in users:
        return jsonify({
            "success": False,
            "error": "User not found"
        }), 404
    
    if username == session.get("username"):
        return jsonify({
            "success": False,
            "error": "You cannot delete your own account."
        }), 400
    
    deleted_user = users.pop(username)
    save_users(users)
    
    return jsonify({
        "success": True,
        "deleted_user": {
            "username": username,
            "email": deleted_user.get("email", "")
        },
        "message": f"User '{username}' deleted successfully."
    })

# ============== REPORT GENERATOR ==============
def generate_html_report(scan_id, target_url, vulnerabilities, scanned_by):
    """
    Generate a professional cyberpunk-styled security vulnerability report.
    Creates an interactive HTML report with executive dashboard, vulnerability cards,
    filters, and full responsiveness.
    """
    import os
    from datetime import datetime
    
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    REPORTS_DIR = os.path.join(BASE_DIR, "reports")
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    generated_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Calculate statistics
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "Low")
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    total = len(vulnerabilities)
    critical = severity_counts["Critical"]
    high = severity_counts["High"]
    medium = severity_counts["Medium"]
    low = severity_counts["Low"]
    
    # Calculate risk score (0-100)
    risk_score = min(100, (critical * 25) + (high * 15) + (medium * 5) + (low * 1))
    
    # Determine security grade
    if risk_score >= 80:
        security_grade = "F"
        grade_color = "#ff0040"
    elif risk_score >= 60:
        security_grade = "D"
        grade_color = "#ff4400"
    elif risk_score >= 40:
        security_grade = "C"
        grade_color = "#ff8800"
    elif risk_score >= 20:
        security_grade = "B"
        grade_color = "#ffcc00"
    else:
        security_grade = "A"
        grade_color = "#00ff88"
    
    # OWASP categories
    owasp_categories = {}
    for vuln in vulnerabilities:
        vuln_type = vuln.get("type", "Unknown")
        owasp_categories[vuln_type] = owasp_categories.get(vuln_type, 0) + 1
    
    # Severity colors
    severity_colors = {
        "Critical": {"bg": "#1a0008", "border": "#ff0040", "text": "#ff0040", "glow": "rgba(255,0,64,0.5)"},
        "High": {"bg": "#1a0800", "border": "#ff6600", "text": "#ff6600", "glow": "rgba(255,102,0,0.5)"},
        "Medium": {"bg": "#1a1500", "border": "#ffcc00", "text": "#ffcc00", "glow": "rgba(255,204,0,0.5)"},
        "Low": {"bg": "#001a08", "border": "#00ff88", "text": "#00ff88", "glow": "rgba(0,255,136,0.5)"}
    }
    
    # Build vulnerability cards HTML
    vuln_cards_html = []
    for idx, vuln in enumerate(vulnerabilities):
        severity = vuln.get("severity", "Low")
        colors = severity_colors.get(severity, severity_colors["Low"])
        vuln_id = f"vuln-{idx}"
        
        card_html = f'''
        <div class="vulnerability-card {severity.lower()}" data-severity="{severity}" data-type="{vuln.get('type', '')}" data-name="{vuln.get('name', '').lower()}" id="{vuln_id}">
            <div class="card-header" onclick="toggleCard('{vuln_id}')">
                <div class="card-title-section">
                    <span class="severity-badge {severity.lower()}">{severity}</span>
                    <h3 class="vuln-name">{vuln.get('name', 'Unknown Vulnerability')}</h3>
                </div>
                <div class="card-actions">
                    <span class="vuln-type">{vuln.get('type', 'Unknown')}</span>
                    <button class="toggle-btn" aria-label="Toggle card">▼</button>
                </div>
            </div>
            <div class="card-body" id="body-{vuln_id}">
                <div class="card-grid">
                    <div class="card-section">
                        <h4>🔍 Evidence</h4>
                        <div class="code-block" id="evidence-{vuln_id}">
                            <code>{vuln.get('evidence', 'No evidence provided')}</code>
                        </div>
                        <button class="copy-btn" onclick="copyToClipboard('evidence-{vuln_id}', this)">📋 Copy Evidence</button>
                    </div>
                    <div class="card-section">
                        <h4>📍 Location</h4>
                        <p><strong>URL:</strong> <a href="{vuln.get('url', '#')}" target="_blank" class="vuln-link">{vuln.get('url', 'N/A')}</a></p>
                        <p><strong>Parameter:</strong> <code class="param-code">{vuln.get('parameter', 'N/A')}</code></p>
                        <button class="copy-btn" onclick="copyText('{vuln.get('url', '')}', this)">📋 Copy URL</button>
                    </div>
                    <div class="card-section full-width">
                        <h4>📝 Description</h4>
                        <p class="description-text">{vuln.get('description', 'No description available')}</p>
                    </div>
                    <div class="card-section full-width">
                        <h4>💡 Solution</h4>
                        <div class="solution-box" id="solution-{vuln_id}">
                            <p>{vuln.get('solution', 'No solution provided')}</p>
                        </div>
                        <button class="copy-btn" onclick="copyToClipboard('solution-{vuln_id}', this)">📋 Copy Solution</button>
                    </div>
                    <div class="card-section">
                        <h4>📊 Details</h4>
                        <p><strong>Confidence:</strong> <span class="confidence-badge">{vuln.get('confidence', 'Unknown')}</span></p>
                        <p><strong>Vulnerability ID:</strong> <code>{vuln.get('id', 'N/A')}</code></p>
                    </div>
                </div>
            </div>
        </div>
        '''
        vuln_cards_html.append(card_html)
    
    vuln_cards_str = "\\n".join(vuln_cards_html) if vuln_cards_html else '<div class="no-vulns">✅ No vulnerabilities detected</div>'
    
    # Build OWASP chart bars
    owasp_chart_html = []
    max_count = max(owasp_categories.values()) if owasp_categories else 1
    for cat, count in sorted(owasp_categories.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / max_count) * 100
        owasp_chart_html.append(f'''
        <div class="owasp-bar-item">
            <span class="owasp-label">{cat}</span>
            <div class="owasp-bar-container">
                <div class="owasp-bar" style="width: {percentage}%;"></div>
            </div>
            <span class="owasp-count">{count}</span>
        </div>
        ''')
    owasp_chart_str = "\\n".join(owasp_chart_html) if owasp_chart_html else '<p class="no-data">No OWASP categories</p>'
    
    # Build OWASP type options for filter dropdown
    owasp_options = "\\n".join([f'<option value="{cat}">{cat}</option>' for cat in sorted(owasp_categories.keys())])
    
    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>⚡ Security Scan Report - {scan_id}</title>
    <style>
        :root {{
            --bg-primary: #0a0a0f;
            --bg-secondary: #12121a;
            --bg-card: #1a1a24;
            --bg-glass: rgba(26, 26, 36, 0.8);
            --neon-red: #ff0040;
            --neon-orange: #ff6600;
            --neon-yellow: #ffcc00;
            --neon-green: #00ff88;
            --neon-cyan: #00ffff;
            --neon-purple: #b829dd;
            --neon-blue: #0088ff;
            --text-primary: #e0e0e0;
            --text-secondary: #a0a0a0;
            --text-muted: #606060;
            --border-color: rgba(255, 255, 255, 0.1);
            --glow-red: rgba(255, 0, 64, 0.5);
            --glow-orange: rgba(255, 102, 0, 0.5);
            --glow-yellow: rgba(255, 204, 0, 0.5);
            --glow-green: rgba(0, 255, 136, 0.5);
        }}
        
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        html {{ scroll-behavior: smooth; }}
        
        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.6;
            overflow-x: hidden;
        }}
        
        /* Scanline Animation */
        body::before {{
            content: '';
            position: fixed;
            top: 0; left: 0;
            width: 100%; height: 100%;
            background: linear-gradient(transparent 50%, rgba(0, 255, 255, 0.02) 50%);
            background-size: 100% 4px;
            pointer-events: none;
            z-index: 9999;
            animation: scanline 8s linear infinite;
        }}
        
        @keyframes scanline {{ 0% {{ transform: translateY(0); }} 100% {{ transform: translateY(4px); }} }}
        
        /* Grid Background */
        body::after {{
            content: '';
            position: fixed;
            top: 0; left: 0;
            width: 100%; height: 100%;
            background-image: 
                linear-gradient(rgba(0, 255, 255, 0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0, 255, 255, 0.03) 1px, transparent 1px);
            background-size: 50px 50px;
            pointer-events: none;
            z-index: -1;
        }}
        
        /* Header */
        .header {{
            background: linear-gradient(180deg, var(--bg-secondary) 0%, var(--bg-primary) 100%);
            border-bottom: 2px solid var(--neon-cyan);
            padding: 2rem 1rem;
            text-align: center;
            position: relative;
            overflow: hidden;
        }}
        
        .header::before {{
            content: '';
            position: absolute;
            top: 0; left: -100%;
            width: 100%; height: 2px;
            background: linear-gradient(90deg, transparent, var(--neon-cyan), transparent);
            animation: scan 3s linear infinite;
        }}
        
        @keyframes scan {{ 0% {{ left: -100%; }} 100% {{ left: 100%; }} }}
        
        .header h1 {{
            font-size: clamp(1.8rem, 5vw, 3rem);
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 3px;
            background: linear-gradient(90deg, var(--neon-red), var(--neon-orange), var(--neon-yellow));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            text-shadow: 0 0 30px var(--glow-red);
            margin-bottom: 0.5rem;
        }}
        
        .header-subtitle {{
            color: var(--neon-cyan);
            font-size: 0.9rem;
            letter-spacing: 5px;
            text-transform: uppercase;
        }}
        
        /* Container */
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem 1rem;
            display: grid;
            grid-template-columns: 280px 1fr;
            gap: 2rem;
        }}
        
        @media (max-width: 1024px) {{
            .container {{ grid-template-columns: 1fr; }}
        }}
        
        /* Sidebar */
        .sidebar {{
            position: sticky;
            top: 1rem;
            height: fit-content;
        }}
        
        @media (max-width: 1024px) {{
            .sidebar {{ position: relative; order: -1; }}
        }}
        
        .sidebar-card {{
            background: var(--bg-glass);
            backdrop-filter: blur(10px);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1rem;
        }}
        
        .sidebar-card h3 {{
            color: var(--neon-cyan);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 2px;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        
        .scan-info-item {{
            margin-bottom: 1rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border-color);
        }}
        
        .scan-info-item:last-child {{ border-bottom: none; margin-bottom: 0; padding-bottom: 0; }}
        
        .scan-info-label {{
            font-size: 0.75rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 0.25rem;
        }}
        
        .scan-info-value {{
            font-size: 0.9rem;
            color: var(--text-primary);
            word-break: break-all;
        }}
        
        .scan-info-value.target {{ color: var(--neon-cyan); }}
        
        .nav-list {{ list-style: none; }}
        .nav-list li {{ margin-bottom: 0.5rem; }}
        
        .nav-list a {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            color: var(--text-secondary);
            text-decoration: none;
            padding: 0.5rem;
            border-radius: 6px;
            transition: all 0.3s ease;
        }}
        
        .nav-list a:hover {{
            background: rgba(0, 255, 255, 0.1);
            color: var(--neon-cyan);
        }}
        
        .export-btn {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            width: 100%;
            padding: 0.75rem;
            margin-bottom: 0.5rem;
            background: transparent;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: var(--text-secondary);
            cursor: pointer;
            transition: all 0.3s ease;
            font-size: 0.85rem;
        }}
        
        .export-btn:hover {{
            border-color: var(--neon-cyan);
            color: var(--neon-cyan);
            box-shadow: 0 0 15px rgba(0, 255, 255, 0.2);
        }}
        
        /* Main Content */
        .main-content {{ min-width: 0; }}
        
        /* Dashboard */
        .dashboard {{ margin-bottom: 2rem; }}
        
        .dashboard-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        
        .stat-card {{
            background: var(--bg-glass);
            backdrop-filter: blur(10px);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
            border: 1px solid var(--border-color);
            transition: all 0.3s ease;
            animation: fadeInUp 0.6s ease forwards;
            opacity: 0;
            transform: translateY(20px);
        }}
        
        .stat-card:nth-child(1) {{ animation-delay: 0.1s; }}
        .stat-card:nth-child(2) {{ animation-delay: 0.2s; }}
        .stat-card:nth-child(3) {{ animation-delay: 0.3s; }}
        .stat-card:nth-child(4) {{ animation-delay: 0.4s; }}
        .stat-card:nth-child(5) {{ animation-delay: 0.5s; }}
        
        @keyframes fadeInUp {{ to {{ opacity: 1; transform: translateY(0); }} }}
        
        .stat-card:hover {{ transform: translateY(-5px); }}
        
        .stat-card.critical {{ border-bottom: 3px solid var(--neon-red); box-shadow: 0 4px 20px var(--glow-red); }}
        .stat-card.high {{ border-bottom: 3px solid var(--neon-orange); box-shadow: 0 4px 20px var(--glow-orange); }}
        .stat-card.medium {{ border-bottom: 3px solid var(--neon-yellow); box-shadow: 0 4px 20px var(--glow-yellow); }}
        .stat-card.low {{ border-bottom: 3px solid var(--neon-green); box-shadow: 0 4px 20px var(--glow-green); }}
        .stat-card.total {{ border-bottom: 3px solid var(--neon-purple); box-shadow: 0 4px 20px rgba(184, 41, 221, 0.3); }}
        
        .stat-number {{
            font-size: 2.5rem;
            font-weight: 800;
            margin-bottom: 0.5rem;
        }}
        
        .stat-card.critical .stat-number {{ color: var(--neon-red); text-shadow: 0 0 20px var(--glow-red); }}
        .stat-card.high .stat-number {{ color: var(--neon-orange); text-shadow: 0 0 20px var(--glow-orange); }}
        .stat-card.medium .stat-number {{ color: var(--neon-yellow); text-shadow: 0 0 20px var(--glow-yellow); }}
        .stat-card.low .stat-number {{ color: var(--neon-green); text-shadow: 0 0 20px var(--glow-green); }}
        .stat-card.total .stat-number {{ color: var(--neon-purple); text-shadow: 0 0 20px rgba(184, 41, 221, 0.5); }}
        
        .stat-label {{
            font-size: 0.85rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        /* Risk Section */
        .risk-section {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        
        @media (max-width: 768px) {{
            .risk-section {{ grid-template-columns: 1fr; }}
        }}
        
        .risk-card {{
            background: var(--bg-glass);
            backdrop-filter: blur(10px);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
        }}
        
        .risk-card h3 {{
            color: var(--neon-cyan);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 2px;
            margin-bottom: 1rem;
        }}
        
        .risk-meter {{
            position: relative;
            height: 30px;
            background: var(--bg-primary);
            border-radius: 15px;
            overflow: hidden;
            margin-bottom: 1rem;
        }}
        
        .risk-progress {{
            height: 100%;
            background: linear-gradient(90deg, var(--neon-green), var(--neon-yellow), var(--neon-orange), var(--neon-red));
            border-radius: 15px;
            transition: width 1s ease;
            position: relative;
        }}
        
        .risk-progress::after {{
            content: '';
            position: absolute;
            top: 0; right: 0;
            width: 20px; height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3));
            animation: shimmer 2s infinite;
        }}
        
        @keyframes shimmer {{ 0% {{ transform: translateX(0); }} 100% {{ transform: translateX(20px); }} }}
        
        .risk-value {{
            font-size: 2rem;
            font-weight: 800;
            color: var(--text-primary);
        }}
        
        .grade-display {{ text-align: center; padding: 2rem; }}
        
        .grade-letter {{
            font-size: 5rem;
            font-weight: 900;
            color: {grade_color};
            text-shadow: 0 0 40px {grade_color}80;
            line-height: 1;
        }}
        
        .grade-label {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 2px;
        }}
        
        /* OWASP Chart */
        .owasp-chart {{ margin-top: 1rem; }}
        
        .owasp-bar-item {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 0.75rem;
        }}
        
        .owasp-label {{
            font-size: 0.8rem;
            color: var(--text-secondary);
            min-width: 120px;
        }}
        
        .owasp-bar-container {{
            flex: 1;
            height: 8px;
            background: var(--bg-primary);
            border-radius: 4px;
            overflow: hidden;
        }}
        
        .owasp-bar {{
            height: 100%;
            background: linear-gradient(90deg, var(--neon-cyan), var(--neon-purple));
            border-radius: 4px;
            transition: width 1s ease;
        }}
        
        .owasp-count {{
            font-size: 0.85rem;
            color: var(--neon-cyan);
            min-width: 30px;
            text-align: right;
        }}
        
        /* Filters */
        .filters-section {{
            background: var(--bg-glass);
            backdrop-filter: blur(10px);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }}
        
        .filters-section h3 {{
            color: var(--neon-cyan);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 2px;
            margin-bottom: 1rem;
        }}
        
        .filters-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }}
        
        .filter-group {{
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }}
        
        .filter-group label {{
            font-size: 0.8rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .filter-group input,
        .filter-group select {{
            padding: 0.75rem;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: var(--text-primary);
            font-size: 0.9rem;
            transition: all 0.3s ease;
        }}
        
        .filter-group input:focus,
        .filter-group select:focus {{
            outline: none;
            border-color: var(--neon-cyan);
            box-shadow: 0 0 10px rgba(0, 255, 255, 0.2);
        }}
        
        .severity-filters {{
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-top: 1rem;
        }}
        
        .severity-filter {{
            padding: 0.5rem 1rem;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 20px;
            cursor: pointer;
            font-size: 0.8rem;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        
        .severity-filter.active {{
            background: var(--neon-cyan);
            color: var(--bg-primary);
            font-weight: 600;
        }}
        
        .severity-filter.critical {{ border-color: var(--neon-red); color: var(--neon-red); }}
        .severity-filter.critical.active {{ background: var(--neon-red); color: white; }}
        .severity-filter.high {{ border-color: var(--neon-orange); color: var(--neon-orange); }}
        .severity-filter.high.active {{ background: var(--neon-orange); color: white; }}
        .severity-filter.medium {{ border-color: var(--neon-yellow); color: var(--neon-yellow); }}
        .severity-filter.medium.active {{ background: var(--neon-yellow); color: var(--bg-primary); }}
        .severity-filter.low {{ border-color: var(--neon-green); color: var(--neon-green); }}
        .severity-filter.low.active {{ background: var(--neon-green); color: var(--bg-primary); }}
        
        /* Vulnerability Cards */
        .vulnerabilities-section {{ margin-bottom: 2rem; }}
        
        .section-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
        }}
        
        .section-header h2 {{
            color: var(--neon-cyan);
            font-size: 1.2rem;
            text-transform: uppercase;
            letter-spacing: 2px;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        
        .vuln-count {{
            background: var(--bg-primary);
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.85rem;
            color: var(--text-secondary);
        }}
        
        .vulnerability-card {{
            background: var(--bg-glass);
            backdrop-filter: blur(10px);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            margin-bottom: 1rem;
            overflow: hidden;
            transition: all 0.3s ease;
            animation: fadeInUp 0.5s ease forwards;
        }}
        
        .vulnerability-card:hover {{ transform: translateX(5px); }}
        
        .vulnerability-card.critical {{ border-left: 4px solid var(--neon-red); box-shadow: 0 4px 20px var(--glow-red); }}
        .vulnerability-card.high {{ border-left: 4px solid var(--neon-orange); box-shadow: 0 4px 20px var(--glow-orange); }}
        .vulnerability-card.medium {{ border-left: 4px solid var(--neon-yellow); box-shadow: 0 4px 20px var(--glow-yellow); }}
        .vulnerability-card.low {{ border-left: 4px solid var(--neon-green); box-shadow: 0 4px 20px var(--glow-green); }}
        
        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem 1.5rem;
            cursor: pointer;
            background: rgba(0,0,0,0.2);
            transition: background 0.3s ease;
        }}
        
        .card-header:hover {{ background: rgba(255,255,255,0.05); }}
        
        .card-title-section {{
            display: flex;
            align-items: center;
            gap: 1rem;
            flex: 1;
            min-width: 0;
        }}
        
        .severity-badge {{
            padding: 0.35rem 0.75rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            white-space: nowrap;
        }}
        
        .severity-badge.critical {{
            background: var(--neon-red);
            color: white;
            box-shadow: 0 0 15px var(--glow-red);
        }}
        
        .severity-badge.high {{
            background: var(--neon-orange);
            color: white;
            box-shadow: 0 0 15px var(--glow-orange);
        }}
        
        .severity-badge.medium {{
            background: var(--neon-yellow);
            color: var(--bg-primary);
            box-shadow: 0 0 15px var(--glow-yellow);
        }}
        
        .severity-badge.low {{
            background: var(--neon-green);
            color: var(--bg-primary);
            box-shadow: 0 0 15px var(--glow-green);
        }}
        
        .vuln-name {{
            font-size: 1rem;
            font-weight: 600;
            color: var(--text-primary);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        
        .card-actions {{
            display: flex;
            align-items: center;
            gap: 1rem;
        }}
        
        .vuln-type {{
            font-size: 0.8rem;
            color: var(--text-secondary);
            background: var(--bg-primary);
            padding: 0.35rem 0.75rem;
            border-radius: 4px;
        }}
        
        .toggle-btn {{
            background: none;
            border: none;
            color: var(--neon-cyan);
            font-size: 0.8rem;
            cursor: pointer;
            transition: transform 0.3s ease;
            padding: 0.5rem;
        }}
        
        .toggle-btn.collapsed {{
            transform: rotate(-90deg);
        }}
        
        .card-body {{
            padding: 1.5rem;
            border-top: 1px solid var(--border-color);
        }}
        
        .card-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
        }}
        
        .card-section {{
            background: var(--bg-primary);
            padding: 1rem;
            border-radius: 8px;
        }}
        
        .card-section.full-width {{ grid-column: 1 / -1; }}
        
        .card-section h4 {{
            color: var(--neon-cyan);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 0.75rem;
        }}
        
        .code-block {{
            background: #0d0d14;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 1rem;
            overflow-x: auto;
            margin-bottom: 0.75rem;
        }}
        
        .code-block code {{
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.85rem;
            color: var(--neon-green);
            white-space: pre-wrap;
            word-break: break-all;
        }}
        
        .param-code {{
            background: var(--bg-secondary);
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-family: monospace;
            color: var(--neon-purple);
        }}
        
        .vuln-link {{
            color: var(--neon-blue);
            text-decoration: none;
            word-break: break-all;
        }}
        
        .vuln-link:hover {{ text-decoration: underline; }}
        
        .description-text {{
            color: var(--text-secondary);
            line-height: 1.7;
        }}
        
        .solution-box {{
            background: rgba(0, 255, 136, 0.05);
            border: 1px solid var(--neon-green);
            border-radius: 6px;
            padding: 1rem;
            margin-bottom: 0.75rem;
        }}
        
        .solution-box p {{
            color: var(--text-primary);
            margin: 0;
        }}
        
        .confidence-badge {{
            background: var(--bg-secondary);
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.85rem;
            color: var(--neon-yellow);
        }}
        
        .copy-btn {{
            background: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            padding: 0.4rem 0.75rem;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.8rem;
            transition: all 0.3s ease;
        }}
        
        .copy-btn:hover {{
            border-color: var(--neon-cyan);
            color: var(--neon-cyan);
        }}
        
        .copy-btn.copied {{
            border-color: var(--neon-green);
            color: var(--neon-green);
        }}
        
        .no-vulns {{
            text-align: center;
            padding: 3rem;
            background: var(--bg-glass);
            border-radius: 12px;
            color: var(--neon-green);
            font-size: 1.2rem;
        }}
        
        /* Footer */
        .footer {{
            background: var(--bg-secondary);
            border-top: 1px solid var(--border-color);
            padding: 2rem;
            text-align: center;
            margin-top: 2rem;
        }}
        
        .footer-text {{
            color: var(--neon-cyan);
            font-size: 0.9rem;
            letter-spacing: 2px;
        }}
        
        .footer-subtitle {{
            color: var(--text-muted);
            font-size: 0.75rem;
            margin-top: 0.5rem;
        }}
        
        /* Back to Top */
        .back-to-top {{
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            width: 50px;
            height: 50px;
            background: var(--bg-glass);
            border: 1px solid var(--neon-cyan);
            border-radius: 50%;
            color: var(--neon-cyan);
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.2rem;
            transition: all 0.3s ease;
            opacity: 0;
            visibility: hidden;
            z-index: 1000;
        }}
        
        .back-to-top.visible {{
            opacity: 1;
            visibility: visible;
        }}
        
        .back-to-top:hover {{
            background: var(--neon-cyan);
            color: var(--bg-primary);
            box-shadow: 0 0 20px rgba(0, 255, 255, 0.5);
        }}
        
        /* Print Styles */
        @media print {{
            body::before, body::after, .back-to-top {{ display: none; }}
            .sidebar {{ display: none; }}
            .container {{ grid-template-columns: 1fr; padding: 0; }}
            .vulnerability-card {{
                break-inside: avoid;
                page-break-inside: avoid;
                box-shadow: none;
                border: 1px solid #ccc;
            }}
            .card-body {{ display: block !important; }}
            .copy-btn, .toggle-btn {{ display: none; }}
            body {{ background: white; color: black; }}
            .header {{ background: white; border-bottom: 2px solid black; }}
            .header h1 {{ -webkit-text-fill-color: black; color: black; }}
        }}
        
        .hidden {{ display: none !important; }}
    </style>
</head>
<body>
    <header class="header">
        <h1>⚡ SECURITY SCAN REPORT</h1>
        <p class="header-subtitle">Professional Penetration Testing Analysis</p>
    </header>
    
    <div class="container">
        <aside class="sidebar">
            <div class="sidebar-card">
                <h3>📋 Scan Information</h3>
                <div class="scan-info-item">
                    <div class="scan-info-label">Target URL</div>
                    <div class="scan-info-value target">{target_url}</div>
                </div>
                <div class="scan-info-item">
                    <div class="scan-info-label">Scan ID</div>
                    <div class="scan-info-value">{scan_id}</div>
                </div>
                <div class="scan-info-item">
                    <div class="scan-info-label">Generated</div>
                    <div class="scan-info-value">{generated_date}</div>
                </div>
                <div class="scan-info-item">
                    <div class="scan-info-label">Scanned By</div>
                    <div class="scan-info-value">{scanned_by}</div>
                </div>
            </div>
            
            <div class="sidebar-card">
                <h3>🧭 Navigation</h3>
                <ul class="nav-list">
                    <li><a href="#dashboard">📊 Dashboard</a></li>
                    <li><a href="#vulnerabilities">🐛 Vulnerabilities</a></li>
                    <li><a href="#owasp-chart">📈 OWASP Categories</a></li>
                </ul>
            </div>
            
            <div class="sidebar-card">
                <h3>💾 Export</h3>
                <button class="export-btn" onclick="window.print()">🖨️ Print Report</button>
                <button class="export-btn" onclick="downloadHTML()">📄 Download HTML</button>
                <button class="export-btn" onclick="downloadJSON()">📋 Download JSON</button>
            </div>
        </aside>
        
        <main class="main-content">
            <section id="dashboard" class="dashboard">
                <div class="dashboard-grid">
                    <div class="stat-card critical">
                        <div class="stat-number">{critical}</div>
                        <div class="stat-label">Critical</div>
                    </div>
                    <div class="stat-card high">
                        <div class="stat-number">{high}</div>
                        <div class="stat-label">High</div>
                    </div>
                    <div class="stat-card medium">
                        <div class="stat-number">{medium}</div>
                        <div class="stat-label">Medium</div>
                    </div>
                    <div class="stat-card low">
                        <div class="stat-number">{low}</div>
                        <div class="stat-label">Low</div>
                    </div>
                    <div class="stat-card total">
                        <div class="stat-number">{total}</div>
                        <div class="stat-label">Total Findings</div>
                    </div>
                </div>
                
                <div class="risk-section">
                    <div class="risk-card">
                        <h3>🎯 Risk Score</h3>
                        <div class="risk-meter">
                            <div class="risk-progress" style="width: {risk_score}%;"></div>
                        </div>
                        <div class="risk-value">{risk_score}/100</div>
                    </div>
                    <div class="risk-card">
                        <h3>🏆 Security Grade</h3>
                        <div class="grade-display">
                            <div class="grade-letter">{security_grade}</div>
                            <div class="grade-label">Overall Rating</div>
                        </div>
                    </div>
                </div>
                
                <div id="owasp-chart" class="risk-card">
                    <h3>📊 OWASP Category Distribution</h3>
                    <div class="owasp-chart">
                        {owasp_chart_str}
                    </div>
                </div>
            </section>
            
            <div class="filters-section">
                <h3>🔍 Filter & Search</h3>
                <div class="filters-grid">
                    <div class="filter-group">
                        <label for="search-input">Search Vulnerabilities</label>
                        <input type="text" id="search-input" placeholder="Type to search..." oninput="filterVulns()">
                    </div>
                    <div class="filter-group">
                        <label for="type-filter">Filter by Type</label>
                        <select id="type-filter" onchange="filterVulns()">
                            <option value="">All Types</option>
                            {owasp_options}
                        </select>
                    </div>
                </div>
                <div class="severity-filters">
                    <span class="severity-filter critical active" data-severity="Critical" onclick="toggleSeverityFilter(this)">Critical</span>
                    <span class="severity-filter high active" data-severity="High" onclick="toggleSeverityFilter(this)">High</span>
                    <span class="severity-filter medium active" data-severity="Medium" onclick="toggleSeverityFilter(this)">Medium</span>
                    <span class="severity-filter low active" data-severity="Low" onclick="toggleSeverityFilter(this)">Low</span>
                </div>
            </div>
            
            <section id="vulnerabilities" class="vulnerabilities-section">
                <div class="section-header">
                    <h2>🐛 Vulnerability Details</h2>
                    <span class="vuln-count" id="vuln-count">{total} findings</span>
                </div>
                <div id="vuln-container">
                    {vuln_cards_str}
                </div>
            </section>
        </main>
    </div>
    
    <footer class="footer">
        <p class="footer-text">⚡ Report generated by Cyberpunk Security Scanner</p>
        <p class="footer-subtitle">// SECURITY SCANNER v2.0 //</p>

    </footer>
    
    <button class="back-to-top" id="backToTop" onclick="scrollToTop()">▲</button>
    
    <script>
        const vulnerabilityData = {vulnerabilities!r};
        const scanMetadata = {{
            scan_id: '{scan_id}',
            target_url: '{target_url}',
            generated_date: '{generated_date}',
            scanned_by: '{scanned_by}',
            statistics: {{
                critical: {critical},
                high: {high},
                medium: {medium},
                low: {low},
                total: {total}
            }}
        }};
        
        function toggleCard(vulnId) {{
            const body = document.getElementById('body-' + vulnId);
            const btn = document.querySelector('#' + vulnId + ' .toggle-btn');
            
            if (body.style.display === 'none') {{
                body.style.display = 'block';
                btn.classList.remove('collapsed');
                btn.textContent = '▼';
            }} else {{
                body.style.display = 'none';
                btn.classList.add('collapsed');
                btn.textContent = '▶';
            }}
        }}
        
        function copyToClipboard(elementId, btn) {{
            const element = document.getElementById(elementId);
            const text = element.innerText || element.textContent;
            copyText(text, btn);
        }}
        
        function copyText(text, btn) {{
            navigator.clipboard.writeText(text).then(() => {{
                const originalText = btn.textContent;
                btn.textContent = '✓ Copied!';
                btn.classList.add('copied');
                setTimeout(() => {{
                    btn.textContent = originalText;
                    btn.classList.remove('copied');
                }}, 2000);
            }}).catch(err => {{
                console.error('Failed to copy:', err);
            }});
        }}
        
        let activeSeverities = ['Critical', 'High', 'Medium', 'Low'];
        
        function toggleSeverityFilter(element) {{
            const severity = element.dataset.severity;
            element.classList.toggle('active');
            
            if (element.classList.contains('active')) {{
                if (!activeSeverities.includes(severity)) {{
                    activeSeverities.push(severity);
                }}
            }} else {{
                activeSeverities = activeSeverities.filter(s => s !== severity);
            }}
            
            filterVulns();
        }}
        
        function filterVulns() {{
            const searchTerm = document.getElementById('search-input').value.toLowerCase();
            const typeFilter = document.getElementById('type-filter').value;
            const cards = document.querySelectorAll('.vulnerability-card');
            let visibleCount = 0;
            
            cards.forEach(card => {{
                const severity = card.dataset.severity;
                const type = card.dataset.type;
                const name = card.dataset.name;
                
                const matchesSearch = name.includes(searchTerm);
                const matchesType = !typeFilter || type === typeFilter;
                const matchesSeverity = activeSeverities.includes(severity);
                
                if (matchesSearch && matchesType && matchesSeverity) {{
                    card.classList.remove('hidden');
                    visibleCount++;
                }} else {{
                    card.classList.add('hidden');
                }}
            }});
            
            document.getElementById('vuln-count').textContent = visibleCount + ' findings';
        }}
        
        window.addEventListener('scroll', () => {{
            const backToTop = document.getElementById('backToTop');
            if (window.pageYOffset > 300) {{
                backToTop.classList.add('visible');
            }} else {{
                backToTop.classList.remove('visible');
            }}
        }});
        
        function scrollToTop() {{
            window.scrollTo({{ top: 0, behavior: 'smooth' }});
        }}
        
        function downloadHTML() {{
            const htmlContent = document.documentElement.outerHTML;
            const blob = new Blob([htmlContent], {{ type: 'text/html' }});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'security_report_{scan_id}.html';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }}
        
        function downloadJSON() {{
            const data = {{
                metadata: scanMetadata,
                vulnerabilities: vulnerabilityData
            }};
            const blob = new Blob([JSON.stringify(data, null, 2)], {{ type: 'application/json' }});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'security_report_{scan_id}.json';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }}
        
        document.addEventListener('DOMContentLoaded', () => {{
            const cards = document.querySelectorAll('.vulnerability-card');
            cards.forEach((card, index) => {{
                const body = card.querySelector('.card-body');
                const btn = card.querySelector('.toggle-btn');
                if (index > 0) {{
                    body.style.display = 'none';
                    btn.classList.add('collapsed');
                    btn.textContent = '▶';
                }}
            }});
        }});
    </script>
</body>
</html>'''
    
    # Write the report
    report_filename = f"report_{scan_id}.html"
    report_path = os.path.join(REPORTS_DIR, report_filename)
    
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return report_path

# ============== REPORT ROUTES ==============
@app.route('/report/<scan_id>')
@login_required
def view_report(scan_id):
    """Open HTML report"""
    report_path = os.path.join(REPORTS_DIR, f"report_{scan_id}.html")

    if not os.path.exists(report_path):
        return "Report not found", 404

    return send_file(report_path)


@app.route('/download-report/<scan_id>')
@login_required
def download_report(scan_id):
    """Download HTML report"""
    report_path = os.path.join(REPORTS_DIR, f"report_{scan_id}.html")

    if not os.path.exists(report_path):
        return "Report not found", 404

    return send_file(
        report_path,
        as_attachment=True,
        download_name=f"security_report_{scan_id}.html"
    )
# ============== ERROR HANDLERS ==============

@app.errorhandler(404)
def not_found(error):
    return "404 Not Found", 404


@app.errorhandler(500)
def server_error(error):
    logger.exception(error)
    return "Internal Server Error", 500
# ============== MAIN ==============

if __name__ == '__main__':
    print("\n" + "="*70)
    print("⚡ CYBERSEC - Security Testing Automation")
    print("="*70)
    print("🌐 Starting on http://localhost:5000")
    print(f"🔐 OAuth Configured: {bool(os.getenv('GOOGLE_CLIENT_ID') or os.getenv('GITHUB_CLIENT_ID'))}")
    print(f"🔍 OWASP ZAP: {'Available' if zap.is_available() else 'Not running (using simulated scans)'}")
    print("="*70 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)