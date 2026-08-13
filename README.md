# 🔒 Security Testing Automation Application

**CodTech Internship Task - 4**

An end-to-end web application for automated security testing of web applications. This tool simulates OWASP ZAP functionality to detect vulnerabilities and generate comprehensive reports with remediation steps.

## ✨ Features

- 🚀 **Automated Security Scanning** - Scan web applications for vulnerabilities
- 🐛 **Vulnerability Detection** - Identifies common security issues:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Cross-Site Request Forgery (CSRF)
  - Insecure Direct Object Reference (IDOR)
  - Broken Authentication
  - Security Misconfiguration
  - Sensitive Data Exposure
  - XML External Entities (XXE)
  - Broken Access Control
  - Insufficient Logging
- 📊 **Interactive Dashboard** - View scan statistics and recent activity
- 📄 **HTML Report Generation** - Professional reports with remediation steps
- 📋 **Scan History** - Track all previous scans
- 🎨 **Modern Web Interface** - Clean, responsive design

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Step 1: Install Dependencies

```bash
# Navigate to the project directory
cd security-scanner-app

# Install required packages
pip install -r requirements.txt
```

### Step 2: Run the Application

```bash
# Start the Flask server
python app.py
```

The application will start on `http://localhost:5000`

### Step 3: Access the Application

Open your browser and navigate to:
```
http://localhost:5000
```

## 📁 Project Structure

```
security-scanner-app/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── templates/            # HTML templates
│   ├── base.html        # Base template
│   ├── index.html       # Dashboard
│   ├── scan.html        # Scan interface
│   └── history.html     # Scan history
├── reports/             # Generated reports (created automatically)
└── scan_history.json    # Scan history data (created automatically)
```

## 🚀 Usage

### Starting a New Scan

1. Click **"New Scan"** in the navigation menu
2. Enter the target URL (e.g., `https://example.com`)
3. Select scan type:
   - **Full Scan** - Complete security assessment
   - **Quick Scan** - Fast vulnerability check
   - **API Scan** - API endpoint testing
   - **Spider** - Site crawling only
4. Click **"Start Security Scan"**
5. Wait for the scan to complete
6. View or download the generated report

### Viewing Reports

- Click **"View Report"** to see the HTML report in your browser
- Click **"Download Report"** to save the report as an HTML file
- Reports include:
  - Executive summary
  - Vulnerability details
  - Evidence of findings
  - Remediation steps

### Scan History

- Access all previous scans from the **History** page
- Filter scans by severity (Critical, High, Clean)
- Search by target URL or scan ID
- Download any previous report

## 📊 Dashboard Overview

The dashboard provides:
- **Total Scans** - Number of scans performed
- **Vulnerabilities Found** - Total issues detected
- **Critical Issues** - High-priority vulnerabilities
- **Recent Scans** - Quick access to latest results

## 🔧 Configuration

### Environment Variables (Optional)

Create a `.env` file for additional configuration:

```env
FLASK_ENV=development
FLASK_PORT=5000
ZAP_PROXY=http://localhost:8080
ZAP_API_KEY=your-api-key
```

### Integration with Real OWASP ZAP

To connect with actual OWASP ZAP:

1. Install OWASP ZAP from https://www.zaproxy.org/
2. Start ZAP in daemon mode: `zap.sh -daemon -port 8080`
3. Update `ZAP_PROXY` in `app.py` to match your ZAP instance
4. Modify the `simulate_security_scan()` function to call ZAP API

## 📝 Sample Reports

The application generates professional HTML reports including:

1. **Executive Summary** - High-level overview with severity counts
2. **Vulnerability Details** - For each finding:
   - Name and severity level
   - Location (URL and parameter)
   - Detailed description
   - Evidence from testing
   - Step-by-step remediation guidance

## 🎓 Learning Resources

This application demonstrates:
- Flask web framework
- RESTful API design
- HTML/CSS/JavaScript frontend
- Security testing concepts
- Report generation
- File I/O operations

## ⚠️ Disclaimer

This is a demonstration application for educational purposes. The vulnerability detection is simulated and should not be used as a replacement for professional security testing tools like OWASP ZAP or Burp Suite.

For production use, integrate with actual security scanning tools and ensure proper authorization before scanning any target.

## 🔗 References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP ZAP](https://www.zaproxy.org/)
- [Flask Documentation](https://flask.palletsprojects.com/)

## 📧 Support

For issues or questions related to this internship task, please refer to the CodTech internship guidelines.

---

**Developed for CodTech Internship Task-4: Security Testing Automation**
