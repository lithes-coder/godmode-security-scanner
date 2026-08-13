# Fix the raw `{vulnerabilities!r}` JSON embedding in the generated HTML report.
p = 'app.py'
with open(p, encoding='utf-8') as f:
    c = f.read()

changes = []

# 1) Replace the raw repr placeholder with single-brace interpolation of the safe variable.
old = "        const vulnerabilityData = {vulnerabilities!r};"
new = "        const vulnerabilityData = {vulnerability_json};"
if old in c:
    c = c.replace(old, new)
    changes.append('vulnerabilityData now uses safe variable')
else:
    changes.append('placeholder already changed')

# 2) Inject the safe JSON variable just before the vulnerable cards building so the
#    f-string variable `vulnerability_json` is in scope.
marker = "    # Build vulnerability cards HTML"
inject = (
    "    # Safe JSON for embedding in the report (no raw repr leakage)\n"
    "    vulnerability_json = json.dumps(vulnerabilities)\n"
    "    # Escape closing script tags to avoid breaking out of the <script> block\n"
    "    vulnerability_json = vulnerability_json.replace('</', '<\\\\/')\n"
    "\n"
    "    # Build vulnerability cards HTML"
)
if marker in c and 'vulnerability_json = json.dumps' not in c:
    c = c.replace(marker, inject, 1)
    changes.append('json variable injected')
elif 'vulnerability_json = json.dumps' in c:
    changes.append('json variable already present')

with open(p, 'w', encoding='utf-8', newline='') as f:
    f.write(c)

print("Changes:", changes if changes else "NO CHANGES MADE")

