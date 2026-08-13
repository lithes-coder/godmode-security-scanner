# Remove redundant thunder/emoji icons, keep a single thunder in dashboard.
import io

def load(p):
    with open(p, encoding='utf-8') as f:
        return f.read()

def save(p, content):
    with open(p, 'w', encoding='utf-8', newline='') as f:
        f.write(content)

changes = []

# ---- base.html ----
p = 'templates/base.html'
c = load(p)
# Navbar brand: remove the standalone <span>⚡</span>
old = '<div class="navbar-brand">\n            <span>⚡</span>\n            <span>CYBERSEC</span>\n        </div>'
new = '<div class="navbar-brand">\n            <span>CYBERSEC</span>\n        </div>'
if old in c:
    c = c.replace(old, new); changes.append('base navbar brand')
# Footer: remove the two ⚡ around the footer line
old_f = '<p>⚡ <span>CYBERPUNK SECURITY SCANNER</span> // SYSTEM ONLINE // SECURE CONNECTION ⚡</p>'
new_f = '<p><span>CYBERPUNK SECURITY SCANNER</span> // SYSTEM ONLINE // SECURE CONNECTION</p>'
if old_f in c:
    c = c.replace(old_f, new_f); changes.append('base footer')
save(p, c)

# ---- index.html ----
p = 'templates/index.html'
c = load(p)
# Keep a single thunder in the dashboard welcome banner.
old = '<h1 class="glitch-text" data-text="⚡ SYSTEM ONLINE ⚡">⚡ <span>SYSTEM</span> ONLINE ⚡</h1>'
new = '<h1 class="glitch-text" data-text="⚡ SYSTEM ONLINE">⚡ <span>SYSTEM</span> ONLINE</h1>'
if old in c:
    c = c.replace(old, new); changes.append('index banner')
# Remove the thunder in "Recent Operations" heading
old = '<h2><span>⚡</span> Recent Operations</h2>'
new = '<h2><span>Recent Operations</span></h2>'
if old in c:
    c = c.replace(old, new); changes.append('index recent ops heading')
save(p, c)

# ---- scan.html ----
p = 'templates/scan.html'
c = load(p)
# Scan header title
old = '<h1 class="glitch-text" data-text="⚡ INITIATE SCAN ⚡">⚡ <span>INITIATE</span> SCAN ⚡</h1>'
new = '<h1 class="glitch-text" data-text="INITIATE SCAN">INITIATE <span>SCAN</span></h1>'
if old in c:
    c = c.replace(old, new); changes.append('scan header')
# Scan button
old = '⚡ INITIATE SCAN SEQUENCE ⚡'
new = 'INITIATE SCAN SEQUENCE'
if old in c:
    c = c.replace(old, new); changes.append('scan button')
# Progress header
old = '<h3>⚡ SCANNING IN PROGRESS ⚡</h3>'
new = '<h3>SCANNING IN PROGRESS</h3>'
if old in c:
    c = c.replace(old, new); changes.append('scan progress header')
save(p, c)

# ---- history.html ----
p = 'templates/history.html'
c = load(p)
old = '<h1 class="glitch-text" data-text="⚡ ARCHIVE DATABASE ⚡">⚡ <span>ARCHIVE</span> DATABASE ⚡</h1>'
new = '<h1 class="glitch-text" data-text="ARCHIVE DATABASE">ARCHIVE <span>DATABASE</span></h1>'
if old in c:
    c = c.replace(old, new); changes.append('history header')
save(p, c)

print("Applied:", changes if changes else "none")
