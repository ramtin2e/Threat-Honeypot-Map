import uuid
from flask import Blueprint, request, make_response
from core.database import Attack, get_db_session
from core.mitre_mapper import map_command_to_mitre
from core.threat_intel import ti_provider

http_trap = Blueprint('http_trap', __name__)

def log_http_attack(payload):
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    geo = "Unknown"
    if ip == "127.0.0.1":
        geo = "Localhost"
        
    intel = ti_provider.get_ip_reputation(ip)
    session_id = str(uuid.uuid4())
        
    session = get_db_session()
    attack = Attack(
        session_id=session_id,
        source_ip=ip,
        geo_location=geo,
        port=80,
        protocol="HTTP",
        payload=payload,
        mitre_tags=map_command_to_mitre(payload),
        risk_score=intel["risk_score"],
        threat_label=intel["threat_label"]
    )
    session.add(attack)
    session.commit()
    session.close()

@http_trap.route('/wp-login.php', methods=['GET', 'POST'])
@http_trap.route('/wp-admin', methods=['GET', 'POST'])
def fake_wp_admin():
    if request.method == 'POST':
        user = request.form.get('log', '')
        pwd = request.form.get('pwd', '')
        payload = f"POST /wp-login.php (user: {user}, pwd: {pwd})"
        log_http_attack(payload)
        return "Invalid username or password.", 403
        
    log_http_attack(f"GET {request.path}")
    return "Wordpress Admin Portal - Access Denied", 403

@http_trap.route('/phpmyadmin', methods=['GET', 'POST'])
def fake_phpmyadmin():
    log_http_attack(f"{request.method} {request.path}")
    return "phpMyAdmin - Access Denied", 403

@http_trap.route('/<path:catchall>', methods=['GET', 'POST'])
def catch_all(catchall):
    # Log any suspicious paths like ../../../etc/passwd
    if '..' in catchall or 'etc' in catchall or 'cmd' in request.args:
        payload = f"{request.method} /{catchall}?{request.query_string.decode('utf-8')}"
        log_http_attack(payload)
        
    return "Not Found", 404
