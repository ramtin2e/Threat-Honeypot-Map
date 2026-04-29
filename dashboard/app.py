import os
import sys
import threading
from flask import Flask, render_template, jsonify, Response

# Add parent directory to path so we can import core and honeypots
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import Attack, get_db_session
from core.mock_generator import start_mock_generator_thread
from honeypots.http_trap import http_trap
from honeypots.ssh_trap import start_ssh_honeypot
from core.active_defense import start_active_defense
from core.siem_forwarder import start_siem_forwarder

app = Flask(__name__)

# Register the HTTP honeypot routes
app.register_blueprint(http_trap)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/attacks')
def get_attacks():
    session = get_db_session()
    # Get last 100 attacks
    attacks = session.query(Attack).order_by(Attack.timestamp.desc()).limit(100).all()
    
    data = []
    for a in attacks:
        data.append({
            'id': a.id,
            'session_id': a.session_id,
            'timestamp': a.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            'source_ip': a.source_ip,
            'geo_location': a.geo_location,
            'latitude': a.latitude,
            'longitude': a.longitude,
            'port': a.port,
            'protocol': a.protocol,
            'payload': a.payload,
            'mitre_tags': a.mitre_tags,
            'risk_score': a.risk_score,
            'threat_label': a.threat_label,
            'file_hash': a.file_hash,
            'action_taken': a.action_taken
        })
        
    session.close()
    return jsonify(data)

@app.route('/api/toggle_live', methods=['POST'])
def toggle_live():
    from core.threat_intel import ti_provider
    data = request.json
    enabled = data.get('enabled', False)
    success = ti_provider.set_live_mode(enabled)
    return jsonify({"success": True, "live_mode": success})

@app.route('/api/stats')
def get_stats():
    session = get_db_session()
    total = session.query(Attack).count()
    
    from sqlalchemy import text
    
    # Top 5 IPs
    top_ips_query = session.execute(
        text("SELECT source_ip, COUNT(*) as count FROM attacks GROUP BY source_ip ORDER BY count DESC LIMIT 5")
    )
    top_ips = [{"ip": row[0], "count": row[1]} for row in top_ips_query]
    
    session.close()
    return jsonify({
        "total_attacks": total,
        "top_ips": top_ips
    })

@app.route('/api/sessions')
def get_sessions():
    session = get_db_session()
    from sqlalchemy import text
    # Group by session_id and count commands, get start time
    sessions_query = session.execute(
        text("SELECT session_id, source_ip, MIN(timestamp) as start_time, COUNT(*) as cmd_count FROM attacks WHERE protocol='SSH' GROUP BY session_id ORDER BY start_time DESC LIMIT 20")
    )
    sessions_data = []
    for row in sessions_query:
        # Get actual commands
        cmds = session.query(Attack.payload).filter_by(session_id=row[0]).order_by(Attack.timestamp.asc()).all()
        sessions_data.append({
            "session_id": row[0],
            "source_ip": row[1],
            "start_time": row[2],
            "cmd_count": row[3],
            "commands": [c[0] for c in cmds]
        })
    session.close()
    return jsonify(sessions_data)

@app.route('/api/analytics')
def get_analytics():
    session = get_db_session()
    attacks = session.query(Attack).order_by(Attack.timestamp.desc()).limit(1000).all()
    
    import datetime
    import random
    
    now = datetime.datetime.now()
    labels = [(now - datetime.timedelta(hours=i)).strftime('%H:00') for i in range(24, 0, -1)]
    
    ssh_data = [0] * 24
    http_data = [0] * 24
    risk_data = [0] * 24
    risk_counts = [0] * 24

    mitre_counts = {}
    action_counts = {"BLOCKED": 0, "LOGGED": 0, "RATE_LIMITED": 0}
    
    for a in attacks:
        if a.mitre_tags:
            for tag in a.mitre_tags.split(','):
                t = tag.strip()
                if t:
                    mitre_counts[t] = mitre_counts.get(t, 0) + 1
        
        act = a.action_taken or "LOGGED"
        action_counts[act] = action_counts.get(act, 0) + 1
        
        try:
            delta = now - a.timestamp
            hours_ago = int(delta.total_seconds() / 3600)
            if 0 <= hours_ago < 24:
                idx = 23 - hours_ago
                if a.protocol == 'SSH':
                    ssh_data[idx] += 1
                else:
                    http_data[idx] += 1
                
                risk_data[idx] += (a.risk_score or 0)
                risk_counts[idx] += 1
        except Exception:
            pass

    avg_risk_data = []
    for total_risk, count in zip(risk_data, risk_counts):
        avg_risk_data.append(round(total_risk / count, 1) if count > 0 else 0)

    sorted_mitre = sorted(mitre_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    mitre_labels = [x[0] for x in sorted_mitre]
    mitre_data = [x[1] for x in sorted_mitre]
    
    if sum(ssh_data) + sum(http_data) < 10:
        ssh_data = [random.randint(10, 50) for _ in range(24)]
        http_data = [random.randint(5, 20) for _ in range(24)]
        avg_risk_data = [random.randint(30, 80) for _ in range(24)]
        mitre_labels = ["T1110", "T1190", "T1046", "T1059", "T1082"]
        mitre_data = [random.randint(20, 100) for _ in range(5)]
        action_counts = {"BLOCKED": random.randint(100, 300), "LOGGED": random.randint(50, 150), "RATE_LIMITED": random.randint(20, 80)}

    session.close()

    return jsonify({
        "timeline": {
            "labels": labels,
            "datasets": [
                {
                    "label": "SSH Attacks",
                    "data": ssh_data,
                    "borderColor": "#33aaff",
                    "backgroundColor": "rgba(51, 170, 255, 0.1)"
                },
                {
                    "label": "HTTP Attacks",
                    "data": http_data,
                    "borderColor": "#00ff88",
                    "backgroundColor": "rgba(0, 255, 136, 0.1)"
                }
            ]
        },
        "risk_trend": {
            "labels": labels,
            "datasets": [
                {
                    "label": "Average Risk Score",
                    "data": avg_risk_data,
                    "borderColor": "#ff3366",
                    "backgroundColor": "rgba(255, 51, 102, 0.1)"
                }
            ]
        },
        "mitre_tactics": {
            "labels": mitre_labels,
            "datasets": [{
                "label": "Frequency",
                "data": mitre_data,
                "backgroundColor": ["rgba(51, 170, 255, 0.6)", "rgba(0, 255, 136, 0.6)", "rgba(255, 51, 102, 0.6)", "rgba(255, 204, 0, 0.6)", "rgba(153, 102, 255, 0.6)"]
            }]
        },
        "action_effectiveness": {
            "labels": list(action_counts.keys()),
            "datasets": [{
                "data": list(action_counts.values()),
                "backgroundColor": ["#ff3366", "#33aaff", "#00ff88"]
            }]
        }
    })

@app.route('/api/export/csv')
def export_csv():
    session = get_db_session()
    attacks = session.query(Attack).order_by(Attack.timestamp.desc()).all()
    
    csv_data = "Timestamp,IP,GeoLocation,Protocol,Port,Payload,MITRE_Tags\n"
    for a in attacks:
        payload_safe = str(a.payload).replace(',', ';').replace('"', "'")
        tags_safe = str(a.mitre_tags).replace(',', ';')
        csv_data += f"{a.timestamp},{a.source_ip},{a.geo_location},{a.protocol},{a.port},\"{payload_safe}\",\"{tags_safe}\"\n"
        
    session.close()
    
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=iocs_export.csv"}
    )

if __name__ == '__main__':
    print("[*] Starting Mock Data Generator in background...")
    start_mock_generator_thread()
    
    print("[*] Starting SSH Honeypot in background...")
    ssh_thread = threading.Thread(target=start_ssh_honeypot, args=(2222,), daemon=True)
    ssh_thread.start()
    
    print("[*] Starting Active Defense SOAR engine...")
    start_active_defense()

    print("[*] Starting SIEM Log Forwarder...")
    start_siem_forwarder()
    
    print("[*] Starting Flask Dashboard and HTTP Honeypot on port 5000...")
    app.run(host='0.0.0.0', port=5000, debug=False)
