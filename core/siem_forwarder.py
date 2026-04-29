import time
import json
import os
import threading
from datetime import datetime
from core.database import Attack, get_db_session

class SIEMForwarder:
    def __init__(self):
        self.logs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs')
        os.makedirs(self.logs_dir, exist_ok=True)
        self.log_file = os.path.join(self.logs_dir, 'siem_forwarder.json')
        self.last_id = 0

    def format_ecs(self, attack):
        """Formats the attack data into Elastic Common Schema (ECS)"""
        return {
            "@timestamp": attack.timestamp.isoformat() + "Z",
            "ecs": {"version": "8.0.0"},
            "event": {
                "category": ["intrusion_detection"],
                "type": ["info", "alert" if attack.risk_score > 60 else "connection"],
                "action": attack.action_taken.lower(),
                "dataset": "honeypot.traffic",
                "risk_score": attack.risk_score
            },
            "source": {
                "ip": attack.source_ip,
                "geo": {"country_name": attack.geo_location, "location": {"lat": attack.latitude, "lon": attack.longitude}}
            },
            "network": {
                "protocol": attack.protocol.lower(),
                "transport": "tcp"
            },
            "destination": {
                "port": attack.port
            },
            "rule": {
                "name": attack.threat_label or "Unknown",
                "ruleset": "mitre_attack",
                "reference": attack.mitre_tags
            },
            "file": {
                "hash": {"sha256": attack.file_hash} if attack.file_hash else None
            },
            "message": attack.payload
        }

    def monitor_loop(self):
        while True:
            try:
                session = get_db_session()
                # Find new attacks since last_id
                new_attacks = session.query(Attack).filter(Attack.id > self.last_id).order_by(Attack.id.asc()).all()
                
                if new_attacks:
                    with open(self.log_file, 'a') as f:
                        for attack in new_attacks:
                            ecs_json = self.format_ecs(attack)
                            f.write(json.dumps(ecs_json) + "\n")
                            self.last_id = attack.id
                            
                session.close()
            except Exception as e:
                print(f"[SIEM Error] {e}")
            
            time.sleep(3)

def start_siem_forwarder():
    forwarder = SIEMForwarder()
    t = threading.Thread(target=forwarder.monitor_loop, daemon=True)
    t.start()
    return forwarder
