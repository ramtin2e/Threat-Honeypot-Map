import time
import os
import threading
from core.database import Attack, get_db_session

class ActiveDefenseSOAR:
    def __init__(self):
        self.rules_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'deployable_rules')
        os.makedirs(self.rules_dir, exist_ok=True)
        self.ps1_path = os.path.join(self.rules_dir, 'windows_firewall.ps1')
        self.sh_path = os.path.join(self.rules_dir, 'iptables_blocklist.sh')
        
        # Initialize files if they don't exist
        if not os.path.exists(self.ps1_path):
            with open(self.ps1_path, 'w') as f:
                f.write("# Auto-generated SOAR Blocklist\n")
        if not os.path.exists(self.sh_path):
            with open(self.sh_path, 'w') as f:
                f.write("#!/bin/bash\n# Auto-generated SOAR Blocklist\n")

    def monitor_loop(self):
        while True:
            try:
                session = get_db_session()
                # Find attacks that need blocking
                pending = session.query(Attack).filter(
                    Attack.risk_score > 80,
                    Attack.action_taken == "LOGGED"
                ).all()
                
                for attack in pending:
                    ip = attack.source_ip
                    # Write to PowerShell WAF list
                    with open(self.ps1_path, 'a') as f:
                        f.write(f'New-NetFirewallRule -DisplayName "SOAR_BLOCK_{ip}" -Direction Inbound -Action Block -RemoteAddress {ip}\n')
                    
                    # Write to iptables WAF list
                    with open(self.sh_path, 'a') as f:
                        f.write(f'iptables -A INPUT -s {ip} -j DROP\n')
                    
                    # Mark as blocked
                    attack.action_taken = "BLOCKED"
                    print(f"[SOAR] Automatically blocked malicious IP: {ip} (Risk: {attack.risk_score})")
                
                session.commit()
                session.close()
            except Exception as e:
                print(f"[SOAR Error] {e}")
            
            time.sleep(5)

def start_active_defense():
    soar = ActiveDefenseSOAR()
    t = threading.Thread(target=soar.monitor_loop, daemon=True)
    t.start()
    return soar
