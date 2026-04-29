import random
import os
import requests
from dotenv import load_dotenv

load_dotenv()

class ThreatIntelProvider:
    """
    A modular class designed to integrate with APIs like AbuseIPDB or AlienVault OTX.
    Supports a LIVE_MODE toggle.
    """
    
    def __init__(self):
        self.live_mode = False
        self.abuseipdb_key = os.getenv("ABUSEIPDB_KEY")
        self.vt_key = os.getenv("VT_KEY")
        
        # Sample realistic threat tags for IPs (Mock Mode)
        self.threat_tags = [
            "Known Botnet", "Tor Exit Node", "Malware C2 Server",
            "Anonymous Proxy", "Suspicious Cloud IP", "Phishing Origin",
            "Scanner/Brute Forcer"
        ]

    def set_live_mode(self, enabled):
        """Toggle between mock and live mode if API keys exist"""
        if enabled and (not self.abuseipdb_key):
            # Fallback to mock if keys are missing
            self.live_mode = False
            return False
        self.live_mode = enabled
        return enabled

    def get_ip_reputation(self, ip_address):
        """
        Queries AbuseIPDB if live_mode is True.
        Otherwise uses realistic simulated data.
        """
        if self.live_mode and self.abuseipdb_key:
            try:
                headers = {'Key': self.abuseipdb_key, 'Accept': 'application/json'}
                params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
                res = requests.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params, timeout=5)
                if res.status_code == 200:
                    data = res.json()['data']
                    score = data.get('abuseConfidenceScore', 0)
                    label = "Known Attacker" if score > 50 else None
                    if data.get('isTor'): label = "Tor Exit Node"
                    return {"risk_score": score, "threat_label": label}
            except Exception as e:
                print(f"[CTI Error] {e}")
                # Fallback to mock on error
        
        # Mock Logic
        seed = sum(ord(c) for c in ip_address)
        random.seed(seed)
        risk_score = random.randint(10, 100)
        label = None
        if risk_score > 60:
            label = random.choice(self.threat_tags)
        random.seed()
        
        return {
            "risk_score": risk_score,
            "threat_label": label
        }

    def check_file_hash(self, file_hash):
        """Queries VirusTotal API if live_mode is True"""
        if self.live_mode and self.vt_key:
            try:
                headers = {'x-apikey': self.vt_key}
                res = requests.get(f'https://www.virustotal.com/api/v3/files/{file_hash}', headers=headers, timeout=5)
                if res.status_code == 200:
                    stats = res.json()['data']['attributes']['last_analysis_stats']
                    malicious = stats.get('malicious', 0)
                    return malicious > 0
            except Exception as e:
                pass
        return True # Mock mode assumes downloaded hashes are malicious

# Global instance to be shared across modules
ti_provider = ThreatIntelProvider()
