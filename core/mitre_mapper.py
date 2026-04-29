def map_command_to_mitre(command):
    """
    Takes a string (command or payload) and returns a comma-separated list of MITRE ATT&CK tags.
    """
    command = command.lower()
    tags = set()
    
    # Discovery
    if any(cmd in command for cmd in ['whoami', 'id']):
        tags.add('T1033 (System Owner/User Discovery)')
    if any(cmd in command for cmd in ['uname -a', 'cat /etc/os-release', 'systeminfo']):
        tags.add('T1082 (System Information Discovery)')
    if any(cmd in command for cmd in ['ifconfig', 'ip a', 'ipconfig']):
        tags.add('T1016 (System Network Configuration Discovery)')
    
    # Credential Access
    if any(cmd in command for cmd in ['cat /etc/passwd', 'cat /etc/shadow']):
        tags.add('T1003.008 (OS Credential Dumping: /etc/passwd)')
    if '.ssh/id_rsa' in command:
        tags.add('T1552.004 (Credentials In Files: Private Keys)')
        
    # Execution
    if any(cmd in command for cmd in ['wget', 'curl']):
        tags.add('T1105 (Ingress Tool Transfer)')
    if any(cmd in command for cmd in ['chmod +x', 'chmod 777']):
        tags.add('T1222.002 (File and Directory Permissions Modification)')
    if './' in command or 'sh ' in command or 'bash ' in command:
        tags.add('T1059.004 (Command and Scripting Interpreter: Unix Shell)')

    # Persistence
    if 'crontab' in command or 'cron.d' in command:
        tags.add('T1053.003 (Scheduled Task/Job: Cron)')
    if 'authorized_keys' in command:
        tags.add('T1098.004 (Account Manipulation: SSH Authorized Keys)')

    # Defense Evasion
    if 'rm -rf' in command or 'history -c' in command:
        tags.add('T1070 (Indicator Removal on Host)')
        
    # HTTP Specific
    if 'wp-admin' in command or 'wp-login' in command:
        tags.add('T1110 (Brute Force)')
    if 'union select' in command or 'or 1=1' in command:
        tags.add('T1190 (Exploit Public-Facing Application: SQLi)')
    if '../' in command or '..%2f' in command:
        tags.add('T1190 (Exploit Public-Facing Application: Path Traversal)')

    if not tags:
        tags.add('Uncategorized')
        
    return ", ".join(list(tags))
