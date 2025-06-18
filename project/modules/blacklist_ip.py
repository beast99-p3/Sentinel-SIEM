def detect_blacklisted_ips(logs, blacklist_ips):
    """Detects connections from a provided set of blacklisted IPs."""
    alerts = []
    for log in logs:
        ip = log.get("ip")
        if ip in blacklist_ips:
            alerts.append({
                "type": "Blacklisted IP",
                "ip": ip,
                "description": f"Connection from blacklisted IP {ip}"
            })
    return alerts