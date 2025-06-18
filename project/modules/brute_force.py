def detect_brute_force(logs):
    # Example: Detect >5 failed logins from same IP in 10 min
    from collections import defaultdict
    from datetime import datetime, timedelta

    failed = defaultdict(list)
    alerts = []
    for log in logs:
        if "failed" in log.get("request", "").lower():
            ip = log.get("ip")
            dt = log.get("datetime")
            if ip and dt:
                failed[ip].append(dt)
    for ip, times in failed.items():
        if len(times) > 5:
            alerts.append({
                "type": "Brute Force",
                "ip": ip,
                "count": len(times),
                "description": f"Brute force detected from {ip} ({len(times)} failed attempts)"
            })
    return alerts