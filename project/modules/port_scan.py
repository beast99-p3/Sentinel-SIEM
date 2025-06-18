def detect_port_scan(logs):
    # Example: Detect >10 different ports accessed by same IP in short time
    from collections import defaultdict

    port_access = defaultdict(set)
    alerts = []
    for log in logs:
        ip = log.get("ip")
        request = log.get("request", "")
        if ":" in request:
            port = request.split(":")[-1]
            port_access[ip].add(port)
    for ip, ports in port_access.items():
        if len(ports) > 10:
            alerts.append({
                "type": "Port Scan",
                "ip": ip,
                "count": len(ports),
                "description": f"Port scan detected from {ip} ({len(ports)} ports)"
            })
    return alerts