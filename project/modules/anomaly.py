def detect_anomalies(logs):
    # Example: Rare user agents
    from collections import Counter
    user_agents = [log.get("user_agent", "") for log in logs]
    counts = Counter(user_agents)
    alerts = []
    for ua, count in counts.items():
        if count == 1 and ua:
            alerts.append({
                "type": "Anomaly",
                "user_agent": ua,
                "description": f"Rare user agent detected: {ua}"
            })
    return alerts