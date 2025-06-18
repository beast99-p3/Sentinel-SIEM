import pandas as pd

def parse_logs(filepath):
    # Example: parse Apache logs (extend for Suricata, Windows, etc.)
    logs = []
    with open(filepath, 'r') as f:
        for line in f:
            # Very basic Apache log parsing (customize as needed)
            parts = line.split()
            if len(parts) > 6:
                logs.append({
                    "ip": parts[0],
                    "datetime": parts[3][1:] if len(parts) > 3 else "",
                    "request": parts[5][1:] if len(parts) > 5 else "",
                    "status": parts[8] if len(parts) > 8 else "",
                    "user_agent": " ".join(parts[11:]) if len(parts) > 11 else ""
                })
    return logs