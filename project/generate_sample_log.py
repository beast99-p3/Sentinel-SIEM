import random
from datetime import datetime, timedelta
import pandas as pd
import os

REPORTS_DIR = 'reports'
ALERTS_CSV = os.path.join(REPORTS_DIR, 'alerts.csv')
NUM_ALERTS = 500  # Total number of alerts to generate

ALERT_TYPES = {
    'Brute Force': ['10.0.0.5', '192.168.1.101', '172.16.0.50'],
    'Port Scan': ['203.0.113.45', '198.51.100.12', '10.0.0.5'],
    'Anomaly': ['192.168.1.150', '172.17.0.2'],
    'Blacklisted IP': ['1.2.3.4', '5.6.7.8']
}

ips = [
    "192.168.1.10", "10.0.0.5", "172.16.0.2", "203.0.113.1", "198.51.100.23",
    "8.8.8.8", "1.2.3.4", "5.6.7.8", "123.45.67.89", "111.222.333.444"
]
methods = ["GET", "POST", "PUT", "DELETE"]
resources = ["/", "/login", "/admin", "/dashboard", "/api/data", "/logout", "/report", "/user/profile"]
statuses = [200, 200, 200, 404, 403, 500, 401, 302]
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "curl/7.68.0",
    "python-requests/2.25.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (Linux; Android 10)",
    "SIEMScanner/1.0"
]

def random_log_line(base_time):
    ip = random.choice(ips)
    dt = (base_time + timedelta(seconds=random.randint(0, 86400))).strftime("%d/%b/%Y:%H:%M:%S +0000")
    method = random.choice(methods)
    resource = random.choice(resources)
    status = random.choice(statuses)
    size = random.randint(100, 5000)
    ua = random.choice(user_agents)
    return f'{ip} - - [{dt}] "{method} {resource} HTTP/1.1" {status} {size} "-" "{ua}"'

def generate_alerts():
    """Generates a diverse set of historical alerts for the last 7 days."""
    alerts = []
    today = datetime.now()

    for _ in range(NUM_ALERTS):
        alert_type = random.choice(list(ALERT_TYPES.keys()))
        ip = random.choice(ALERT_TYPES[alert_type])
        
        days_ago = random.uniform(0, 7)
        timestamp = today - timedelta(days=days_ago)
        
        description = f"Detected {alert_type.lower()} activity from IP {ip}"
        if alert_type == 'Blacklisted IP':
            description = f"Connection from blacklisted IP {ip}"

        alerts.append({
            'type': alert_type,
            'ip': ip,
            'description': description,
            'timestamp': timestamp
        })

    df = pd.DataFrame(alerts)
    df = df.sort_values(by='timestamp')
    
    os.makedirs(REPORTS_DIR, exist_ok=True)
    df.to_csv(ALERTS_CSV, index=False)
    print(f"Successfully generated {NUM_ALERTS} sample alerts in '{ALERTS_CSV}'")

if __name__ == "__main__":
    num_lines = 10000
    base_time = datetime.now() - timedelta(days=1)
    with open("sample_apache.log", "w") as f:
        for _ in range(num_lines):
            f.write(random_log_line(base_time) + "\n")
    print(f"Generated sample_apache.log with {num_lines} lines.")
    generate_alerts()