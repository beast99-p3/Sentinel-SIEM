import pandas as pd
import os
from datetime import datetime

def generate_report(log_filename, alerts):
    """
    Generates a CSV report from a list of alerts, saving it with a unique,
    timestamped filename to prevent overwrites.

    Args:
        log_filename (str): The name of the original log file being analyzed.
        alerts (list): A list of dictionaries, where each dictionary is an alert.

    Returns:
        str: The full path to the newly created report file.
    """
    # Ensure the 'reports' directory exists, creating it if necessary.
    reports_dir = "reports"
    os.makedirs(reports_dir, exist_ok=True)

    # Sanitize the base name and create a unique timestamp.
    base_name = os.path.splitext(log_filename)[0]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Construct a unique, descriptive report filename.
    report_filename = f"{base_name}_report_{timestamp}.csv"
    report_path = os.path.join(reports_dir, report_filename)
    
    # Create the report file.
    if alerts:
        # If there are alerts, save them to a DataFrame and then to CSV.
        alerts_df = pd.DataFrame(alerts)
        alerts_df.to_csv(report_path, index=False)
    else:
        # If no alerts, create an empty report with just the headers.
        with open(report_path, 'w') as f:
            f.write("type,ip,description\n")
    
    return report_path