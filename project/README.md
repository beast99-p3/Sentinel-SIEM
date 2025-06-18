# Mini SIEM System

This project is a Mini Security Information and Event Management (SIEM) system built in Python. It is designed to collect, parse, detect, and alert on security-related logs from various sources. The system integrates with Elasticsearch for log indexing and Kibana for visualization.

## Project Structure

- **ingest/**: Contains scripts for collecting logs from different sources.
  - `log_collector.py`: Collects logs from syslog, Apache logs, and Suricata alerts.
  
- **parser/**: Contains scripts for parsing logs.
  - `parse_logs.py`: Parses Apache and Suricata logs and formats them for Elasticsearch.

- **detection/**: Contains scripts for detecting threats.
  - `brute_force_detector.py`: Detects brute force attempts, focusing on failed SSH login attempts.

- **alerts/**: Contains scripts for sending alerts.
  - `email_alerts.py`: Sends email alerts based on detected patterns or thresholds.

- **dashboards/**: Contains Kibana dashboard configurations for visualizing logs and threats.

- **config/**: Holds configuration files for Elasticsearch, email alerts, and other parameters.

- **Docker/**: Contains Docker configuration for local setup.
  - `docker-compose.yml`: Sets up Elasticsearch and Kibana using Docker.

- **requirements.txt**: Lists the Python dependencies required for the project.

## Setup Instructions

1. **Clone the Repository**
   ```bash
   git clone <repository-url>
   cd python-mini-siem
   ```

2. **Install Dependencies**
   It is recommended to use a virtual environment. You can create one using:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```
   Then install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

3. **Set Up Docker**
   Ensure you have Docker installed on your machine. Navigate to the Docker directory and run:
   ```bash
   cd Docker
   docker-compose up -d
   ```
   This command will start Elasticsearch and Kibana in the background.

4. **Configure the Application**
   Update the configuration files in the `config/` directory with the necessary settings for Elasticsearch and email alerts.

5. **Run the Log Collector**
   Start collecting logs by running:
   ```bash
   python ingest/log_collector.py
   ```

6. **Parse Logs**
   After logs are collected, parse them using:
   ```bash
   python parser/parse_logs.py
   ```

7. **Detect Threats**
   Run the brute force detection script:
   ```bash
   python detection/brute_force_detector.py
   ```

8. **Send Alerts**
   If any threats are detected, alerts will be sent automatically via email using:
   ```bash
   python alerts/email_alerts.py
   ```

9. **Visualize in Kibana**
   Access Kibana at `http://localhost:5601` to visualize the logs and detected threats. Import the dashboard configurations from the `dashboards/` directory.

## Usage

This Mini SIEM system can be extended to include additional log sources, detection mechanisms, and alerting methods. It serves as a foundational framework for building more complex security monitoring solutions.