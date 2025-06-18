import os
import pandas as pd
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, request, flash, redirect, url_for, 
    send_from_directory, jsonify
)
from werkzeug.utils import secure_filename
from pandas.errors import EmptyDataError
import geoip2.database
from geoip2.errors import AddressNotFoundError

# --- Import all analysis modules ---
from modules.log_parser import parse_logs
from modules.brute_force import detect_brute_force
from modules.port_scan import detect_port_scan
from modules.anomaly import detect_anomalies
from modules.blacklist_ip import detect_blacklisted_ips
from modules.report_generator import generate_report

# --- Application Setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_very_secret_key_that_should_be_changed'
UPLOAD_FOLDER = 'uploads'
REPORTS_FOLDER = 'reports'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['REPORTS_FOLDER'] = REPORTS_FOLDER

# --- File Paths and Constants ---
BLACKLIST_FILE = 'blacklist.txt'
GEOIP_DB_PATH = 'database/GeoLite2-Country.mmdb'

# --- Create necessary directories and files on startup ---
for folder in [UPLOAD_FOLDER, REPORTS_FOLDER, 'database']:
    if not os.path.exists(folder):
        os.makedirs(folder)
if not os.path.exists(BLACKLIST_FILE):
    with open(BLACKLIST_FILE, 'w') as f:
        f.write("# Add one IP address per line to blacklist.\n# Example:\n# 1.2.3.4\n# 5.6.7.8\n")

# --- Initialize GeoIP Reader ---
geoip_reader = None
try:
    geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
except FileNotFoundError:
    print(f"WARNING: GeoIP database not found at '{GEOIP_DB_PATH}'. Geolocation features will be disabled.")

# --- Helper Functions ---
def get_ip_location(ip):
    if not geoip_reader or not ip: return None
    try:
        if ip.startswith(('192.168.', '10.', '127.')) or ip in ('::1', 'localhost'): return None
        response = geoip_reader.country(ip)
        return {'country_code': response.country.iso_code, 'country_name': response.country.name}
    except (AddressNotFoundError, ValueError):
        return None

def get_blacklist():
    with open(BLACKLIST_FILE, 'r') as f:
        return {line.strip() for line in f if line.strip() and not line.startswith('#')}

def save_blacklist(content):
    with open(BLACKLIST_FILE, 'w') as f:
        f.write(content)

# --- Centralized Color Scheme ---
ALERT_TYPE_COLORS = {
    'Brute Force': '#dc2626', 'Port Scan': '#f59e0b', 'Anomaly': '#6366f1',
    'Blacklisted IP': '#16a34a', 'default': '#3b82f6'
}

# --- Main Routes ---
@app.route('/')
def dashboard():
    """Renders the main dashboard page skeleton."""
    return render_template('dashboard.html')

@app.route('/api/dashboard-data')
def dashboard_data():
    """Provides all necessary data for the dashboard as JSON, handling data errors gracefully."""
    try:
        stats = {"total_logs": 0, "threats_detected": 0, "alerts": 0}
        threat_type_counts, chart_colors, line_chart_data, top_ips, recent_alerts = {}, [], {'labels': [], 'data': []}, [], []
        alerts_df = pd.DataFrame()
        alerts_csv_path = os.path.join(app.config['REPORTS_FOLDER'], 'alerts.csv')

        if os.path.exists(UPLOAD_FOLDER):
            stats['total_logs'] = len(os.listdir(UPLOAD_FOLDER))

        if os.path.exists(alerts_csv_path):
            try:
                alerts_df = pd.read_csv(alerts_csv_path)
            except (EmptyDataError, pd.errors.ParserError):
                alerts_df = pd.DataFrame()

        required_cols = ['timestamp', 'type', 'ip']
        if not alerts_df.empty and all(col in alerts_df.columns for col in required_cols):
            stats['threats_detected'] = len(alerts_df)
            stats['alerts'] = len(alerts_df)
            alerts_df['timestamp'] = pd.to_datetime(alerts_df['timestamp'], errors='coerce')
            alerts_df.dropna(subset=['timestamp'], inplace=True)

            if not alerts_df.empty:
                threat_type_counts = alerts_df['type'].value_counts().to_dict()
                chart_labels = list(threat_type_counts.keys())
                chart_colors = [ALERT_TYPE_COLORS.get(label, ALERT_TYPE_COLORS['default']) for label in chart_labels]
                today = datetime.now().date()
                date_range = pd.date_range(start=today - timedelta(days=6), end=today, freq='D')
                alerts_by_day = alerts_df.set_index('timestamp').resample('D').size().reindex(date_range, fill_value=0)
                line_chart_data['labels'] = alerts_by_day.index.strftime('%b %d').tolist()
                line_chart_data['data'] = alerts_by_day.values.tolist()
                top_ips = list(alerts_df['ip'].value_counts().nlargest(5).to_dict().items())
                recent_alerts = alerts_df.sort_values(by='timestamp', ascending=False).head(5).to_dict(orient='records')

        return jsonify({
            'stats': stats, 'threat_type_counts': threat_type_counts, 'chart_colors': chart_colors,
            'line_chart_data': line_chart_data, 'top_ips': top_ips, 'recent_alerts': recent_alerts,
            'alert_type_colors': ALERT_TYPE_COLORS
        })
    except Exception as e:
        print(f"FATAL ERROR in /api/dashboard-data: {e}")
        return jsonify({'error': 'A critical error occurred on the server.'}), 500

@app.route('/alerts')
def alerts():
    """Displays a paginated, sortable, and filterable list of all security alerts."""
    page = request.args.get('page', 1, type=int)
    per_page = 15
    sort_by = request.args.get('sort_by', 'timestamp')
    sort_order = request.args.get('sort_order', 'desc')
    filter_type = request.args.get('filter_type', '')
    alerts_df = pd.DataFrame()
    unique_alert_types = []
    alerts_csv_path = os.path.join(app.config['REPORTS_FOLDER'], 'alerts.csv')

    if os.path.exists(alerts_csv_path):
        try:
            alerts_df = pd.read_csv(alerts_csv_path)
            if not alerts_df.empty:
                unique_alert_types = sorted(alerts_df['type'].unique())
                alerts_df['timestamp'] = pd.to_datetime(alerts_df['timestamp'], errors='coerce')
                alerts_df.dropna(subset=['timestamp'], inplace=True)
                
                # Add location data
                alerts_df['location'] = alerts_df['ip'].apply(get_ip_location)

                if filter_type:
                    alerts_df = alerts_df[alerts_df['type'] == filter_type]
                if sort_by in alerts_df.columns:
                    is_ascending = sort_order == 'asc'
                    alerts_df = alerts_df.sort_values(by=sort_by, ascending=is_ascending, kind='mergesort')
                alerts_df['display_timestamp'] = alerts_df['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
        except (EmptyDataError, pd.errors.ParserError):
            alerts_df = pd.DataFrame()

    total_alerts = len(alerts_df)
    start_index = (page - 1) * per_page
    end_index = start_index + per_page
    paginated_df = alerts_df.iloc[start_index:end_index]
    
    alerts_data = []
    for _, row in paginated_df.iterrows():
        alert_item = row.to_dict()
        alert_item['location'] = None if pd.isna(alert_item.get('location')) else alert_item['location']
        alerts_data.append(alert_item)

    total_pages = (total_alerts + per_page - 1) // per_page
    pagination_items = []
    if total_pages > 1:
        start, end = max(1, page - 2), min(total_pages, page + 2)
        if start > 1: pagination_items.append(1)
        if start > 2: pagination_items.append(None)
        for i in range(start, end + 1): pagination_items.append(i)
        if end < total_pages:
            if end < total_pages - 1: pagination_items.append(None)
            pagination_items.append(total_pages)
            
    return render_template(
        'alerts.html', alerts=alerts_data, page=page, total_pages=total_pages,
        total_alerts=total_alerts, pagination_items=pagination_items,
        alert_type_colors=ALERT_TYPE_COLORS, sort_by=sort_by, sort_order=sort_order,
        filter_type=filter_type, unique_alert_types=unique_alert_types
    )

@app.route('/upload', methods=['GET', 'POST'])
def upload_logs():
    """Handles log file uploads and initiates analysis."""
    if request.method == 'POST':
        files = request.files.getlist('log_files')
        if not files or files[0].filename == '':
            flash('No files selected for uploading.', 'warning')
            return redirect(request.url)
        
        analysis_summary = ""
        blacklist = get_blacklist()
        for file in files:
            if file:
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                
                logs = parse_logs(filepath)
                all_alerts = []
                all_alerts.extend(detect_brute_force(logs))
                all_alerts.extend(detect_port_scan(logs))
                all_alerts.extend(detect_anomalies(logs))
                all_alerts.extend(detect_blacklisted_ips(logs, blacklist))

                for alert in all_alerts:
                    alert['timestamp'] = datetime.now()

                generate_report(filename, all_alerts)
                analysis_summary += f"Analysis of {filename} complete. Found {len(all_alerts)} potential threats. "

                if all_alerts:
                    main_alerts_path = os.path.join(app.config['REPORTS_FOLDER'], 'alerts.csv')
                    new_alerts_df = pd.DataFrame(all_alerts)
                    new_alerts_df.to_csv(main_alerts_path, mode='a', header=not os.path.exists(main_alerts_path), index=False)

        if analysis_summary:
            flash(analysis_summary.strip(), 'success')
            return redirect(url_for('reports'))
        else:
            flash('An error occurred during file processing.', 'danger')
            return redirect(request.url)

    return render_template('upload.html')

@app.route('/reports')
def reports():
    """Displays a list of all generated reports."""
    reports_dir = app.config['REPORTS_FOLDER']
    report_files = []
    if os.path.exists(reports_dir):
        for filename in os.listdir(reports_dir):
            if filename.endswith('.csv'):
                filepath = os.path.join(reports_dir, filename)
                stat = os.stat(filepath)
                report_files.append({
                    'filename': filename,
                    'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                    'size': f"{stat.st_size / 1024:.2f} KB" if stat.st_size > 1024 else f"{stat.st_size} B"
                })
    report_files.sort(key=lambda x: x['modified'], reverse=True)
    return render_template('report.html', reports=report_files)

@app.route('/report/download/<path:filename>')
def report_download(filename):
    """Serves a specific report file for download."""
    return send_from_directory(app.config['REPORTS_FOLDER'], filename, as_attachment=True)

@app.route('/report/delete/<path:filename>', methods=['POST'])
def delete_report(filename):
    """Deletes a specific report file."""
    try:
        filepath = os.path.join(app.config['REPORTS_FOLDER'], secure_filename(filename))
        if os.path.exists(filepath):
            os.remove(filepath)
            flash(f"Report '{filename}' has been deleted.", 'success')
        else:
            flash(f"Report '{filename}' not found.", 'warning')
    except Exception as e:
        flash(f"Error deleting report: {e}", 'danger')
    return redirect(url_for('reports'))

# --- New Settings Route ---
@app.route('/settings', methods=['GET', 'POST'])
def settings():
    """Manages the IP blacklist settings."""
    if request.method == 'POST':
        content = request.form.get('blacklist')
        save_blacklist(content)
        flash('IP Blacklist has been updated successfully.', 'success')
        return redirect(url_for('settings'))
    
    blacklist_content = ""
    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, 'r') as f:
            blacklist_content = f.read()
            
    return render_template('settings.html', blacklist_content=blacklist_content)

# --- Main execution ---
if __name__ == '__main__':
    app.run(debug=True)