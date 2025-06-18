document.addEventListener("DOMContentLoaded", function () {
  const API_URL = '/api/dashboard-data';

  // --- Helper Functions to build UI components ---

  function renderStats(stats) {
    document.getElementById('stats-total-logs').textContent = stats.total_logs;
    document.getElementById('stats-threats-detected').textContent = stats.threats_detected;
    document.getElementById('stats-alerts').textContent = stats.alerts;
  }

  function renderThreatTypes(containerId, counts, colors, colorMap) {
    const container = document.getElementById(containerId);
    if (!counts || Object.keys(counts).length === 0) {
      container.innerHTML = `<h5 class="card-title text-accent"><i class="bi bi-pie-chart-fill me-2"></i>Threat Types</h5><div class="d-flex flex-grow-1 align-items-center justify-content-center text-center text-muted"><div><i class="bi bi-bar-chart-line fs-1"></i><p class="mt-2">No threat data available.</p></div></div>`;
      return;
    }

    let listHtml = '<ul class="list-group list-group-flush">';
    for (const [type, count] of Object.entries(counts)) {
      const color = colorMap[type] || colorMap['default'];
      listHtml += `<li class="list-group-item d-flex justify-content-between align-items-center px-0"><span><span class="d-inline-block rounded-circle me-2" style="width: 10px; height: 10px; background-color: ${color};"></span>${type}</span><span class="badge rounded-pill" style="background-color: ${color};">${count}</span></li>`;
    }
    listHtml += '</ul>';

    container.innerHTML = `
      <h5 class="card-title text-accent"><i class="bi bi-pie-chart-fill me-2"></i>Threat Types</h5>
      <div class="chart-container" style="height: 220px;"><canvas id="threatTypeChart"></canvas></div>
      <hr class="my-3">
      <div class="flex-grow-1" style="overflow-y: auto;">${listHtml}</div>`;

    new Chart(document.getElementById('threatTypeChart'), {
      type: 'doughnut',
      data: { labels: Object.keys(counts), datasets: [{ data: Object.values(counts), backgroundColor: colors, borderWidth: 2, borderColor: '#fff' }] },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }
    });
  }

  function renderAlertsOverTime(containerId, chartData) {
    const container = document.getElementById(containerId);
    if (!chartData || !chartData.data || chartData.data.length === 0) {
      container.innerHTML = `<h5 class="card-title text-accent"><i class="bi bi-graph-up-arrow me-2"></i>Alerts Over Last 7 Days</h5><div class="d-flex flex-grow-1 align-items-center justify-content-center text-center text-muted"><div><i class="bi bi-graph-up fs-1"></i><p class="mt-2">Not enough data for a trend.</p></div></div>`;
      return;
    }
    
    container.innerHTML = `<h5 class="card-title text-accent"><i class="bi bi-graph-up-arrow me-2"></i>Alerts Over Last 7 Days</h5><div class="chart-container flex-grow-1" style="min-height: 300px;"><canvas id="alertsOverTimeChart"></canvas></div>`;
    
    new Chart(document.getElementById('alertsOverTimeChart'), {
      type: 'line',
      data: { labels: chartData.labels, datasets: [{ label: 'Alerts', data: chartData.data, borderColor: '#2563eb', backgroundColor: 'rgba(37, 99, 235, 0.1)', fill: true, tension: 0.4, pointBackgroundColor: '#2563eb', pointRadius: 4 }] },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { color: '#232946' }, grid: { color: '#e0e7ef' } }, x: { ticks: { color: '#232946' }, grid: { color: '#e0e7ef' } } } }
    });
  }

  function renderTopIPs(containerId, ips) {
    const container = document.getElementById(containerId);
    if (!ips || ips.length === 0) {
      container.innerHTML = `<h5 class="card-title text-accent"><i class="bi bi-shield-exclamation me-2"></i>Top Offending IPs</h5><p class="text-muted mt-3">No offending IPs recorded yet.</p>`;
      return;
    }

    let tableHtml = `<table class="table table-sm table-striped"><thead><tr><th>IP Address</th><th>Count</th></tr></thead><tbody>`;
    ips.forEach(([ip, count]) => {
      tableHtml += `<tr><td class="font-monospace">${ip}</td><td><span class="badge bg-danger rounded-pill">${count}</span></td></tr>`;
    });
    tableHtml += `</tbody></table>`;
    
    container.innerHTML = `<h5 class="card-title text-accent"><i class="bi bi-shield-exclamation me-2"></i>Top Offending IPs</h5>${tableHtml}`;
  }

  function renderRecentAlerts(containerId, alerts, colorMap) {
    const container = document.getElementById(containerId);
    if (!alerts || alerts.length === 0) {
      container.innerHTML = `<h5 class="card-title text-accent"><i class="bi bi-bell-fill me-2"></i>Recent Alerts</h5><p class="text-muted mt-3">No recent alerts to display.</p>`;
      return;
    }

    let listHtml = '<ul class="list-group list-group-flush flex-grow-1" style="overflow-y: auto;">';
    alerts.forEach(alert => {
      const color = colorMap[alert.type] || colorMap['default'];
      listHtml += `<li class="list-group-item"><span class="badge me-2" style="background-color: ${color};">${alert.type}</span>${alert.description}</li>`;
    });
    listHtml += '</ul>';

    container.innerHTML = `<h5 class="card-title text-accent"><i class="bi bi-bell-fill me-2"></i>Recent Alerts</h5>${listHtml}`;
  }

  // --- Main function to fetch data and populate the dashboard ---

  async function loadDashboard() {
    try {
      const response = await fetch(API_URL);
      if (!response.ok) {
        throw new Error(`API Error: ${response.statusText}`);
      }
      const data = await response.json();

      renderStats(data.stats);
      renderThreatTypes('threat-types-container', data.threat_type_counts, data.chart_colors, data.alert_type_colors);
      renderAlertsOverTime('alerts-over-time-container', data.line_chart_data);
      renderTopIPs('top-ips-container', data.top_ips);
      renderRecentAlerts('recent-alerts-container', data.recent_alerts, data.alert_type_colors);

      // Initialize tooltips after the DOM is populated
      const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
      [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));

    } catch (error) {
      console.error('Failed to load dashboard data:', error);
      document.getElementById('dashboard-container').innerHTML = `<div class="alert alert-danger"><strong>Error:</strong> Could not load dashboard data. Please try again later.</div>`;
    }
  }

  loadDashboard();
});