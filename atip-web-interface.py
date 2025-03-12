from flask import Flask, request, jsonify, render_template, redirect, url_for
import json
import sqlite3
import pandas as pd
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
import plotly.io as pio
from atip_core import ThreatIntelligencePlatform

app = Flask(__name__)
platform = ThreatIntelligencePlatform()

@app.route('/')
def index():
    """Main dashboard page."""
    return render_template('dashboard.html')

@app.route('/api/dashboard/summary')
def dashboard_summary():
    """API endpoint for dashboard summary stats."""
    conn = sqlite3.connect(platform.config["database"]["path"])
    
    # Last 24 hours
    end_time = datetime.now()
    start_time = end_time - timedelta(hours=24)
    
    # Get counts
    threat_count = pd.read_sql_query(
        "SELECT COUNT(*) FROM threats WHERE timestamp BETWEEN ? AND ?",
        conn, params=(start_time, end_time)
    ).iloc[0, 0]
    
    alert_count = pd.read_sql_query(
        "SELECT COUNT(*) FROM alerts WHERE timestamp BETWEEN ? AND ?",
        conn, params=(start_time, end_time)
    ).iloc[0, 0]
    
    action_count = pd.read_sql_query(
        "SELECT COUNT(*) FROM actions WHERE timestamp BETWEEN ? AND ?",
        conn, params=(start_time, end_time)
    ).iloc[0, 0]
    
    # High severity threats
    high_severity = pd.read_sql_query(
        "SELECT COUNT(*) FROM threats WHERE severity >= 8 AND timestamp BETWEEN ? AND ?",
        conn, params=(start_time, end_time)
    ).iloc[0, 0]
    
    conn.close()
    
    return jsonify({
        "total_threats": threat_count,
        "total_alerts": alert_count,
        "total_actions": action_count,
        "high_severity_threats": high_severity,
        "time_period": "24h"
    })

@app.route('/api/dashboard/threats')
def dashboard_threats():
    """API endpoint for threat breakdown."""
    conn = sqlite3.connect(platform.config["database"]["path"])
    
    # Last 7 days
    end_time = datetime.now()
    start_time = end_time - timedelta(days=7)
    
    # Get threat breakdown
    threats_by_type = pd.read_sql_query(
        "SELECT threat_type, COUNT(*) as count FROM threats WHERE timestamp BETWEEN ? AND ? GROUP BY threat_type",
        conn, params=(start_time, end_time)
    )
    
    threats_by_source = pd.read_sql_query(
        "SELECT source, COUNT(*) as count FROM threats WHERE timestamp BETWEEN ? AND ? GROUP BY source",
        conn, params=(start_time, end_time)
    )
    
    threats_by_severity = pd.read_sql_query(
        "SELECT severity, COUNT(*) as count FROM threats WHERE timestamp BETWEEN ? AND ? GROUP BY severity",
        conn, params=(start_time, end_time)
    )
    
    # Recent threats
    recent_threats = pd.read_sql_query(
        """
        SELECT id, threat_type, source, indicator, severity, description, timestamp
        FROM threats
        WHERE timestamp BETWEEN ? AND ?
        ORDER BY timestamp DESC LIMIT 10
        """,
        conn, params=(start_time, end_time)
    )
    
    conn.close()
    
    return jsonify({
        "by_type": threats_by_type.to_dict(orient="records"),
        "by_source": threats_by_source.to_dict(orient="records"),
        "by_severity": threats_by_severity.to_dict(orient="records"),
        "recent": recent_threats.to_dict(orient="records")
    })

@app.route('/api/dashboard/charts')
def dashboard_charts():
    """API endpoint for dashboard charts."""
    conn = sqlite3.connect(platform.config["database"]["path"])
    
    # Last 7 days
    end_time = datetime.now()
    start_time = end_time - timedelta(days=7)
    
    # Get hourly trend
    hourly_trend = pd.read_sql_query(
        """
        SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as hour, COUNT(*) as count 
        FROM threats 
        WHERE timestamp BETWEEN ? AND ? 
        GROUP BY hour
        ORDER BY hour
        """,
        conn, params=(start_time, end_time)
    )
    
    # Severity distribution
    severity_dist = pd.read_sql_query(
        """
        SELECT severity, COUNT(*) as count 
        FROM threats 
        WHERE timestamp BETWEEN ? AND ? 
        GROUP BY severity
        ORDER BY severity
        """,
        conn, params=(start_time, end_time)
    )
    
    conn.close()
    
    return jsonify({
        "hourly_trend": hourly_trend.to_dict(orient="records"),
        "severity_distribution": severity_dist.to_dict(orient="records")
    })

@app.route('/api/threats')
def get_threats():
    """API endpoint to get threats with filtering."""
    conn = sqlite3.connect(platform.config["database"]["path"])
    
    # Get query parameters
    severity = request.args.get('severity')
    source = request.args.get('source')
    threat_type = request.args.get('type')
    days = request.args.get('days', 7, type=int)
    limit = request.args.get('limit', 100, type=int)
    
    # Build query
    query = "SELECT * FROM threats WHERE timestamp >= datetime('now', ?)"
    params = [f'-{days} day']
    
    if severity:
        query += " AND severity >= ?"
        params.append(int(severity))
    
    if source:
        query += " AND source = ?"
        params.append(source)
    
    if threat_type:
        query += " AND threat_type = ?"
        params.append(threat_type)
    
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    
    # Execute query
    threats = pd.read_sql_query(query, conn, params=params)
    conn.close()
    
    return jsonify(threats.to_dict(orient="records"))

@app.route('/api/report/generate', methods=['POST'])
def generate_report():
    """Generate a threat intelligence report."""
    data = request.json
    time_period = data.get('time_period', '24h')
    
    report = platform.generate_report(time_period)
    
    return jsonify(report)

@app.route('/api/actions/block', methods=['POST'])
def block_indicator():
    """Manually block an indicator."""
    data = request.json
    indicator_type = data.get('type')
    indicator = data.get('indicator')
    
    if indicator_type == 'ip':
        status, details = platform._block_ip(indicator)
    elif indicator_type == 'url':
        status, details = platform._block_url(indicator)
    elif indicator_type == 'domain':
        status, details = platform._block_domain(indicator)
    else:
        return jsonify({"status": "error", "message": f"Unsupported indicator type: {indicator_type}"})
    
    return jsonify({
        "status": status,
        "details": details,
        "indicator": indicator,
        "type": indicator_type
    })

@app.route('/api/scan', methods=['POST'])
def manual_scan():
    """Trigger a manual data collection and analysis."""
    # Collect threat data
    threats = platform.collect_data()
    
    # Analyze data
    findings = platform.analyze_data()
    
    # Generate alerts
    alerts = platform.generate_alerts()
    
    # Send alerts
    if alerts:
        platform.send_alerts(alerts)
    
    return jsonify({
        "threats_collected": len(threats),
        "findings": len(findings),
        "alerts_generated": len(alerts)
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
