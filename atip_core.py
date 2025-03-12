import requests
import json
import os
import time
import logging
from datetime import datetime
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
import sqlite3
import threading
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("atip.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ATIP")

class ThreatIntelligencePlatform:
    def __init__(self, config_path="config.json"):
        """Initialize the Automated Threat Intelligence Platform."""
        self.load_config(config_path)
        self.setup_database()
        self.last_run = {}
        
    def load_config(self, config_path):
        """Load configuration from JSON file."""
        try:
            with open(config_path, 'r') as f:
                self.config = json.load(f)
            logger.info("Configuration loaded successfully")
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            # Default configuration
            self.config = {
                "sources": {
                    "virus_total": {
                        "api_key": "YOUR_VIRUSTOTAL_API_KEY",
                        "url": "https://www.virustotal.com/api/v3/",
                        "polling_interval": 3600  # in seconds
                    },
                    "alien_vault": {
                        "api_key": "YOUR_ALIENVAULT_API_KEY",
                        "url": "https://otx.alienvault.com/api/v1/",
                        "polling_interval": 3600
                    },
                    "system_logs": {
                        "path": "/var/log/",
                        "polling_interval": 300
                    }
                },
                "database": {
                    "path": "atip_database.db"
                },
                "alerts": {
                    "email": {
                        "smtp_server": "smtp.gmail.com",
                        "smtp_port": 587,
                        "sender_email": "your_email@gmail.com",
                        "sender_password": "your_app_password",
                        "recipients": ["security_team@example.com"]
                    },
                    "slack": {
                        "webhook_url": "YOUR_SLACK_WEBHOOK_URL"
                    }
                },
                "analysis": {
                    "anomaly_detection": {
                        "contamination": 0.1
                    }
                },
                "integrations": {
                    "firewall": {
                        "api_url": "http://firewall.local/api/",
                        "api_key": "YOUR_FIREWALL_API_KEY"
                    }
                }
            }
            logger.warning("Using default configuration")
            
    def setup_database(self):
        """Set up SQLite database for storing threat intelligence data."""
        try:
            self.conn = sqlite3.connect(self.config["database"]["path"], check_same_thread=False)
            self.cursor = self.conn.cursor()
            
            # Create tables if they don't exist
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    threat_type TEXT,
                    source TEXT,
                    indicator TEXT,
                    severity INTEGER,
                    description TEXT,
                    timestamp DATETIME,
                    raw_data TEXT
                )
            ''')
            
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    threat_id INTEGER,
                    alert_type TEXT,
                    status TEXT,
                    timestamp DATETIME,
                    recipients TEXT,
                    FOREIGN KEY (threat_id) REFERENCES threats (id)
                )
            ''')
            
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    threat_id INTEGER,
                    action_type TEXT,
                    status TEXT,
                    details TEXT,
                    timestamp DATETIME,
                    FOREIGN KEY (threat_id) REFERENCES threats (id)
                )
            ''')
            
            self.conn.commit()
            logger.info("Database setup complete")
        except Exception as e:
            logger.error(f"Database setup error: {e}")
            
    def collect_data(self):
        """Collect threat data from configured sources."""
        all_threats = []
        
        # Collect from VirusTotal
        if "virus_total" in self.config["sources"]:
            vt_config = self.config["sources"]["virus_total"]
            if self._should_run("virus_total", vt_config["polling_interval"]):
                try:
                    logger.info("Collecting data from VirusTotal")
                    headers = {
                        "x-apikey": vt_config["api_key"]
                    }
                    # Example: Get recent malicious URLs
                    response = requests.get(
                        f"{vt_config['url']}urls/recent_malicious",
                        headers=headers
                    )
                    if response.status_code == 200:
                        data = response.json()
                        for item in data.get("data", []):
                            threat = {
                                "threat_type": "malicious_url",
                                "source": "virus_total",
                                "indicator": item["id"],
                                "severity": self._calculate_severity(item),
                                "description": f"Malicious URL detected by VirusTotal",
                                "timestamp": datetime.now(),
                                "raw_data": json.dumps(item)
                            }
                            all_threats.append(threat)
                    else:
                        logger.warning(f"VirusTotal API returned status code: {response.status_code}")
                except Exception as e:
                    logger.error(f"Error collecting data from VirusTotal: {e}")
                self.last_run["virus_total"] = time.time()
        
        # Collect from AlienVault OTX
        if "alien_vault" in self.config["sources"]:
            av_config = self.config["sources"]["alien_vault"]
            if self._should_run("alien_vault", av_config["polling_interval"]):
                try:
                    logger.info("Collecting data from AlienVault OTX")
                    headers = {
                        "X-OTX-API-KEY": av_config["api_key"]
                    }
                    # Example: Get recent pulses
                    response = requests.get(
                        f"{av_config['url']}pulses/subscribed",
                        headers=headers
                    )
                    if response.status_code == 200:
                        data = response.json()
                        for pulse in data.get("results", []):
                            for indicator in pulse.get("indicators", []):
                                threat = {
                                    "threat_type": indicator["type"],
                                    "source": "alien_vault",
                                    "indicator": indicator["indicator"],
                                    "severity": self._calculate_severity_from_pulse(pulse),
                                    "description": pulse.get("description", "Threat detected by AlienVault OTX"),
                                    "timestamp": datetime.now(),
                                    "raw_data": json.dumps(indicator)
                                }
                                all_threats.append(threat)
                    else:
                        logger.warning(f"AlienVault API returned status code: {response.status_code}")
                except Exception as e:
                    logger.error(f"Error collecting data from AlienVault OTX: {e}")
                self.last_run["alien_vault"] = time.time()
        
        # Collect from system logs
        if "system_logs" in self.config["sources"]:
            logs_config = self.config["sources"]["system_logs"]
            if self._should_run("system_logs", logs_config["polling_interval"]):
                try:
                    logger.info("Collecting data from system logs")
                    # Implement log parsing logic
                    # This is a simplified example - in a real system you'd use a log parser
                    log_threats = self._parse_system_logs(logs_config["path"])
                    all_threats.extend(log_threats)
                except Exception as e:
                    logger.error(f"Error collecting data from system logs: {e}")
                self.last_run["system_logs"] = time.time()
        
        # Store all collected threats in database
        self._store_threats(all_threats)
        return all_threats
    
    def _should_run(self, source_name, interval):
        """Determine if a source should be polled based on its interval."""
        current_time = time.time()
        if source_name not in self.last_run:
            return True
        return (current_time - self.last_run[source_name]) >= interval
    
    def _calculate_severity(self, item):
        """Calculate threat severity score (1-10) based on VirusTotal data."""
        # Example logic - customize based on your needs
        positives = item.get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
        total = sum(item.get("attributes", {}).get("last_analysis_stats", {}).values())
        if total == 0:
            return 5  # Default mid-level severity
        
        # Calculate percentage of positive detections
        detection_ratio = positives / total
        
        # Map to severity score (1-10)
        if detection_ratio > 0.8:
            return 10
        elif detection_ratio > 0.6:
            return 8
        elif detection_ratio > 0.4:
            return 6
        elif detection_ratio > 0.2:
            return 4
        else:
            return 2
    
    def _calculate_severity_from_pulse(self, pulse):
        """Calculate threat severity score (1-10) based on AlienVault pulse."""
        # Example logic - customize based on your needs
        tags = pulse.get("tags", [])
        high_severity_tags = ["malware", "ransomware", "exploit", "apt"]
        
        # Count high severity tags
        severity_count = sum(1 for tag in tags if any(high_tag in tag.lower() for high_tag in high_severity_tags))
        
        # Base severity on tag count and TLP level
        base_severity = min(severity_count * 2, 8)
        
        # Adjust based on TLP (Traffic Light Protocol)
        tlp = pulse.get("tlp", "").lower()
        if tlp == "red":
            base_severity += 2
        elif tlp == "amber":
            base_severity += 1
            
        return min(base_severity, 10)  # Cap at 10
    
    def _parse_system_logs(self, log_path):
        """Parse system logs for potential threats."""
        threats = []
        
        # This is a simplified example - in a real system, you'd use a proper log parser
        # and analyze various log files (authentication logs, firewall logs, etc.)
        try:
            # Example: Parse authentication logs for failed login attempts
            auth_log_path = os.path.join(log_path, "auth.log")
            if os.path.exists(auth_log_path):
                with open(auth_log_path, 'r') as f:
                    lines = f.readlines()
                
                # Look for failed login patterns
                failed_logins = {}
                for line in lines[-1000:]:  # Look at last 1000 lines
                    if "Failed password" in line:
                        # Extract IP address (simplified regex)
                        import re
                        ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                        if ip_match:
                            ip = ip_match.group(0)
                            if ip in failed_logins:
                                failed_logins[ip] += 1
                            else:
                                failed_logins[ip] = 1
                
                # Create threats for IPs with multiple failed logins
                for ip, count in failed_logins.items():
                    if count >= 5:  # Threshold for alerting
                        threat = {
                            "threat_type": "brute_force_attempt",
                            "source": "system_logs",
                            "indicator": ip,
                            "severity": min(count // 5, 10),  # Severity based on attempt count, max 10
                            "description": f"Multiple failed login attempts ({count}) from IP {ip}",
                            "timestamp": datetime.now(),
                            "raw_data": json.dumps({"failed_attempts": count})
                        }
                        threats.append(threat)
        except Exception as e:
            logger.error(f"Error parsing system logs: {e}")
        
        return threats
    
    def _store_threats(self, threats):
        """Store collected threats in the database."""
        if not threats:
            return
        
        try:
            for threat in threats:
                self.cursor.execute('''
                    INSERT INTO threats 
                    (threat_type, source, indicator, severity, description, timestamp, raw_data) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    threat["threat_type"], 
                    threat["source"], 
                    threat["indicator"], 
                    threat["severity"], 
                    threat["description"], 
                    threat["timestamp"], 
                    threat["raw_data"]
                ))
            
            self.conn.commit()
            logger.info(f"Stored {len(threats)} new threats in database")
        except Exception as e:
            logger.error(f"Error storing threats in database: {e}")
    
    def analyze_data(self):
        """Analyze threat data to identify patterns and anomalies."""
        logger.info("Starting threat data analysis")
        
        try:
            # Get recent threats from database
            self.cursor.execute('''
                SELECT id, threat_type, source, indicator, severity, timestamp 
                FROM threats 
                WHERE timestamp >= datetime('now', '-7 day')
            ''')
            recent_threats = self.cursor.fetchall()
            
            if not recent_threats:
                logger.info("No recent threats to analyze")
                return []
            
            # Convert to DataFrame for analysis
            df = pd.DataFrame(recent_threats, 
                             columns=['id', 'threat_type', 'source', 'indicator', 'severity', 'timestamp'])
            
            # 1. Anomaly Detection using Isolation Forest
            anomalies = self._detect_anomalies(df)
            
            # 2. Clustering to identify attack patterns
            clusters = self._cluster_threats(df)
            
            # 3. Time series analysis to detect unusual activity spikes
            time_anomalies = self._detect_time_anomalies(df)
            
            # Combine all findings
            all_findings = anomalies + clusters + time_anomalies
            
            # Store findings as new threats if they represent significant insights
            self._store_analysis_findings(all_findings)
            
            return all_findings
            
        except Exception as e:
            logger.error(f"Error during threat analysis: {e}")
            return []
    
    def _detect_anomalies(self, df):
        """Detect anomalous threats using Isolation Forest."""
        findings = []
               
        try:
            # Extract features for anomaly detection
            if len(df) < 10:  # Need sufficient data for meaningful analysis
                return findings
            
            # Prepare numeric features
            features = df[['severity']].copy()
            
            # Add source and threat_type as numeric features (one-hot encoding)
            source_dummies = pd.get_dummies(df['source'], prefix='source')
            type_dummies = pd.get_dummies(df['threat_type'], prefix='type')
            
            features = pd.concat([features, source_dummies, type_dummies], axis=1)
            
            # Apply Isolation Forest
            contamination = self.config["analysis"]["anomaly_detection"]["contamination"]
            model = IsolationForest(contamination=contamination, random_state=42)
            df['anomaly'] = model.fit_predict(features)
            
            # Extract anomalies (-1 indicates anomaly)
            anomalies = df[df['anomaly'] == -1]
            
            for _, anomaly in anomalies.iterrows():
                finding = {
                    "type": "anomaly",
                    "threat_id": int(anomaly['id']),
                    "description": f"Anomalous {anomaly['threat_type']} threat detected from {anomaly['source']}",
                    "severity": min(anomaly['severity'] + 2, 10),  # Increase severity for anomalies
                    "details": {
                        "indicator": anomaly['indicator'],
                        "original_severity": anomaly['severity'],
                        "detection_method": "Isolation Forest"
                    }
                }
                findings.append(finding)
                
            logger.info(f"Detected {len(findings)} anomalous threats")
            
        except Exception as e:
            logger.error(f"Error in anomaly detection: {e}")
            
        return findings
    
    def _cluster_threats(self, df):
        """Cluster threats to identify attack patterns."""
        findings = []
        
        try:
            # We need sufficient data for clustering
            if len(df) < 20:
                return findings
                
            # Prepare features for clustering
            # Convert categorical data to numeric
            source_dummies = pd.get_dummies(df['source'], prefix='source')
            type_dummies = pd.get_dummies(df['threat_type'], prefix='type')
            
            # Extract time features
            df['datetime'] = pd.to_datetime(df['timestamp'])
            df['hour'] = df['datetime'].dt.hour
            df['day'] = df['datetime'].dt.day
            
            # Combine features
            features = pd.concat([
                df[['severity', 'hour', 'day']],
                source_dummies,
                type_dummies
            ], axis=1)
            
            # Apply DBSCAN clustering
            model = DBSCAN(eps=0.5, min_samples=5)
            df['cluster'] = model.fit_predict(features)
            
            # Identify significant clusters (-1 is noise)
            clusters = df[df['cluster'] != -1]['cluster'].unique()
            
            for cluster_id in clusters:
                cluster_threats = df[df['cluster'] == cluster_id]
                
                # Only report clusters with multiple threats
                if len(cluster_threats) >= 3:
                    # Get most common threat type and source
                    common_type = cluster_threats['threat_type'].mode()[0]
                    common_source = cluster_threats['source'].mode()[0]
                    
                    # Calculate average severity
                    avg_severity = cluster_threats['severity'].mean()
                    
                    finding = {
                        "type": "cluster",
                        "threat_ids": cluster_threats['id'].tolist(),
                        "description": f"Identified cluster of {len(cluster_threats)} related {common_type} threats from {common_source}",
                        "severity": min(round(avg_severity) + 1, 10),
                        "details": {
                            "cluster_id": int(cluster_id),
                            "threat_types": cluster_threats['threat_type'].value_counts().to_dict(),
                            "sources": cluster_threats['source'].value_counts().to_dict(),
                            "detection_method": "DBSCAN Clustering"
                        }
                    }
                    findings.append(finding)
            
            logger.info(f"Detected {len(findings)} threat clusters")
            
        except Exception as e:
            logger.error(f"Error in threat clustering: {e}")
            
        return findings
    
    def _detect_time_anomalies(self, df):
        """Detect unusual spikes in threat activity over time."""
        findings = []
        
        try:
            # Convert timestamp to datetime
            df['datetime'] = pd.to_datetime(df['timestamp'])
            
            # Group by hour and count threats
            hourly_counts = df.groupby(pd.Grouper(key='datetime', freq='H')).size()
            
            # Need sufficient data
            if len(hourly_counts) < 24:
                return findings
                
            # Calculate moving average
            window_size = 6  # 6-hour window
            moving_avg = hourly_counts.rolling(window=window_size).mean()
            
            # Calculate standard deviation
            std_dev = hourly_counts.rolling(window=window_size).std()
            
            # Identify hours with unusually high activity (3 standard deviations above mean)
            for hour, count in hourly_counts.items():
                if hour < hourly_counts.index[window_size]:
                    continue  # Skip initial hours where we don't have enough data
                    
                mean = moving_avg[hour]
                std = std_dev[hour]
                
                if std > 0 and count > mean + 3 * std:
                    # Get threats in this hour
                    hour_threats = df[(df['datetime'] >= hour) & (df['datetime'] < hour + pd.Timedelta(hours=1))]
                    
                    finding = {
                        "type": "time_anomaly",
                        "threat_ids": hour_threats['id'].tolist(),
                        "description": f"Unusual spike of {count} threats detected at {hour}",
                        "severity": 8,  # High severity for time-based anomalies
                        "details": {
                            "timestamp": hour.strftime("%Y-%m-%d %H:%M:%S"),
                            "expected_count": round(mean, 2),
                            "actual_count": count,
                            "standard_deviations": round((count - mean) / std if std > 0 else 0, 2),
                            "detection_method": "Time Series Analysis"
                        }
                    }
                    findings.append(finding)
            
            logger.info(f"Detected {len(findings)} time-based anomalies")
            
        except Exception as e:
            logger.error(f"Error in time anomaly detection: {e}")
            
        return findings
    
    def _store_analysis_findings(self, findings):
        """Store analysis findings in the database."""
        if not findings:
            return
            
        try:
            for finding in findings:
                # Store finding as a new threat
                self.cursor.execute('''
                    INSERT INTO threats 
                    (threat_type, source, indicator, severity, description, timestamp, raw_data) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    f"analysis_{finding['type']}",
                    "internal_analysis",
                    ",".join(str(tid) for tid in finding.get("threat_ids", [finding.get("threat_id", 0)])),
                    finding["severity"],
                    finding["description"],
                    datetime.now(),
                    json.dumps(finding["details"])
                ))
            
            self.conn.commit()
            logger.info(f"Stored {len(findings)} analysis findings in database")
        except Exception as e:
            logger.error(f"Error storing analysis findings: {e}")
    
    def generate_alerts(self, threshold=7):
        """Generate alerts for high-severity threats."""
        alerts = []
        
        try:
            # Get high severity threats that haven't been alerted on
            self.cursor.execute('''
                SELECT t.id, t.threat_type, t.source, t.indicator, t.severity, t.description 
                FROM threats t
                LEFT JOIN alerts a ON t.id = a.threat_id
                WHERE t.severity >= ? AND a.id IS NULL
                ORDER BY t.severity DESC
            ''', (threshold,))
            
            high_severity_threats = self.cursor.fetchall()
            
            for threat in high_severity_threats:
                threat_id, threat_type, source, indicator, severity, description = threat
                
                # Create alert
                alert = {
                    "threat_id": threat_id,
                    "alert_type": "high_severity",
                    "status": "new",
                    "timestamp": datetime.now(),
                    "recipients": ",".join(self.config["alerts"]["email"]["recipients"])
                }
                
                # Insert alert into database
                self.cursor.execute('''
                    INSERT INTO alerts 
                    (threat_id, alert_type, status, timestamp, recipients) 
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    alert["threat_id"],
                    alert["alert_type"],
                    alert["status"],
                    alert["timestamp"],
                    alert["recipients"]
                ))
                
                # Get the alert ID
                alert_id = self.cursor.lastrowid
                alert["id"] = alert_id
                
                # Add threat details to alert
                alert["threat_details"] = {
                    "type": threat_type,
                    "source": source,
                    "indicator": indicator,
                    "severity": severity,
                    "description": description
                }
                
                alerts.append(alert)
            
            self.conn.commit()
            logger.info(f"Generated {len(alerts)} new alerts")
            
        except Exception as e:
            logger.error(f"Error generating alerts: {e}")
            
        return alerts
    
    def send_alerts(self, alerts):
        """Send alerts through configured channels."""
        if not alerts:
            return
            
        # Send email alerts
        if "email" in self.config["alerts"]:
            self._send_email_alerts(alerts)
            
        # Send Slack alerts
        if "slack" in self.config["alerts"]:
            self._send_slack_alerts(alerts)
            
        # Update alert status
        try:
            for alert in alerts:
                self.cursor.execute('''
                    UPDATE alerts SET status = 'sent' WHERE id = ?
                ''', (alert["id"],))
            
            self.conn.commit()
            logger.info(f"Updated status for {len(alerts)} alerts")
        except Exception as e:
            logger.error(f"Error updating alert status: {e}")
    
    def _send_email_alerts(self, alerts):
        """Send alerts via email."""
        try:
            email_config = self.config["alerts"]["email"]
            
            # Connect to SMTP server
            server = smtplib.SMTP(email_config["smtp_server"], email_config["smtp_port"])
            server.starttls()
            server.login(email_config["sender_email"], email_config["sender_password"])
            
            for alert in alerts:
                # Create message
                msg = MIMEMultipart()
                msg["From"] = email_config["sender_email"]
                msg["To"] = ", ".join(email_config["recipients"])
                
                threat = alert["threat_details"]
                severity_stars = "★" * threat["severity"]
                
                msg["Subject"] = f"[SECURITY ALERT] {severity_stars} {threat['type']} threat detected"
                
                body = f"""
                <html>
                <body>
                <h2>Security Alert: {threat['type']}</h2>
                <p><strong>Severity:</strong> {threat['severity']}/10 {severity_stars}</p>
                <p><strong>Source:</strong> {threat['source']}</p>
                <p><strong>Indicator:</strong> {threat['indicator']}</p>
                <p><strong>Description:</strong> {threat['description']}</p>
                <p><strong>Detection Time:</strong> {alert['timestamp']}</p>
                <p>Please investigate this threat immediately.</p>
                </body>
                </html>
                """
                
                msg.attach(MIMEText(body, "html"))
                
                # Send email
                server.send_message(msg)
                logger.info(f"Sent email alert for threat ID {alert['threat_id']}")
            
            server.quit()
            
        except Exception as e:
            logger.error(f"Error sending email alerts: {e}")
    
    def _send_slack_alerts(self, alerts):
        """Send alerts via Slack webhook."""
        try:
            slack_config = self.config["alerts"]["slack"]
            
            for alert in alerts:
                threat = alert["threat_details"]
                
                # Create Slack message payload
                payload = {
                    "text": f"*SECURITY ALERT*: {threat['type']} threat detected",
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": f"Security Alert: {threat['type']}"
                            }
                        },
                        {
                            "type": "section",
                            "fields": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Severity:* {threat['severity']}/10 {'★' * threat['severity']}"
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Source:* {threat['source']}"
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Indicator:* {threat['indicator']}"
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Description:* {threat['description']}"
                                }
                            ]
                        },
                        {
                            "type": "context",
                            "elements": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"Detected at {alert['timestamp']}"
                                }
                            ]
                        }
                    ]
                }
                
                # Send to Slack
                response = requests.post(
                    slack_config["webhook_url"],
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code == 200:
                    logger.info(f"Sent Slack alert for threat ID {alert['threat_id']}")
                else:
                    logger.warning(f"Failed to send Slack alert: {response.status_code} - {response.text}")
                    
        except Exception as e:
            logger.error(f"Error sending Slack alerts: {e}")
    
    def take_actions(self, threats, auto_threshold=9):
        """Take automated actions on threats based on severity."""
        actions_taken = []
        
        try:
            # Get high severity threats that haven't had actions taken
            self.cursor.execute('''
                SELECT t.id, t.threat_type, t.source, t.indicator, t.severity, t.description 
                FROM threats t
                LEFT JOIN actions a ON t.id = a.threat_id
                WHERE t.severity >= ? AND a.id IS NULL
                ORDER BY t.severity DESC
            ''', (auto_threshold,))
            
            action_threats = self.cursor.fetchall()
            
            for threat in action_threats:
                threat_id, threat_type, source, indicator, severity, description = threat
                
                # Determine action based on threat type
                action_type = self._determine_action_type(threat_type, indicator)
                
                if action_type:
                    # Execute action
                    status, details = self._execute_action(action_type, threat_type, indicator)
                    
                    # Record action
                    self.cursor.execute('''
                        INSERT INTO actions 
                        (threat_id, action_type, status, details, timestamp) 
                        VALUES (?, ?, ?, ?, ?)
                    ''', (
                        threat_id,
                        action_type,
                        status,
                        details,
                        datetime.now()
                    ))
                    
                    action = {
                        "threat_id": threat_id,
                        "action_type": action_type,
                        "status": status,
                        "details": details,
                        "timestamp": datetime.now()
                    }
                    
                    actions_taken.append(action)
            
            self.conn.commit()
            logger.info(f"Took {len(actions_taken)} automated actions")
            
        except Exception as e:
            logger.error(f"Error taking automated actions: {e}")
            
        return actions_taken
    
    def _determine_action_type(self, threat_type, indicator):
        """Determine appropriate action based on threat type."""
        # IP-based threats
        if self._is_ip_address(indicator):
            if threat_type in ["brute_force_attempt", "malicious_ip", "scanning", "ddos"]:
                return "block_ip"
                
        # URL-based threats
        elif self._is_url(indicator):
            if threat_type in ["malicious_url", "phishing"]:
                return "block_url"
                
        # Domain-based threats
        elif self._is_domain(indicator):
            if threat_type in ["malicious_domain", "c2_server"]:
                return "block_domain"
                
        # File-based threats
        elif self._is_file_hash(indicator):
            if threat_type in ["malware", "ransomware", "trojan"]:
                return "quarantine_file"
                
        # Default - no action
        return None
    
    def _is_ip_address(self, indicator):
        """Check if the indicator is an IP address."""
        import re
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        return bool(ip_pattern.match(indicator))
    
    def _is_url(self, indicator):
        """Check if the indicator is a URL."""
        return indicator.startswith(('http://', 'https://'))
    
    def _is_domain(self, indicator):
        """Check if the indicator is a domain."""
        import re
        domain_pattern = re.compile(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$')
        return bool(domain_pattern.match(indicator))
    
    def _is_file_hash(self, indicator):
        """Check if the indicator is a file hash."""
        import re
        # Match MD5, SHA-1, SHA-256
        hash_pattern = re.compile(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$')
        return bool(hash_pattern.match(indicator))
    
    def _execute_action(self, action_type, threat_type, indicator):
        """Execute the appropriate action based on action type."""
        if action_type == "block_ip":
            return self._block_ip(indicator)
        elif action_type == "block_url":
            return self._block_url(indicator)
        elif action_type == "block_domain":
            return self._block_domain(indicator)
        elif action_type == "quarantine_file":
            return self._quarantine_file(indicator)
        else:
            return "failed", f"Unknown action type: {action_type}"
    
    def _block_ip(self, ip):
        """Block an IP address through firewall integration."""
        try:
            # Check if firewall integration is configured
            if "firewall" not in self.config["integrations"]:
                return "skipped", "Firewall integration not configured"
                
            firewall_config = self.config["integrations"]["firewall"]
            
            # Call firewall API to block IP
            headers = {
                "Authorization": f"Bearer {firewall_config['api_key']}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "action": "block",
                "ip": ip,
                "reason": "ATIP automated response",
                "duration": "24h"  # Block for 24 hours
            }
            
            response = requests.post(
                f"{firewall_config['api_url']}/rules",
                headers=headers,
                json=payload
            )
            
            if response.status_code == 200 or response.status_code == 201:
                return "success", f"IP {ip} blocked for 24 hours"
            else:
                return "failed", f"Failed to block IP: {response.status_code} - {response.text}"
                
        except Exception as e:
            logger.error(f"Error blocking IP {ip}: {e}")
            return "failed", f"Error: {str(e)}"
    
    def _block_url(self, url):
        """Block a URL through web filter integration."""
        try:
            # Simplified implementation - in a real system, this would integrate with a web filter
            logger.info(f"Would block URL: {url}")
            return "simulated", f"URL {url} would be blocked (simulation)"
        except Exception as e:
            logger.error(f"Error blocking URL {url}: {e}")
            return "failed", f"Error: {str(e)}"
    
    def _block_domain(self, domain):
        """Block a domain through DNS filter integration."""
        try:
            # Simplified implementation - in a real system, this would integrate with a DNS filter
            logger.info(f"Would block domain: {domain}")
            return "simulated", f"Domain {domain} would be blocked (simulation)"
        except Exception as e:
            logger.error(f"Error blocking domain {domain}: {e}")
            return "failed", f"Error: {str(e)}"
    
    def _quarantine_file(self, file_hash):
        """Quarantine a file through endpoint protection integration."""
        try:
            # Simplified implementation - in a real system, this would integrate with endpoint protection
            logger.info(f"Would quarantine file with hash: {file_hash}")
            return "simulated", f"File with hash {file_hash} would be quarantined (simulation)"
        except Exception as e:
            logger.error(f"Error quarantining file {file_hash}: {e}")
            return "failed", f"Error: {str(e)}"
    
    def generate_report(self, time_period="24h"):
        """Generate a comprehensive threat intelligence report."""
        try:
            # Calculate time range
            end_time = datetime.now()
            
            if time_period == "24h":
                start_time = end_time - pd.Timedelta(days=1)
            elif time_period == "7d":
                start_time = end_time - pd.Timedelta(days=7)
            elif time_period == "30d":
                start_time = end_time - pd.Timedelta(days=30)
            else:
                start_time = end_time - pd.Timedelta(days=1)  # Default to 24h
                
            # Get threats in the time range
            self.cursor.execute('''
                SELECT id, threat_type, source, indicator, severity, description, timestamp
                FROM threats 
                WHERE timestamp BETWEEN ? AND ?
                ORDER BY timestamp DESC
            ''', (start_time, end_time))
            
            threats = self.cursor.fetchall()
            
            # Get alerts in the time range
            self.cursor.execute('''
                SELECT a.id, a.threat_id, a.alert_type, a.status, a.timestamp
                FROM alerts a
                WHERE a.timestamp BETWEEN ? AND ?
                ORDER BY a.timestamp DESC
            ''', (start_time, end_time))
            
            alerts = self.cursor.fetchall()
            
            # Get actions in the time range
            self.cursor.execute('''
                SELECT a.id, a.threat_id, a.action_type, a.status, a.details, a.timestamp
                FROM actions a
                WHERE a.timestamp BETWEEN ? AND ?
                ORDER BY a.timestamp DESC
            ''', (start_time, end_time))
            
            actions = self.cursor.fetchall()
            
            # Convert to dataframes
            threats_df = pd.DataFrame(threats, columns=['id', 'threat_type', 'source', 'indicator', 'severity', 'description', 'timestamp'])
            alerts_df = pd.DataFrame(alerts, columns=['id', 'threat_id', 'alert_type', 'status', 'timestamp'])
            actions_df = pd.DataFrame(actions, columns=['id', 'threat_id', 'action_type', 'status', 'details', 'timestamp'])
            
            # Generate report
            report = {
                "summary": {
                    "period": time_period,
                    "start_time": start_time,
                    "end_time": end_time,
                    "total_threats": len(threats),
                    "total_alerts": len(alerts),
                    "total_actions": len(actions),
                    "avg_severity": threats_df['severity'].mean() if not threats_df.empty else 0,
                    "high_severity_threats": len(threats_df[threats_df['severity'] >= 8]) if not threats_df.empty else 0
                },
                "threat_breakdown": {
                    "by_type": threats_df['threat_type'].value_counts().to_dict() if not threats_df.empty else {},
                    "by_source": threats_df['source'].value_counts().to_dict() if not threats_df.empty else {},
                    "by_severity": threats_df['severity'].value_counts().to_dict() if not threats_df.empty else {}
                },
                "top_threats": threats_df.sort_values('severity', ascending=False).head(10).to_dict('records') if not threats_df.empty else [],
                "recent_alerts": alerts_df.head(10).to_dict('records') if not alerts_df.empty else [],
                "recent_actions": actions_df.head(10).to_dict('records') if not actions_df.empty else [],
                "hourly_distribution": threats_df['timestamp'].dt.hour.value_counts().sort_index().to_dict() if not threats_df.empty else {}
            }
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return {"error": f"Failed to generate report: {str(e)}"}
    
    def run(self):
        """Run the main platform loop."""
        try:
            while True:
                # 1. Collect threat data
                logger.info("Starting data collection...")
                threats = self.collect_data()
                logger.info(f"Collected {len(threats)} threats")
                
                # 2. Analyze data
                logger.info("Starting data analysis...")
                findings = self.analyze_data()
                logger.info(f"Analysis found {len(findings)} insights")
                
                # 3. Generate alerts
                logger.info("Generating alerts...")
                alerts = self.generate_alerts()
                logger.info(f"Generated {len(alerts)} alerts")
                
                # 4. Send alerts
                if alerts:
                    logger.info("Sending alerts...")
                    self.send_alerts(alerts)
                
                # 5. Take automated actions
                logger.info("Taking automated actions...")
                actions = self.take_actions(threats)
                logger.info(f"Took {len(actions)} actions")
                
                # Sleep for a while before next iteration
                time.sleep(600)  # 10 minutes
                
        except KeyboardInterrupt:
            logger.info("Shutting down ATIP...")
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
        finally:
            if hasattr(self, 'conn'):
                self.conn.close()
