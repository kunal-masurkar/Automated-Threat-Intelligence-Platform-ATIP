import sqlite3
import os
import logging
import json
import sys
from datetime import datetime, timedelta
import random
import hashlib

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("atip-init")

def init_database():
    """Initialize the ATIP database with schema and default data."""
    try:
        # Load configuration
        with open('config.json', 'r') as f:
            config = json.load(f)
        
        db_path = config['database']['path']
        
        # Check if database already exists
        db_exists = os.path.exists(db_path)
        
        if db_exists:
            logger.warning(f"Database already exists at {db_path}")
            while True:
                choice = input("Do you want to reinitialize the database? This will delete all existing data. (y/n): ").lower()
                if choice == 'y':
                    logger.info("Reinitializing database...")
                    os.remove(db_path)
                    break
                elif choice == 'n':
                    logger.info("Keeping existing database.")
                    return
                else:
                    print("Please enter 'y' or 'n'.")
        
        # Connect to database
        conn = sqlite3.connect(db_path)
        logger.info(f"Connected to database at {db_path}")
        
        # Read schema file
        with open('database_schema.sql', 'r') as f:
            schema = f.read()
        
        # Execute schema script
        conn.executescript(schema)
        conn.commit()
        logger.info("Database schema created successfully")
        
        # Insert default data for testing
        if '--with-sample-data' in sys.argv:
            insert_sample_data(conn)
            logger.info("Sample data inserted successfully")
        
        # Insert sources from config
        cursor = conn.cursor()
        for source in config['sources']:
            cursor.execute(
                "INSERT INTO sources (name, type, description, config, enabled) VALUES (?, ?, ?, ?, ?)",
                (
                    source['name'],
                    source['type'],
                    source.get('name', ''),
                    json.dumps(source),
                    source.get('enabled', True)
                )
            )
        conn.commit()
        logger.info(f"Inserted {len(config['sources'])} intelligence sources")
        
        # Insert default admin user
        password_hash = hashlib.sha256("admin123".encode()).hexdigest()
        cursor.execute(
            "INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)",
            ("admin", password_hash, "admin@example.com", "admin")
        )
        conn.commit()
        logger.info("Created default admin user (username: admin, password: admin123)")
        
        conn.close()
        logger.info("Database initialization complete!")
        
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        sys.exit(1)

def insert_sample_data(conn):
    """Insert sample threat data for testing."""
    cursor = conn.cursor()
    
    # Sample threat types
    threat_types = ["malicious_ip", "phishing_url", "malicious_domain", "malware_hash", "vulnerability", "unusual_activity"]
    
    # Sample sources
    sources = ["AlienVault OTX", "AbuseIPDB", "PhishTank", "Emerging Threats", "Local Network Scanner"]
    
    # Sample indicators
    malicious_ips = [
        "192.168.1.10", "10.0.0.15", "172.16.0.20", 
        "185.143.223.17", "45.227.253.98", "103.55.38.112",
        "89.44.9.243", "185.176.27.132", "77.91.102.45"
    ]
    
    phishing_urls = [
        "http://fakebook-login.com/secure", 
        "https://drive-docs.tk/document", 
        "http://account-verify-apple.com/login",
        "https://secure.bank-of-amerrica.com/signin",
        "http://paypa1-secure.com/verify",
        "https://accounts.g00gle.com/login"
    ]
    
    malicious_domains = [
        "malware-host.xyz", 
        "cryptominer.club", 
        "trojan-delivery.info",
        "ransomware-service.cc",
        "botnet-controller.net",
        "fake-antivirus.org"
    ]
    
    # Generate random timestamps for the last 7 days
    now = datetime.now()
    timestamps = []
    for i in range(100):
        random_hours = random.randint(0, 168)  # 7 days in hours
        timestamp = now - timedelta(hours=random_hours)
        timestamps.append(timestamp)
    
    # Insert threats
    threats = []
    for i in range(50):
        threat_type = random.choice(threat_types)
        
        # Select appropriate indicator based on threat type
        if threat_type == "malicious_ip":
            indicator = random.choice(malicious_ips)
        elif threat_type == "phishing_url":
            indicator = random.choice(phishing_urls)
        elif threat_type == "malicious_domain":
            indicator = random.choice(malicious_domains)
        else:
            # Generic indicator for other types
            indicator = f"sample-indicator-{i+1}"
        
        severity = random.randint(1, 10)
        confidence = random.randint(5, 10)
        source = random.choice(sources)
        timestamp = random.choice(timestamps)
        
        description = f"Sample {threat_type} detected from {source}"
        metadata = json.dumps({
            "sample": True,
            "tags": ["test", "sample", threat_type]
        })
        
        threats.append((threat_type, indicator, source, severity, confidence, description, metadata, timestamp))
    
    cursor.executemany(
        "INSERT INTO threats (threat_type, indicator, source, severity, confidence, description, metadata, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        threats
    )
    
    # Insert alerts
    alerts = []
    for i in range(20):
        alert_type = "new_threat" if i % 3 == 0 else "threshold_exceeded" if i % 3 == 1 else "unusual_activity"
        severity = random.randint(3, 10)
        title = f"Sample Alert {i+1}"
        description = f"This is a sample {alert_type} alert for testing"
        related_threats = json.dumps([random.randint(1, 50) for _ in range(random.randint(1, 3))])
        status = "new" if i % 4 == 0 else "acknowledged" if i % 4 == 1 else "resolved"
        timestamp = random.choice(timestamps)
        
        alerts.append((alert_type, severity, title, description, related_threats, status, None, None, None, None, timestamp))
    
    cursor.executemany(
        "INSERT INTO alerts (alert_type, severity, title, description, related_threats, status, acknowledged_by, acknowledged_at, resolved_by, resolved_at, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        alerts
    )
    
    # Insert actions
    actions = []
    for i in range(15):
        action_type = "block_ip" if i % 3 == 0 else "update_firewall" if i % 3 == 1 else "block_domain"
        target = random.choice(malicious_ips) if action_type == "block_ip" else random.choice(malicious_domains)
        status = "success" if i % 5 != 0 else "failure"
        details = "Action completed successfully" if status == "success" else "Failed to execute action"
        triggered_by = "auto" if i % 2 == 0 else "admin"
        related_threat_id = random.randint(1, 50)
        related_alert_id = random.randint(1, 20) if i % 3 == 0 else None
        timestamp = random.choice(timestamps)
        
        actions.append((action_type, target, status, details, triggered_by, related_threat_id, related_alert_id, timestamp))
    
    cursor.executemany(
        "INSERT INTO actions (action_type, target, status, details, triggered_by, related_threat_id, related_alert_id, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        actions
    )
    
    conn.commit()

if __name__ == "__main__":
    init_database()
