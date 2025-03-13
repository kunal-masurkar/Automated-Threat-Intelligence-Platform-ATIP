# 🚀 Automated Threat Intelligence Platform (ATIP) Setup Guide

This guide will help you set up and run the Automated Threat Intelligence Platform on your system.

## 🔧 Prerequisites

- 🐍 Python 3.8 or higher
- 📂 SQLite 3
- 🌍 Network access for external threat feeds
- 🔐 Appropriate permissions for system actions (if using firewall integration)

## 📥 Installation Steps

### 1️⃣ Clone or download the ATIP files

Ensure you have all the necessary files in your project directory as per the `app_structure.txt` file.

### 2️⃣ Set up a virtual environment (recommended)

```bash
# Create a virtual environment
python -m venv atip-env

# Activate the virtual environment
# On Windows:
atip-env\Scripts\activate
# On Linux/Mac:
source atip-env/bin/activate
```

### 3️⃣ Install dependencies

```bash
pip install -r requirements.txt
```

### 4️⃣ Configure the platform

Edit the `config.json` file to customize your settings:

- 🔑 Update API keys for threat intelligence sources
- 📧 Configure email/Slack alert settings
- 🔥 Set up firewall and proxy integration settings
- 🎨 Modify web interface settings as needed

### 5️⃣ Initialize the database

```bash
# Basic initialization
python init_database.py

# Or with sample data for testing
python init_database.py --with-sample-data
```

This will create the SQLite database with the required schema and default settings.

### 6️⃣ Create directory structure

Ensure all necessary directories exist:

```bash
mkdir -p templates static/css static/js static/img
mkdir -p modules/collectors modules/analyzers modules/actions modules/alerts
mkdir -p utils tests
```

### 7️⃣ Copy templates to appropriate locations

📁 Place the `dashboard.html` file into the `templates` directory.

## 🚀 Running ATIP

### 🖥️ Command Line Mode

Run the platform from the command line:

```bash
# Run in default mode (continuous monitoring)
python atip-main.py

# Collect threat data only
python atip-main.py --mode collect

# Analyze existing data
python atip-main.py --mode analyze

# Generate a report
python atip-main.py --mode report --report-period 7d --output threat_report.json
```

### 🌐 Web Interface

Start the web interface server:

```bash
python atip-web-interface.py
```

🔗 Access the web interface by opening `http://localhost:5000` in your browser.

🛡️ **Default login credentials:**
- Username: `admin`
- Password: `admin123`

## 📂 Project Structure

- `atip-main.py` 🖥️: Command-line interface for the platform
- `atip-web-interface.py` 🌍: Web interface server
- `atip_core.py` 🛠️: Core functionality of the platform
- `config.json` ⚙️: Configuration settings
- `database_schema.sql` 🗄️: Database schema definition
- `init_database.py` 🔧: Database initialization script
- `templates/` 📁: Web interface HTML templates
- `static/` 🎨: Static files for the web interface

## 🔌 Customization and Extension

To extend the platform with additional modules:

1. 📡 Add new collectors in `modules/collectors/`
2. 🕵️ Create custom analyzers in `modules/analyzers/`
3. 🔥 Implement additional actions in `modules/actions/`
4. 📢 Add new alerting mechanisms in `modules/alerts/`

## 🛠️ Troubleshooting

### ⚠️ Common Issues

- **Database Connection Errors** 🗄️: Check that the database path in `config.json` is correct and the directory is writable.
- **API Key Errors** 🔑: Verify that you've entered valid API keys for all enabled threat intelligence sources.
- **Permission Issues** 🔥: When using firewall integration, ensure the application has sufficient permissions.

### 📜 Logs

Check the application logs (default: `atip.log`) for detailed error information.

## 🔒 Security Notes

- 🛑 Change the default admin password immediately after setup
- 🔐 Secure your API keys in the configuration file
- 🌐 Consider running the web interface behind a reverse proxy with HTTPS for production use
- 👨‍💻 Restrict access to the platform to authorized personnel only

## 🏆 Author

🌐 [GitHub](https://github.com/kunal-masurkar) <br> 👉 [LinkedIn](https://linkedin.com/in/kunal-masurkar-8494a123a)

