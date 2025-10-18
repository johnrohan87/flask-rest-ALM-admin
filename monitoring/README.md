# Flask App Monitoring System

A comprehensive monitoring system for your Flask REST API with Heroku hosting, featuring real-time log monitoring, health checks, deployment tracking, and multi-channel notifications.

## Features

### 🔍 **Complete Monitoring Coverage**
- **Heroku Log Monitoring**: Real-time log analysis with pattern matching for errors, warnings, database issues, authentication, and performance metrics
- **Deployment Monitoring**: Automated deployment tracking with pre/post health checks and rollback detection
- **Local Development Monitoring**: Flask server monitoring, database connectivity checks, file change tracking, and Pipenv environment validation
- **Health Check System**: Periodic endpoint testing with response time monitoring and availability tracking
- **Smart Notifications**: Multi-channel alerts (Email, Slack, Discord, Webhooks) with cooldown periods to prevent spam

### 📊 **Integrated Dashboard**
- Real-time status overview of all environments
- Historical health data and alert tracking
- Performance metrics and trend analysis
- One-command deployment with full monitoring

## Installation

### 1. Install Dependencies

The monitoring system requires additional Python packages. Install them using pipenv:

```bash
# Install required monitoring dependencies
pip install requests psutil watchdog
```

### 2. Set Up Notification Channels (Optional)

Create notification configuration by generating a sample file:

```bash
cd monitoring/
python notification_system.py --sample-config
```

This creates `notification-config.env.sample`. Copy the relevant settings to your main `.env` file:

```bash
# Email Notifications (Gmail example)
NOTIFICATION_SMTP_SERVER=smtp.gmail.com
NOTIFICATION_SMTP_PORT=587
NOTIFICATION_EMAIL_USERNAME=your-email@gmail.com
NOTIFICATION_EMAIL_PASSWORD=your-app-password
NOTIFICATION_EMAIL_FROM=your-email@gmail.com
NOTIFICATION_EMAIL_TO=admin@example.com,dev@example.com

# Slack Notifications (optional)
NOTIFICATION_SLACK_WEBHOOK=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
NOTIFICATION_SLACK_CHANNEL=#monitoring

# Discord Notifications (optional)
NOTIFICATION_DISCORD_WEBHOOK=https://discord.com/api/webhooks/YOUR/DISCORD/WEBHOOK
```

### 3. Make Scripts Executable

```bash
chmod +x monitoring/*.py
```

## Quick Start

### 🚀 **One-Command Dashboard**
```bash
# Show comprehensive status dashboard
python monitoring/monitor.py --dashboard

# Or just run the master monitor (default action)
python monitoring/monitor.py
```

### 🔍 **Quick Health Check**
```bash
# Check all systems quickly
python monitoring/monitor.py --health
```

### 📺 **Start Continuous Monitoring**
```bash
# Start full monitoring (logs, health checks, dashboard)
python monitoring/monitor.py --monitor

# Custom intervals (health every 2min, dashboard every 10min)
python monitoring/monitor.py --monitor --health-interval 120 --dashboard-interval 600
```

### 🚀 **Monitored Deployment**
```bash
# Deploy with full monitoring and notifications
python monitoring/monitor.py --deploy main
```

## Individual Component Usage

### Heroku Log Monitoring
```bash
# Real-time log monitoring with filtering
python monitoring/heroku_logs.py

# Check app status and recent deployments
python monitoring/heroku_logs.py --status
python monitoring/heroku_logs.py --releases

# Filter by specific dyno
python monitoring/heroku_logs.py --dyno web.1
```

### Deployment Monitoring
```bash
# Full deployment report
python monitoring/deployment_monitor.py --report

# Health checks only
python monitoring/deployment_monitor.py --health

# Deploy and monitor
python monitoring/deployment_monitor.py --deploy main

# Watch mode (continuous monitoring)
python monitoring/deployment_monitor.py --watch 60
```

### Local Development Monitoring
```bash
# Generate development environment report
python monitoring/local_monitor.py --report

# Start Flask server with monitoring
python monitoring/local_monitor.py --start

# Continuous monitoring (with file watching)
python monitoring/local_monitor.py

# Monitor without file changes (lighter)
python monitoring/local_monitor.py --no-files
```

### Health Check Monitoring
```bash
# Single health check
python monitoring/health_monitor.py --single-check

# Continuous monitoring (1-minute intervals)
python monitoring/health_monitor.py --interval 60

# Check only Heroku environment
python monitoring/health_monitor.py --heroku-only

# View health history (last 24 hours)
python monitoring/health_monitor.py --history 24

# View alert history
python monitoring/health_monitor.py --alerts 24
```

### Notification System
```bash
# Test all configured notification channels
python monitoring/notification_system.py --test

# Check configuration status
python monitoring/notification_system.py --status

# Send custom test notification
python monitoring/notification_system.py --send "Test message" --level warning
```

## Configuration

### Environment Variables

The monitoring system uses these environment variables from your `.env` file:

#### Flask App Configuration
- `DB_CONNECTION_STRING`: Database connection for connectivity checks
- `AUTH0_DOMAIN`, `JWT_SECRET_KEY`, `API_AUDIENCE`: For authentication monitoring

#### Notification Configuration (Optional)
- `NOTIFICATION_EMAIL_*`: Email notification settings
- `NOTIFICATION_SLACK_*`: Slack webhook settings  
- `NOTIFICATION_DISCORD_WEBHOOK`: Discord webhook URL
- `NOTIFICATION_CUSTOM_WEBHOOK`: Custom webhook URL

### Health Check Endpoints

The system monitors these endpoints by default:
- `/` - Root endpoint
- `/admin/` - Admin interface (requires database)
- `/feeds` - API endpoints (add more in health_monitor.py)

You can customize endpoints by editing the `endpoints` dictionary in `health_monitor.py`.

## Monitoring Data Storage

The system stores monitoring data in SQLite databases:
- `monitoring/health_history.db` - Health check results and alert history
- `monitoring/notifications.log` - Notification log file

## Understanding the Dashboard

The integrated dashboard shows:

### Overall Status
- ✅ **Healthy**: All systems operating normally
- ⚠️ **Issues Detected**: Some components have problems

### Heroku Environment
- **Deployment Status**: Current release and dyno status
- **Health Status**: Endpoint availability and performance
- **Response Times**: Average response time monitoring

### Local Development
- **Development Environment**: Pipenv, server, and database status
- **Health Status**: Local endpoint monitoring
- **File Changes**: Recent code changes (when file monitoring is active)

### Alerts & Monitoring
- **Recent Alerts**: Count of alerts in last 24 hours
- **Critical Alerts**: High-priority issues requiring attention
- **Notification Channels**: Number of configured alert channels

## Troubleshooting

### Common Issues

**Heroku CLI not found**
```bash
# Install Heroku CLI
curl https://cli-assets.heroku.com/install.sh | sh
heroku login
```

**Module import errors**
```bash
# Ensure you're in the project root directory
cd /path/to/flask-rest-ALM-admin
python monitoring/monitor.py
```

**Local server connection errors**
```bash
# Start your Flask development server first
pipenv run start
# Then run monitoring in another terminal
python monitoring/monitor.py --health
```

**Email notifications not working**
- For Gmail: Use App Passwords, not your regular password
- Ensure "Less secure app access" is enabled, or use OAuth2

### Debug Mode

Add debug output by modifying the scripts:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Integration with Development Workflow

### Pre-deployment Check
```bash
# Before deploying, check system health
python monitoring/monitor.py --health
```

### Post-deployment Verification
```bash
# After deployment, monitor for issues
python monitoring/deployment_monitor.py --watch 60
```

### Development Workflow
```bash
# Start monitoring in development
python monitoring/local_monitor.py &
pipenv run start
```

## Extending the System

### Adding New Health Endpoints
Edit `monitoring/health_monitor.py`:
```python
self.endpoints = {
    'root': '/',
    'admin': '/admin/',
    'feeds': '/feeds',
    'custom_endpoint': '/api/custom'  # Add your endpoint
}
```

### Custom Notification Channels
Extend `monitoring/notification_system.py` by adding new channel types to the `NotificationChannel` enum and implementing the corresponding send method.

### Additional Log Patterns
Edit `monitoring/heroku_logs.py` to add custom log pattern matching:
```python
self.log_patterns = {
    'custom_pattern': [
        r'your_custom_pattern',
        r'another_pattern'
    ]
}
```

## Support

This monitoring system is designed to work specifically with your Flask REST ALM Admin application. The configuration is based on your project structure as defined in `WARP.md`.

For issues or customizations, check the individual script files - they contain detailed error messages and configuration options.