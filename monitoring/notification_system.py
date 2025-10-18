#!/usr/bin/env python3
"""
Notification System for Flask App Monitoring
Supports multiple notification channels: email, Slack, Discord, SMS, etc.
"""

import smtplib
import json
import requests
import os
from datetime import datetime
from typing import Dict, List, Optional, Any
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import argparse
from dataclasses import dataclass
from enum import Enum

class NotificationLevel(Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class NotificationChannel(Enum):
    EMAIL = "email"
    SLACK = "slack"
    DISCORD = "discord"
    WEBHOOK = "webhook"
    FILE = "file"

@dataclass
class NotificationConfig:
    """Configuration for different notification channels"""
    
    # Email configuration
    smtp_server: str = ""
    smtp_port: int = 587
    email_username: str = ""
    email_password: str = ""
    email_from: str = ""
    email_to: List[str] = None
    
    # Slack configuration
    slack_webhook_url: str = ""
    slack_channel: str = "#monitoring"
    slack_username: str = "Flask Monitor"
    
    # Discord configuration
    discord_webhook_url: str = ""
    
    # Custom webhook configuration
    custom_webhook_url: str = ""
    
    # File logging
    log_file_path: str = "monitoring/notifications.log"
    
    def __post_init__(self):
        if self.email_to is None:
            self.email_to = []

class NotificationSystem:
    def __init__(self, config: NotificationConfig = None):
        self.config = config or self.load_config_from_env()
        self.enabled_channels = self.detect_enabled_channels()
        
    def load_config_from_env(self) -> NotificationConfig:
        """Load configuration from environment variables"""
        return NotificationConfig(
            # Email
            smtp_server=os.environ.get('NOTIFICATION_SMTP_SERVER', 'smtp.gmail.com'),
            smtp_port=int(os.environ.get('NOTIFICATION_SMTP_PORT', '587')),
            email_username=os.environ.get('NOTIFICATION_EMAIL_USERNAME', ''),
            email_password=os.environ.get('NOTIFICATION_EMAIL_PASSWORD', ''),
            email_from=os.environ.get('NOTIFICATION_EMAIL_FROM', ''),
            email_to=os.environ.get('NOTIFICATION_EMAIL_TO', '').split(',') if os.environ.get('NOTIFICATION_EMAIL_TO') else [],
            
            # Slack
            slack_webhook_url=os.environ.get('NOTIFICATION_SLACK_WEBHOOK', ''),
            slack_channel=os.environ.get('NOTIFICATION_SLACK_CHANNEL', '#monitoring'),
            slack_username=os.environ.get('NOTIFICATION_SLACK_USERNAME', 'Flask Monitor'),
            
            # Discord
            discord_webhook_url=os.environ.get('NOTIFICATION_DISCORD_WEBHOOK', ''),
            
            # Custom webhook
            custom_webhook_url=os.environ.get('NOTIFICATION_CUSTOM_WEBHOOK', ''),
            
            # File logging
            log_file_path=os.environ.get('NOTIFICATION_LOG_FILE', 'monitoring/notifications.log')
        )
    
    def detect_enabled_channels(self) -> List[NotificationChannel]:
        """Detect which notification channels are properly configured"""
        channels = []
        
        # Check email
        if all([self.config.smtp_server, self.config.email_username, 
                self.config.email_password, self.config.email_from, 
                self.config.email_to]):
            channels.append(NotificationChannel.EMAIL)
        
        # Check Slack
        if self.config.slack_webhook_url:
            channels.append(NotificationChannel.SLACK)
        
        # Check Discord
        if self.config.discord_webhook_url:
            channels.append(NotificationChannel.DISCORD)
        
        # Check custom webhook
        if self.config.custom_webhook_url:
            channels.append(NotificationChannel.WEBHOOK)
        
        # File logging is always available
        channels.append(NotificationChannel.FILE)
        
        return channels
    
    def format_message(self, title: str, message: str, level: NotificationLevel, 
                      details: Dict = None, app_name: str = "Flask App") -> Dict[str, str]:
        """Format message for different channels"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Determine emoji based on level
        level_emojis = {
            NotificationLevel.INFO: "ℹ️",
            NotificationLevel.WARNING: "⚠️",
            NotificationLevel.ERROR: "❌",
            NotificationLevel.CRITICAL: "🚨"
        }
        
        emoji = level_emojis.get(level, "📢")
        
        # Basic text format
        text_message = f"{emoji} [{level.value.upper()}] {app_name}\n\n{title}\n\n{message}"
        if details:
            text_message += f"\n\nDetails:\n{json.dumps(details, indent=2)}"
        text_message += f"\n\nTime: {timestamp}"
        
        # HTML format for email
        html_message = f"""
        <html>
        <body>
        <h2>{emoji} {app_name} Alert - {level.value.upper()}</h2>
        <p><strong>Time:</strong> {timestamp}</p>
        <p><strong>Title:</strong> {title}</p>
        <p><strong>Message:</strong></p>
        <p>{message}</p>
        """
        
        if details:
            html_message += "<p><strong>Details:</strong></p><pre>{}</pre>".format(
                json.dumps(details, indent=2)
            )
        
        html_message += "</body></html>"
        
        return {
            'text': text_message,
            'html': html_message,
            'title': f"{app_name} - {title}",
            'level': level.value,
            'emoji': emoji,
            'timestamp': timestamp
        }
    
    def send_email(self, formatted_message: Dict[str, str]):
        """Send email notification"""
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = formatted_message['title']
            msg['From'] = self.config.email_from
            msg['To'] = ', '.join(self.config.email_to)
            
            # Add both plain text and HTML versions
            text_part = MIMEText(formatted_message['text'], 'plain')
            html_part = MIMEText(formatted_message['html'], 'html')
            
            msg.attach(text_part)
            msg.attach(html_part)
            
            # Connect and send
            server = smtplib.SMTP(self.config.smtp_server, self.config.smtp_port)
            server.starttls()
            server.login(self.config.email_username, self.config.email_password)
            server.send_message(msg)
            server.quit()
            
            return True, "Email sent successfully"
            
        except Exception as e:
            return False, f"Email sending failed: {str(e)}"
    
    def send_slack(self, formatted_message: Dict[str, str]):
        """Send Slack notification"""
        try:
            # Determine color based on level
            level_colors = {
                'info': '#36a64f',      # Green
                'warning': '#ff9500',   # Orange
                'error': '#ff0000',     # Red
                'critical': '#800000'   # Dark red
            }
            
            payload = {
                'channel': self.config.slack_channel,
                'username': self.config.slack_username,
                'attachments': [{
                    'color': level_colors.get(formatted_message['level'], '#808080'),
                    'title': formatted_message['title'],
                    'text': formatted_message['text'],
                    'footer': 'Flask App Monitoring',
                    'ts': datetime.now().timestamp()
                }]
            }
            
            response = requests.post(
                self.config.slack_webhook_url,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                return True, "Slack message sent successfully"
            else:
                return False, f"Slack sending failed with status {response.status_code}"
                
        except Exception as e:
            return False, f"Slack sending failed: {str(e)}"
    
    def send_discord(self, formatted_message: Dict[str, str]):
        """Send Discord notification"""
        try:
            # Determine color based on level (decimal format for Discord)
            level_colors = {
                'info': 3581519,    # Green
                'warning': 16749056, # Orange
                'error': 16711680,   # Red
                'critical': 8388608  # Dark red
            }
            
            embed = {
                'title': formatted_message['title'],
                'description': formatted_message['text'][:2000],  # Discord limit
                'color': level_colors.get(formatted_message['level'], 8421504),  # Gray
                'timestamp': datetime.now().isoformat(),
                'footer': {
                    'text': 'Flask App Monitoring'
                }
            }
            
            payload = {
                'embeds': [embed]
            }
            
            response = requests.post(
                self.config.discord_webhook_url,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 204:  # Discord returns 204 for success
                return True, "Discord message sent successfully"
            else:
                return False, f"Discord sending failed with status {response.status_code}"
                
        except Exception as e:
            return False, f"Discord sending failed: {str(e)}"
    
    def send_webhook(self, formatted_message: Dict[str, str]):
        """Send custom webhook notification"""
        try:
            payload = {
                'title': formatted_message['title'],
                'message': formatted_message['text'],
                'level': formatted_message['level'],
                'timestamp': formatted_message['timestamp'],
                'app': 'flask-rest-alm-admin'
            }
            
            response = requests.post(
                self.config.custom_webhook_url,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                return True, "Webhook sent successfully"
            else:
                return False, f"Webhook sending failed with status {response.status_code}"
                
        except Exception as e:
            return False, f"Webhook sending failed: {str(e)}"
    
    def log_to_file(self, formatted_message: Dict[str, str]):
        """Log notification to file"""
        try:
            os.makedirs(os.path.dirname(self.config.log_file_path), exist_ok=True)
            
            log_entry = {
                'timestamp': formatted_message['timestamp'],
                'level': formatted_message['level'],
                'title': formatted_message['title'],
                'message': formatted_message['text']
            }
            
            with open(self.config.log_file_path, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
            
            return True, "Logged to file successfully"
            
        except Exception as e:
            return False, f"File logging failed: {str(e)}"
    
    def send_notification(self, title: str, message: str, level: NotificationLevel = NotificationLevel.INFO,
                         details: Dict = None, app_name: str = "Flask App",
                         channels: List[NotificationChannel] = None):
        """Send notification through specified channels"""
        
        if not channels:
            channels = self.enabled_channels
        
        formatted_message = self.format_message(title, message, level, details, app_name)
        results = {}
        
        for channel in channels:
            if channel not in self.enabled_channels:
                results[channel.value] = (False, "Channel not configured")
                continue
            
            try:
                if channel == NotificationChannel.EMAIL:
                    success, msg = self.send_email(formatted_message)
                elif channel == NotificationChannel.SLACK:
                    success, msg = self.send_slack(formatted_message)
                elif channel == NotificationChannel.DISCORD:
                    success, msg = self.send_discord(formatted_message)
                elif channel == NotificationChannel.WEBHOOK:
                    success, msg = self.send_webhook(formatted_message)
                elif channel == NotificationChannel.FILE:
                    success, msg = self.log_to_file(formatted_message)
                else:
                    success, msg = False, "Unknown channel"
                
                results[channel.value] = (success, msg)
                
            except Exception as e:
                results[channel.value] = (False, f"Unexpected error: {str(e)}")
        
        return results
    
    def test_all_channels(self):
        """Test all configured notification channels"""
        print("Testing notification channels...")
        
        test_title = "Notification System Test"
        test_message = "This is a test message to verify notification channels are working correctly."
        
        results = self.send_notification(
            title=test_title,
            message=test_message,
            level=NotificationLevel.INFO,
            app_name="Flask Test"
        )
        
        print("\nTest Results:")
        for channel, (success, message) in results.items():
            status = "✅ SUCCESS" if success else "❌ FAILED"
            print(f"{status} {channel}: {message}")
        
        return results
    
    def get_configuration_status(self) -> Dict[str, Any]:
        """Get current configuration status"""
        return {
            'enabled_channels': [ch.value for ch in self.enabled_channels],
            'configuration': {
                'email_configured': bool(self.config.email_username and self.config.email_password),
                'slack_configured': bool(self.config.slack_webhook_url),
                'discord_configured': bool(self.config.discord_webhook_url),
                'webhook_configured': bool(self.config.custom_webhook_url),
                'file_logging_enabled': True,
                'email_recipients': len(self.config.email_to),
                'log_file_path': self.config.log_file_path
            }
        }

def create_sample_env_file():
    """Create a sample .env file with notification configuration"""
    sample_env = """
# Flask App Monitoring Notification Configuration

# Email Notifications (Gmail example)
NOTIFICATION_SMTP_SERVER=smtp.gmail.com
NOTIFICATION_SMTP_PORT=587
NOTIFICATION_EMAIL_USERNAME=your-email@gmail.com
NOTIFICATION_EMAIL_PASSWORD=your-app-password
NOTIFICATION_EMAIL_FROM=your-email@gmail.com
NOTIFICATION_EMAIL_TO=admin@example.com,dev@example.com

# Slack Notifications
NOTIFICATION_SLACK_WEBHOOK=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
NOTIFICATION_SLACK_CHANNEL=#monitoring
NOTIFICATION_SLACK_USERNAME=Flask Monitor

# Discord Notifications
NOTIFICATION_DISCORD_WEBHOOK=https://discord.com/api/webhooks/YOUR/DISCORD/WEBHOOK

# Custom Webhook
NOTIFICATION_CUSTOM_WEBHOOK=https://your-custom-webhook.com/notify

# File Logging
NOTIFICATION_LOG_FILE=monitoring/notifications.log
"""
    
    with open('notification-config.env.sample', 'w') as f:
        f.write(sample_env.strip())
    
    print("Sample notification configuration saved to: notification-config.env.sample")
    print("Copy this to your .env file and update with your actual credentials.")

def main():
    parser = argparse.ArgumentParser(description='Flask App Notification System')
    parser.add_argument('--test', '-t', action='store_true', help='Test all notification channels')
    parser.add_argument('--status', '-s', action='store_true', help='Show configuration status')
    parser.add_argument('--sample-config', action='store_true', help='Create sample configuration file')
    parser.add_argument('--send', help='Send test notification with custom message')
    parser.add_argument('--level', choices=['info', 'warning', 'error', 'critical'], 
                       default='info', help='Notification level for test message')
    
    args = parser.parse_args()
    
    if args.sample_config:
        create_sample_env_file()
        return
    
    notification_system = NotificationSystem()
    
    if args.status:
        status = notification_system.get_configuration_status()
        print("Notification System Status:")
        print(json.dumps(status, indent=2))
        
    elif args.test:
        notification_system.test_all_channels()
        
    elif args.send:
        level = NotificationLevel(args.level)
        results = notification_system.send_notification(
            title="Manual Test Notification",
            message=args.send,
            level=level,
            app_name="Flask Manual Test"
        )
        
        print("Send Results:")
        for channel, (success, message) in results.items():
            status = "✅" if success else "❌"
            print(f"{status} {channel}: {message}")
    
    else:
        print("Flask App Notification System")
        print("Use --help to see available commands")
        print("Use --sample-config to create a sample configuration file")

if __name__ == "__main__":
    main()