#!/usr/bin/env python3
"""
Master Monitoring Script for Flask App
Integrates all monitoring components: Heroku logs, deployment, local dev, health checks, and notifications
"""

import sys
import os
import argparse
import time
import threading
import json
from datetime import datetime
from typing import Dict, List, Optional

# Add the monitoring directory to the path to import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from heroku_logs import HerokuLogMonitor
from deployment_monitor import DeploymentMonitor
from local_monitor import LocalMonitor
from health_monitor import HealthMonitor, HealthStatus
from notification_system import NotificationSystem, NotificationLevel

class MasterMonitor:
    """Master monitoring system that coordinates all monitoring components"""
    
    def __init__(self, app_name: str = "flask-rest-alm-admin", local_port: int = 3000):
        self.app_name = app_name
        self.local_port = local_port
        
        # Initialize all monitoring components
        self.heroku_monitor = HerokuLogMonitor(app_name)
        self.deployment_monitor = DeploymentMonitor(app_name)
        self.local_monitor = LocalMonitor()
        self.health_monitor = HealthMonitor(app_name, local_port)
        self.notification_system = NotificationSystem()
        
        # Monitoring state
        self.monitoring_active = False
        self.monitor_threads = []
        
        print(f"Master Monitor initialized for app: {app_name}")
        print(f"Notification channels available: {[ch for ch in self.notification_system.enabled_channels]}")
    
    def dashboard_summary(self) -> Dict:
        """Generate a comprehensive dashboard summary"""
        print("Generating comprehensive status dashboard...")
        
        # Get deployment status
        deployment_report = self.deployment_monitor.generate_report()
        
        # Get health status for both environments
        heroku_health = self.health_monitor.run_health_checks("heroku", self.health_monitor.heroku_url)
        local_health = self.health_monitor.run_health_checks("local", self.health_monitor.local_url)
        
        # Get local development status
        local_dev_report = self.local_monitor.generate_development_report()
        
        # Get recent alerts
        recent_alerts = self.health_monitor.get_alert_history(hours=24)
        
        summary = {
            'timestamp': datetime.now().isoformat(),
            'app_name': self.app_name,
            'overall_status': 'healthy',  # Will be determined below
            
            'heroku': {
                'deployment': deployment_report.get('overall_status', {}),
                'health': {
                    'status': heroku_health['overall_status'].value,
                    'success_rate': heroku_health['success_rate'],
                    'avg_response_time': heroku_health.get('avg_response_time')
                }
            },
            
            'local': {
                'development': local_dev_report.get('overall_status', {}),
                'health': {
                    'status': local_health['overall_status'].value,
                    'success_rate': local_health['success_rate'],
                    'avg_response_time': local_health.get('avg_response_time')
                }
            },
            
            'alerts': {
                'recent_count': len(recent_alerts),
                'critical_count': len([a for a in recent_alerts if a.get('severity') == 'critical']),
                'latest_alerts': recent_alerts[:5]  # Last 5 alerts
            },
            
            'monitoring': {
                'notification_channels': len(self.notification_system.enabled_channels),
                'database_accessible': os.path.exists(self.health_monitor.db_path),
                'log_monitoring_available': True
            }
        }
        
        # Determine overall status
        issues = []
        if deployment_report.get('overall_status', {}).get('status') != 'healthy':
            issues.append('deployment')
        if heroku_health['overall_status'] == HealthStatus.CRITICAL:
            issues.append('heroku_health')
        if local_health['overall_status'] == HealthStatus.CRITICAL:
            issues.append('local_health')
        if len([a for a in recent_alerts if a.get('severity') == 'critical']) > 0:
            issues.append('critical_alerts')
        
        if issues:
            summary['overall_status'] = 'issues_detected'
            summary['issues'] = issues
        
        return summary
    
    def print_dashboard(self):
        """Print a formatted dashboard to console"""
        summary = self.dashboard_summary()
        
        print(f"\n{'='*80}")
        print(f"FLASK APP MONITORING DASHBOARD - {summary['timestamp']}")
        print(f"App: {summary['app_name']}")
        print(f"{'='*80}")
        
        # Overall status
        status_emoji = "✅" if summary['overall_status'] == 'healthy' else "⚠️"
        print(f"{status_emoji} Overall Status: {summary['overall_status'].upper()}")
        
        if summary.get('issues'):
            print(f"   Issues detected in: {', '.join(summary['issues'])}")
        
        print(f"\n📊 HEROKU ENVIRONMENT")
        heroku = summary['heroku']
        deploy_status = heroku['deployment'].get('status', 'unknown')
        health_status = heroku['health']['status']
        success_rate = heroku['health']['success_rate']
        response_time = heroku['health'].get('avg_response_time', 0)
        
        deploy_emoji = "✅" if deploy_status == 'healthy' else "❌"
        health_emoji = "✅" if health_status == 'healthy' else "⚠️" if health_status == 'degraded' else "❌"
        
        print(f"   {deploy_emoji} Deployment: {deploy_status}")
        print(f"   {health_emoji} Health: {health_status} ({success_rate:.1%} success)")
        if response_time:
            print(f"   ⏱️  Avg Response: {response_time:.2f}s")
        
        print(f"\n💻 LOCAL DEVELOPMENT")
        local = summary['local']
        local_dev_healthy = local['development'].get('healthy', False)
        local_health_status = local['health']['status']
        local_success_rate = local['health']['success_rate']
        
        dev_emoji = "✅" if local_dev_healthy else "❌"
        local_health_emoji = "✅" if local_health_status == 'healthy' else "⚠️" if local_health_status == 'degraded' else "❌"
        
        print(f"   {dev_emoji} Development Environment: {'healthy' if local_dev_healthy else 'issues'}")
        print(f"   {local_health_emoji} Health: {local_health_status} ({local_success_rate:.1%} success)")
        
        print(f"\n🚨 ALERTS & MONITORING")
        alerts = summary['alerts']
        print(f"   📋 Recent Alerts: {alerts['recent_count']} (last 24h)")
        print(f"   🔥 Critical Alerts: {alerts['critical_count']}")
        print(f"   📡 Notification Channels: {summary['monitoring']['notification_channels']}")
        
        if alerts['latest_alerts']:
            print(f"\n   Latest Alerts:")
            for alert in alerts['latest_alerts'][:3]:
                severity_emoji = "🚨" if alert['severity'] == 'critical' else "⚠️"
                print(f"   {severity_emoji} [{alert['severity']}] {alert['environment']}: {alert['message'][:50]}...")
        
        print(f"\n{'='*80}")
    
    def start_continuous_monitoring(self, intervals: Dict[str, int] = None):
        """Start all monitoring components in continuous mode"""
        if intervals is None:
            intervals = {
                'health_check': 300,    # 5 minutes
                'log_monitoring': True,  # Continuous
                'dashboard_update': 900  # 15 minutes
            }
        
        print("Starting comprehensive monitoring...")
        print(f"Health checks every {intervals['health_check']} seconds")
        print(f"Dashboard updates every {intervals['dashboard_update']} seconds")
        print("Press Ctrl+C to stop all monitoring")
        
        self.monitoring_active = True
        
        # Start health monitoring in a separate thread
        def health_monitoring():
            while self.monitoring_active:
                try:
                    # Check both environments
                    heroku_report = self.health_monitor.run_health_checks("heroku", self.health_monitor.heroku_url)
                    local_report = self.health_monitor.run_health_checks("local", self.health_monitor.local_url)
                    
                    # Analyze and send alerts if needed
                    self.health_monitor.analyze_and_alert(heroku_report)
                    self.health_monitor.analyze_and_alert(local_report)
                    
                    time.sleep(intervals['health_check'])
                except Exception as e:
                    print(f"Health monitoring error: {e}")
                    time.sleep(60)  # Wait before retry
        
        # Start dashboard updates in a separate thread
        def dashboard_monitoring():
            while self.monitoring_active:
                try:
                    self.print_dashboard()
                    time.sleep(intervals['dashboard_update'])
                except Exception as e:
                    print(f"Dashboard monitoring error: {e}")
                    time.sleep(60)  # Wait before retry
        
        # Start monitoring threads
        health_thread = threading.Thread(target=health_monitoring, daemon=True)
        dashboard_thread = threading.Thread(target=dashboard_monitoring, daemon=True)
        
        health_thread.start()
        dashboard_thread.start()
        
        self.monitor_threads = [health_thread, dashboard_thread]
        
        # Start log monitoring (this will block until interrupted)
        if intervals.get('log_monitoring', True):
            try:
                self.heroku_monitor.monitor_logs()
            except KeyboardInterrupt:
                print("\n\nStopping all monitoring...")
                self.monitoring_active = False
        
        # Wait for all threads to finish
        for thread in self.monitor_threads:
            if thread.is_alive():
                thread.join(timeout=5)
    
    def quick_health_check(self):
        """Perform a quick health check of all systems"""
        print("Performing quick health check...")
        
        # Check Heroku health
        print("\n🔍 Checking Heroku environment...")
        heroku_health = self.health_monitor.run_health_checks("heroku", self.health_monitor.heroku_url)
        
        # Check local health
        print("\n🔍 Checking local environment...")
        local_health = self.health_monitor.run_health_checks("local", self.health_monitor.local_url)
        
        # Send summary notification if there are issues
        issues = []
        if heroku_health['overall_status'] == HealthStatus.CRITICAL:
            issues.append(f"Heroku critical ({heroku_health['success_rate']:.1%} success rate)")
        if local_health['overall_status'] == HealthStatus.CRITICAL:
            issues.append(f"Local critical ({local_health['success_rate']:.1%} success rate)")
        
        if issues:
            self.notification_system.send_notification(
                title="Health Check Alert",
                message=f"Issues detected: {', '.join(issues)}",
                level=NotificationLevel.WARNING,
                app_name=self.app_name
            )
        
        print(f"\n✅ Quick health check completed")
        print(f"Heroku: {heroku_health['overall_status'].value}")
        print(f"Local: {local_health['overall_status'].value}")
    
    def deploy_with_monitoring(self, branch: str = "main"):
        """Deploy and monitor the deployment process"""
        print(f"Starting monitored deployment from {branch} branch...")
        
        # Send deployment start notification
        self.notification_system.send_notification(
            title="Deployment Started",
            message=f"Starting deployment from {branch} branch",
            level=NotificationLevel.INFO,
            app_name=self.app_name
        )
        
        # Perform deployment
        deployment_result = self.deployment_monitor.deploy_and_monitor(branch)
        
        # Send deployment completion notification
        if deployment_result['success']:
            self.notification_system.send_notification(
                title="Deployment Successful",
                message=f"Deployment from {branch} completed successfully",
                level=NotificationLevel.INFO,
                details={'duration': f"{deployment_result['start_time']} to {deployment_result['end_time']}"},
                app_name=self.app_name
            )
        else:
            self.notification_system.send_notification(
                title="Deployment Failed",
                message=f"Deployment from {branch} failed",
                level=NotificationLevel.ERROR,
                details=deployment_result,
                app_name=self.app_name
            )
        
        return deployment_result

def main():
    parser = argparse.ArgumentParser(description='Master Flask App Monitor')
    parser.add_argument('--app', '-a', default='flask-rest-alm-admin', help='Heroku app name')
    parser.add_argument('--local-port', type=int, default=3000, help='Local Flask port')
    
    # Mode selection
    parser.add_argument('--dashboard', '-d', action='store_true', help='Show comprehensive dashboard')
    parser.add_argument('--monitor', '-m', action='store_true', help='Start continuous monitoring')
    parser.add_argument('--health', action='store_true', help='Quick health check')
    parser.add_argument('--deploy', help='Deploy from specified branch with monitoring')
    
    # Monitoring intervals
    parser.add_argument('--health-interval', type=int, default=300, help='Health check interval (seconds)')
    parser.add_argument('--dashboard-interval', type=int, default=900, help='Dashboard update interval (seconds)')
    
    # Component-specific options
    parser.add_argument('--heroku-only', action='store_true', help='Monitor Heroku only')
    parser.add_argument('--local-only', action='store_true', help='Monitor local only')
    
    args = parser.parse_args()
    
    monitor = MasterMonitor(args.app, args.local_port)
    
    if args.dashboard:
        monitor.print_dashboard()
        
    elif args.health:
        monitor.quick_health_check()
        
    elif args.deploy:
        result = monitor.deploy_with_monitoring(args.deploy)
        print(f"\nDeployment {'succeeded' if result['success'] else 'failed'}")
        
    elif args.monitor:
        intervals = {
            'health_check': args.health_interval,
            'dashboard_update': args.dashboard_interval,
            'log_monitoring': True
        }
        monitor.start_continuous_monitoring(intervals)
        
    else:
        # Default: show dashboard
        monitor.print_dashboard()

if __name__ == "__main__":
    main()