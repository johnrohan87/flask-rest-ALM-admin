#!/usr/bin/env python3
"""
Health Check Monitoring Script
Periodically checks application endpoints, database connectivity, and sends alerts
"""

import requests
import time
import json
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import argparse
import sqlite3
import os
from dataclasses import dataclass, asdict
from enum import Enum

class HealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    UNKNOWN = "unknown"

@dataclass
class HealthCheckResult:
    endpoint: str
    status: HealthStatus
    response_time: Optional[float]
    status_code: Optional[int]
    error: Optional[str]
    timestamp: str
    details: Optional[Dict] = None

class HealthMonitor:
    def __init__(self, app_name: str = "flask-rest-alm-admin", local_port: int = 3000):
        self.app_name = app_name
        self.heroku_url = f"https://{app_name}.herokuapp.com"
        self.local_url = f"http://localhost:{local_port}"
        
        # Initialize SQLite database for storing health history
        self.db_path = os.path.join(os.getcwd(), "monitoring", "health_history.db")
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.init_database()
        
        # Define health check endpoints based on your Flask app structure
        self.endpoints = {
            'root': '/',
            'admin': '/admin/',
            'feeds': '/feeds',  # Add more based on your actual endpoints
        }
        
        # Thresholds for health determination
        self.thresholds = {
            'response_time_warning': 2.0,  # seconds
            'response_time_critical': 5.0,  # seconds
            'success_rate_warning': 0.8,   # 80%
            'success_rate_critical': 0.5,  # 50%
        }
        
        # Alert history to prevent spam
        self.alert_history = {}
        self.alert_cooldown = timedelta(minutes=15)  # Cooldown between similar alerts

    def init_database(self):
        """Initialize SQLite database for health history"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS health_checks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    status TEXT NOT NULL,
                    response_time REAL,
                    status_code INTEGER,
                    error TEXT,
                    details TEXT
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    message TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    environment TEXT NOT NULL
                )
            ''')

    def save_health_result(self, environment: str, result: HealthCheckResult):
        """Save health check result to database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO health_checks (timestamp, environment, endpoint, status, 
                                         response_time, status_code, error, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                result.timestamp, environment, result.endpoint, result.status.value,
                result.response_time, result.status_code, result.error,
                json.dumps(result.details) if result.details else None
            ))

    def save_alert(self, alert_type: str, message: str, severity: str, environment: str):
        """Save alert to database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO alerts (timestamp, alert_type, message, severity, environment)
                VALUES (?, ?, ?, ?, ?)
            ''', (datetime.now().isoformat(), alert_type, message, severity, environment))

    def check_endpoint(self, base_url: str, endpoint: str, timeout: int = 30) -> HealthCheckResult:
        """Perform health check on a specific endpoint"""
        url = f"{base_url}{endpoint}"
        timestamp = datetime.now().isoformat()
        
        try:
            start_time = time.time()
            response = requests.get(url, timeout=timeout)
            response_time = time.time() - start_time
            
            # Determine status based on response
            if response.status_code == 200:
                if response_time > self.thresholds['response_time_critical']:
                    status = HealthStatus.CRITICAL
                elif response_time > self.thresholds['response_time_warning']:
                    status = HealthStatus.DEGRADED
                else:
                    status = HealthStatus.HEALTHY
            elif 400 <= response.status_code < 500:
                status = HealthStatus.DEGRADED
            else:
                status = HealthStatus.CRITICAL
            
            return HealthCheckResult(
                endpoint=endpoint,
                status=status,
                response_time=response_time,
                status_code=response.status_code,
                error=None,
                timestamp=timestamp,
                details={
                    'url': url,
                    'content_length': len(response.content),
                    'headers': dict(response.headers)
                }
            )
            
        except requests.exceptions.Timeout:
            return HealthCheckResult(
                endpoint=endpoint,
                status=HealthStatus.CRITICAL,
                response_time=None,
                status_code=None,
                error="Request timeout",
                timestamp=timestamp,
                details={'url': url}
            )
            
        except requests.exceptions.ConnectionError:
            return HealthCheckResult(
                endpoint=endpoint,
                status=HealthStatus.CRITICAL,
                response_time=None,
                status_code=None,
                error="Connection error - service may be down",
                timestamp=timestamp,
                details={'url': url}
            )
            
        except Exception as e:
            return HealthCheckResult(
                endpoint=endpoint,
                status=HealthStatus.CRITICAL,
                response_time=None,
                status_code=None,
                error=str(e),
                timestamp=timestamp,
                details={'url': url}
            )

    def check_heroku_dyno_status(self) -> Dict:
        """Check Heroku dyno status"""
        try:
            result = subprocess.run(
                ['heroku', 'ps', '-a', self.app_name],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                output = result.stdout.strip()
                if 'up' in output.lower():
                    return {'status': 'running', 'details': output}
                elif 'crashed' in output.lower():
                    return {'status': 'crashed', 'details': output}
                elif 'idle' in output.lower():
                    return {'status': 'idle', 'details': output}
                else:
                    return {'status': 'unknown', 'details': output}
            else:
                return {'status': 'error', 'error': result.stderr}
                
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    def run_health_checks(self, environment: str, base_url: str) -> Dict:
        """Run health checks for all endpoints"""
        results = []
        overall_status = HealthStatus.HEALTHY
        
        print(f"Running health checks for {environment} ({base_url})...")
        
        for endpoint_name, endpoint_path in self.endpoints.items():
            result = self.check_endpoint(base_url, endpoint_path)
            results.append(result)
            
            # Save to database
            self.save_health_result(environment, result)
            
            # Update overall status
            if result.status == HealthStatus.CRITICAL:
                overall_status = HealthStatus.CRITICAL
            elif result.status == HealthStatus.DEGRADED and overall_status != HealthStatus.CRITICAL:
                overall_status = HealthStatus.DEGRADED
            
            # Print immediate feedback
            status_emoji = {
                HealthStatus.HEALTHY: "✅",
                HealthStatus.DEGRADED: "⚠️",
                HealthStatus.CRITICAL: "❌",
                HealthStatus.UNKNOWN: "❓"
            }
            
            emoji = status_emoji.get(result.status, "❓")
            response_info = f"{result.response_time:.2f}s" if result.response_time else "N/A"
            status_info = f"{result.status_code}" if result.status_code else "ERROR"
            
            print(f"{emoji} {endpoint_name}: {status_info} ({response_info})")
            if result.error:
                print(f"   Error: {result.error}")
        
        # Calculate success rate
        successful = sum(1 for r in results if r.status == HealthStatus.HEALTHY)
        success_rate = successful / len(results) if results else 0
        
        avg_response_time = None
        if any(r.response_time for r in results):
            valid_times = [r.response_time for r in results if r.response_time is not None]
            avg_response_time = sum(valid_times) / len(valid_times) if valid_times else None
        
        return {
            'timestamp': datetime.now().isoformat(),
            'environment': environment,
            'overall_status': overall_status,
            'success_rate': success_rate,
            'avg_response_time': avg_response_time,
            'results': [asdict(r) for r in results],
            'summary': {
                'total_checks': len(results),
                'healthy': sum(1 for r in results if r.status == HealthStatus.HEALTHY),
                'degraded': sum(1 for r in results if r.status == HealthStatus.DEGRADED),
                'critical': sum(1 for r in results if r.status == HealthStatus.CRITICAL),
            }
        }

    def should_send_alert(self, alert_key: str) -> bool:
        """Check if an alert should be sent based on cooldown period"""
        if alert_key not in self.alert_history:
            return True
        
        last_alert = self.alert_history[alert_key]
        return datetime.now() - last_alert > self.alert_cooldown

    def send_alert(self, alert_type: str, message: str, severity: str, environment: str):
        """Send alert and record it"""
        alert_key = f"{alert_type}_{environment}_{severity}"
        
        if not self.should_send_alert(alert_key):
            return  # Skip due to cooldown
        
        print(f"\n🚨 ALERT [{severity.upper()}] {environment}: {message}")
        
        # Save alert to database
        self.save_alert(alert_type, message, severity, environment)
        
        # Update alert history
        self.alert_history[alert_key] = datetime.now()
        
        # Here you could integrate with external alerting services like:
        # - Email notifications
        # - Slack/Discord webhooks
        # - SMS services
        # - PagerDuty, etc.

    def analyze_and_alert(self, health_report: Dict):
        """Analyze health report and send alerts if needed"""
        environment = health_report['environment']
        overall_status = health_report['overall_status']
        success_rate = health_report['success_rate']
        
        # Check for critical issues
        if overall_status == HealthStatus.CRITICAL:
            self.send_alert(
                "service_down",
                f"Critical service issues detected. Success rate: {success_rate:.1%}",
                "critical",
                environment
            )
        elif overall_status == HealthStatus.DEGRADED:
            self.send_alert(
                "service_degraded",
                f"Service performance degraded. Success rate: {success_rate:.1%}",
                "warning",
                environment
            )
        
        # Check response time
        avg_response_time = health_report.get('avg_response_time')
        if avg_response_time and avg_response_time > self.thresholds['response_time_critical']:
            self.send_alert(
                "slow_response",
                f"Average response time is {avg_response_time:.2f}s (threshold: {self.thresholds['response_time_critical']}s)",
                "critical",
                environment
            )
        elif avg_response_time and avg_response_time > self.thresholds['response_time_warning']:
            self.send_alert(
                "slow_response",
                f"Average response time is {avg_response_time:.2f}s (threshold: {self.thresholds['response_time_warning']}s)",
                "warning",
                environment
            )

    def get_health_history(self, environment: str, hours: int = 24) -> List[Dict]:
        """Get health check history from database"""
        cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('''
                SELECT * FROM health_checks 
                WHERE environment = ? AND timestamp > ?
                ORDER BY timestamp DESC
            ''', (environment, cutoff_time))
            
            return [dict(row) for row in cursor.fetchall()]

    def get_alert_history(self, environment: str = None, hours: int = 24) -> List[Dict]:
        """Get alert history from database"""
        cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if environment:
                cursor = conn.execute('''
                    SELECT * FROM alerts 
                    WHERE environment = ? AND timestamp > ?
                    ORDER BY timestamp DESC
                ''', (environment, cutoff_time))
            else:
                cursor = conn.execute('''
                    SELECT * FROM alerts 
                    WHERE timestamp > ?
                    ORDER BY timestamp DESC
                ''', (cutoff_time,))
            
            return [dict(row) for row in cursor.fetchall()]

    def monitor_continuously(self, interval: int = 60, check_heroku: bool = True, check_local: bool = True):
        """Monitor health continuously"""
        print(f"Starting continuous health monitoring (checking every {interval} seconds)...")
        print("Press Ctrl+C to stop monitoring")
        
        try:
            while True:
                print(f"\n{'='*70}")
                print(f"Health Check - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"{'='*70}")
                
                # Check Heroku environment
                if check_heroku:
                    heroku_report = self.run_health_checks("heroku", self.heroku_url)
                    self.analyze_and_alert(heroku_report)
                    
                    # Check dyno status
                    dyno_status = self.check_heroku_dyno_status()
                    print(f"Heroku Dyno Status: {dyno_status.get('status', 'unknown')}")
                
                # Check local environment  
                if check_local:
                    print()
                    local_report = self.run_health_checks("local", self.local_url)
                    self.analyze_and_alert(local_report)
                
                print(f"\nNext check in {interval} seconds...")
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n\nHealth monitoring stopped by user")

def main():
    parser = argparse.ArgumentParser(description='Monitor application health and send alerts')
    parser.add_argument('--app', '-a', default='flask-rest-alm-admin', help='Heroku app name')
    parser.add_argument('--local-port', type=int, default=3000, help='Local Flask port')
    parser.add_argument('--interval', '-i', type=int, default=60, help='Check interval in seconds')
    parser.add_argument('--heroku-only', action='store_true', help='Check Heroku environment only')
    parser.add_argument('--local-only', action='store_true', help='Check local environment only')
    parser.add_argument('--single-check', '-s', action='store_true', help='Run single check instead of continuous monitoring')
    parser.add_argument('--history', type=int, help='Show health history for N hours')
    parser.add_argument('--alerts', type=int, help='Show alert history for N hours')
    
    args = parser.parse_args()
    
    monitor = HealthMonitor(args.app, args.local_port)
    
    if args.history:
        print("Health Check History:")
        for env in ['heroku', 'local']:
            history = monitor.get_health_history(env, args.history)
            if history:
                print(f"\n{env.title()} Environment:")
                for record in history[:10]:  # Show last 10 records
                    print(f"  {record['timestamp']} - {record['endpoint']}: {record['status']}")
    elif args.alerts:
        print("Alert History:")
        alerts = monitor.get_alert_history(hours=args.alerts)
        for alert in alerts:
            print(f"{alert['timestamp']} [{alert['severity'].upper()}] {alert['environment']}: {alert['message']}")
    elif args.single_check:
        check_heroku = not args.local_only
        check_local = not args.heroku_only
        
        if check_heroku:
            heroku_report = monitor.run_health_checks("heroku", monitor.heroku_url)
            print(f"\nHeroku Status: {heroku_report['overall_status'].value}")
        
        if check_local:
            local_report = monitor.run_health_checks("local", monitor.local_url)
            print(f"Local Status: {local_report['overall_status'].value}")
    else:
        # Continuous monitoring
        check_heroku = not args.local_only
        check_local = not args.heroku_only
        monitor.monitor_continuously(args.interval, check_heroku, check_local)

if __name__ == "__main__":
    main()