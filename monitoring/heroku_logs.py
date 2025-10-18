#!/usr/bin/env python3
"""
Heroku Log Monitoring Script
Monitors real-time Heroku logs with filtering, analysis, and alerting
"""

import subprocess
import sys
import time
import re
import json
from datetime import datetime
from typing import Dict, List, Optional
import argparse

class HerokuLogMonitor:
    def __init__(self, app_name: str = "flask-rest-alm-admin"):
        self.app_name = app_name
        self.log_patterns = {
            'error': [
                r'ERROR',
                r'Exception',
                r'Traceback',
                r'500\s+Internal\s+Server\s+Error',
                r'at=error',
                r'code=H[0-9]+',  # Heroku error codes
            ],
            'warning': [
                r'WARNING',
                r'WARN',
                r'at=timeout',
                r'code=H12',  # Request timeout
            ],
            'database': [
                r'mysql',
                r'postgresql',
                r'database',
                r'SQLAlchemy',
                r'migration',
            ],
            'auth': [
                r'Auth0',
                r'JWT',
                r'authentication',
                r'authorization',
                r'token',
            ],
            'performance': [
                r'connect=\d+ms',
                r'service=\d+ms',
                r'status=\d+',
                r'bytes=\d+',
            ]
        }
        
        self.error_counts = {category: 0 for category in self.log_patterns.keys()}
        self.start_time = datetime.now()
        
    def run_heroku_command(self, command: List[str]) -> Optional[subprocess.Popen]:
        """Execute Heroku CLI command and return process"""
        try:
            full_command = ["heroku"] + command + ["-a", self.app_name]
            process = subprocess.Popen(
                full_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            return process
        except subprocess.CalledProcessError as e:
            print(f"Error executing Heroku command: {e}")
            return None
        except FileNotFoundError:
            print("Heroku CLI not found. Please install it first.")
            return None

    def categorize_log_line(self, line: str) -> List[str]:
        """Categorize a log line based on patterns"""
        categories = []
        for category, patterns in self.log_patterns.items():
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    categories.append(category)
                    self.error_counts[category] += 1
                    break
        return categories

    def format_log_entry(self, line: str, categories: List[str]) -> Dict:
        """Format log entry with metadata"""
        timestamp = datetime.now().isoformat()
        
        # Extract Heroku log metadata if present
        heroku_metadata = {}
        if line.startswith('20'):  # Heroku timestamp format
            parts = line.split(' ', 3)
            if len(parts) >= 4:
                heroku_metadata = {
                    'timestamp': parts[0],
                    'source': parts[2] if len(parts) > 2 else 'unknown',
                    'message': parts[3] if len(parts) > 3 else line
                }
        
        return {
            'local_timestamp': timestamp,
            'categories': categories,
            'raw_line': line.strip(),
            'heroku_metadata': heroku_metadata,
            'severity': self.get_severity(categories)
        }

    def get_severity(self, categories: List[str]) -> str:
        """Determine log severity based on categories"""
        if 'error' in categories:
            return 'HIGH'
        elif 'warning' in categories:
            return 'MEDIUM'
        elif any(cat in categories for cat in ['database', 'auth']):
            return 'MEDIUM'
        else:
            return 'LOW'

    def print_colored_log(self, entry: Dict):
        """Print log entry with color coding"""
        colors = {
            'HIGH': '\033[91m',    # Red
            'MEDIUM': '\033[93m',  # Yellow
            'LOW': '\033[92m',     # Green
        }
        reset = '\033[0m'
        
        severity = entry['severity']
        color = colors.get(severity, '')
        
        categories_str = f"[{','.join(entry['categories'])}]" if entry['categories'] else ""
        
        print(f"{color}[{entry['local_timestamp']}] {severity} {categories_str}{reset}")
        print(f"{color}{entry['raw_line']}{reset}")
        print("-" * 80)

    def print_summary(self):
        """Print monitoring summary"""
        runtime = datetime.now() - self.start_time
        print(f"\n{'='*50}")
        print(f"MONITORING SUMMARY (Runtime: {runtime})")
        print(f"{'='*50}")
        for category, count in self.error_counts.items():
            print(f"{category.upper()}: {count}")
        print(f"{'='*50}\n")

    def monitor_logs(self, tail_lines: int = 100, follow: bool = True, dyno: Optional[str] = None):
        """Start monitoring Heroku logs"""
        print(f"Starting log monitoring for app: {self.app_name}")
        print(f"Monitoring started at: {self.start_time}")
        print("-" * 80)
        
        # Build logs command
        logs_cmd = ["logs"]
        if tail_lines > 0:
            logs_cmd.extend(["-n", str(tail_lines)])
        if follow:
            logs_cmd.append("--tail")
        if dyno:
            logs_cmd.extend(["-d", dyno])
        
        process = self.run_heroku_command(logs_cmd)
        if not process:
            return
            
        try:
            line_count = 0
            while True:
                line = process.stdout.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    time.sleep(0.1)
                    continue
                
                line_count += 1
                categories = self.categorize_log_line(line)
                entry = self.format_log_entry(line, categories)
                
                # Only print significant logs or every 50th line
                if categories or line_count % 50 == 0:
                    self.print_colored_log(entry)
                
                # Print summary every 100 lines
                if line_count % 100 == 0:
                    self.print_summary()
                    
        except KeyboardInterrupt:
            print("\n\nMonitoring stopped by user")
            self.print_summary()
        finally:
            if process:
                process.terminate()

    def get_app_status(self):
        """Get current app status and dyno information"""
        print(f"Checking status for app: {self.app_name}")
        
        # Get app info
        process = self.run_heroku_command(["info"])
        if process:
            stdout, stderr = process.communicate()
            if process.returncode == 0:
                print("App Info:")
                print(stdout)
            else:
                print(f"Error getting app info: {stderr}")
        
        # Get dyno status
        process = self.run_heroku_command(["ps"])
        if process:
            stdout, stderr = process.communicate()
            if process.returncode == 0:
                print("\nDyno Status:")
                print(stdout)
            else:
                print(f"Error getting dyno status: {stderr}")

    def check_recent_deploys(self, count: int = 5):
        """Check recent deployment history"""
        print(f"Checking recent deployments for app: {self.app_name}")
        
        process = self.run_heroku_command(["releases", "-n", str(count)])
        if process:
            stdout, stderr = process.communicate()
            if process.returncode == 0:
                print("Recent Releases:")
                print(stdout)
            else:
                print(f"Error getting releases: {stderr}")

def main():
    parser = argparse.ArgumentParser(description='Monitor Heroku logs and app status')
    parser.add_argument('--app', '-a', default='flask-rest-alm-admin', 
                       help='Heroku app name')
    parser.add_argument('--tail', '-t', type=int, default=100,
                       help='Number of recent lines to fetch initially')
    parser.add_argument('--follow', '-f', action='store_true', default=True,
                       help='Follow logs in real-time')
    parser.add_argument('--dyno', '-d', help='Filter logs from specific dyno')
    parser.add_argument('--status', '-s', action='store_true',
                       help='Show app status instead of monitoring logs')
    parser.add_argument('--releases', '-r', action='store_true',
                       help='Show recent releases')
    
    args = parser.parse_args()
    
    monitor = HerokuLogMonitor(args.app)
    
    if args.status:
        monitor.get_app_status()
    elif args.releases:
        monitor.check_recent_deploys()
    else:
        monitor.monitor_logs(tail_lines=args.tail, follow=args.follow, dyno=args.dyno)

if __name__ == "__main__":
    main()