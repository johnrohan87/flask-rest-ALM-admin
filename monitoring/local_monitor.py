#!/usr/bin/env python3
"""
Local Development Monitoring Script
Monitors local Flask development server, database connectivity, and file changes
"""

import os
import sys
import time
import subprocess
import requests
import psutil
import json
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import argparse
import threading

class FileChangeHandler(FileSystemEventHandler):
    """Handle file system events for monitoring"""
    
    def __init__(self):
        self.recent_changes = []
        self.max_changes = 100
        
    def on_modified(self, event):
        if not event.is_directory:
            self.recent_changes.append({
                'timestamp': datetime.now().isoformat(),
                'event_type': 'modified',
                'path': event.src_path,
                'is_python': event.src_path.endswith('.py')
            })
            if len(self.recent_changes) > self.max_changes:
                self.recent_changes = self.recent_changes[-self.max_changes:]
    
    def on_created(self, event):
        if not event.is_directory:
            self.recent_changes.append({
                'timestamp': datetime.now().isoformat(),
                'event_type': 'created',
                'path': event.src_path,
                'is_python': event.src_path.endswith('.py')
            })
    
    def get_recent_changes(self, minutes: int = 10) -> List[Dict]:
        """Get changes within the last N minutes"""
        cutoff_time = datetime.now().timestamp() - (minutes * 60)
        return [
            change for change in self.recent_changes
            if datetime.fromisoformat(change['timestamp']).timestamp() > cutoff_time
        ]

class LocalMonitor:
    def __init__(self, project_path: str = None):
        self.project_path = project_path or os.getcwd()
        self.flask_port = 3000  # Based on WARP.md configuration
        self.flask_host = "127.0.0.1"
        self.base_url = f"http://{self.flask_host}:{self.flask_port}"
        
        # File monitoring
        self.file_handler = FileChangeHandler()
        self.observer = Observer()
        self.observer.schedule(self.file_handler, self.project_path, recursive=True)
        
        # Process monitoring
        self.monitored_processes = []
        
        # Load environment variables
        self.load_environment()
        
    def load_environment(self):
        """Load environment variables from .env file"""
        env_file = os.path.join(self.project_path, '.env')
        if os.path.exists(env_file):
            with open(env_file, 'r') as f:
                for line in f:
                    if '=' in line and not line.strip().startswith('#'):
                        key, value = line.strip().split('=', 1)
                        os.environ[key] = value
                        
    def get_database_config(self) -> Dict:
        """Extract database configuration from environment"""
        db_connection = os.environ.get('DB_CONNECTION_STRING', '')
        
        config = {
            'connection_string_available': bool(db_connection),
            'connection_string': db_connection[:50] + '...' if len(db_connection) > 50 else db_connection,
        }
        
        # Parse connection string for database type
        if 'mysql' in db_connection.lower():
            config['database_type'] = 'mysql'
        elif 'postgresql' in db_connection.lower() or 'postgres' in db_connection.lower():
            config['database_type'] = 'postgresql'
        else:
            config['database_type'] = 'unknown'
            
        return config

    def check_flask_server(self) -> Dict:
        """Check if Flask development server is running"""
        try:
            response = requests.get(self.base_url, timeout=5)
            return {
                'running': True,
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds(),
                'accessible': 200 <= response.status_code < 400
            }
        except requests.exceptions.ConnectionError:
            return {
                'running': False,
                'error': 'Connection refused - server not running'
            }
        except requests.exceptions.Timeout:
            return {
                'running': True,
                'accessible': False,
                'error': 'Request timeout'
            }
        except Exception as e:
            return {
                'running': False,
                'error': str(e)
            }

    def check_database_connectivity(self) -> Dict:
        """Check database connectivity"""
        db_config = self.get_database_config()
        
        if not db_config['connection_string_available']:
            return {
                'accessible': False,
                'error': 'No database connection string found in environment'
            }
        
        # Try connecting through Flask app endpoints that require DB
        try:
            admin_response = requests.get(f"{self.base_url}/admin/", timeout=10)
            return {
                'accessible': admin_response.status_code != 500,
                'status_code': admin_response.status_code,
                'database_type': db_config['database_type'],
                'test_method': 'admin_endpoint'
            }
        except requests.exceptions.ConnectionError:
            return {
                'accessible': False,
                'error': 'Flask server not running - cannot test DB connectivity'
            }
        except Exception as e:
            return {
                'accessible': False,
                'error': str(e)
            }

    def check_pipenv_environment(self) -> Dict:
        """Check Pipenv virtual environment status"""
        try:
            # Check if we're in a pipenv shell
            result = subprocess.run(['pipenv', '--venv'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                venv_path = result.stdout.strip()
                return {
                    'active': True,
                    'venv_path': venv_path,
                    'in_shell': os.environ.get('VIRTUAL_ENV') == venv_path
                }
            else:
                return {
                    'active': False,
                    'error': result.stderr.strip()
                }
        except subprocess.TimeoutExpired:
            return {'active': False, 'error': 'Pipenv command timed out'}
        except FileNotFoundError:
            return {'active': False, 'error': 'Pipenv not found'}
        except Exception as e:
            return {'active': False, 'error': str(e)}

    def get_flask_processes(self) -> List[Dict]:
        """Find running Flask processes"""
        flask_processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_percent']):
            try:
                cmdline = proc.info['cmdline']
                if cmdline and any('flask' in cmd.lower() or 'main.py' in cmd for cmd in cmdline):
                    flask_processes.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'cmdline': ' '.join(cmdline),
                        'cpu_percent': proc.info['cpu_percent'],
                        'memory_percent': proc.info['memory_percent']
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        return flask_processes

    def run_flask_commands(self) -> Dict:
        """Run Flask development commands and check status"""
        results = {}
        
        # Check if migrations are up to date
        try:
            result = subprocess.run(['pipenv', 'run', 'flask', 'db', 'current'], 
                                  capture_output=True, text=True, timeout=10, cwd=self.project_path)
            results['migrations'] = {
                'command_success': result.returncode == 0,
                'output': result.stdout.strip(),
                'error': result.stderr.strip()
            }
        except Exception as e:
            results['migrations'] = {'command_success': False, 'error': str(e)}
            
        return results

    def start_file_monitoring(self):
        """Start monitoring file changes"""
        if not self.observer.is_alive():
            self.observer.start()
            
    def stop_file_monitoring(self):
        """Stop monitoring file changes"""
        if self.observer.is_alive():
            self.observer.stop()
            self.observer.join()

    def generate_development_report(self) -> Dict:
        """Generate comprehensive development environment report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'project_path': self.project_path,
            'flask_server': self.check_flask_server(),
            'database': self.check_database_connectivity(),
            'pipenv': self.check_pipenv_environment(),
            'processes': self.get_flask_processes(),
            'flask_commands': self.run_flask_commands(),
            'recent_file_changes': self.file_handler.get_recent_changes(10),
            'environment': {
                'python_version': sys.version,
                'working_directory': os.getcwd(),
                'environment_variables': {
                    'AUTH0_DOMAIN': bool(os.environ.get('AUTH0_DOMAIN')),
                    'DB_CONNECTION_STRING': bool(os.environ.get('DB_CONNECTION_STRING')),
                    'JWT_SECRET_KEY': bool(os.environ.get('JWT_SECRET_KEY')),
                }
            }
        }
        
        # Overall status
        server_ok = report['flask_server'].get('accessible', False)
        db_ok = report['database'].get('accessible', False)
        pipenv_ok = report['pipenv'].get('active', False)
        
        report['overall_status'] = {
            'healthy': all([server_ok, db_ok, pipenv_ok]),
            'components': {
                'server': 'ok' if server_ok else 'error',
                'database': 'ok' if db_ok else 'error',
                'pipenv': 'ok' if pipenv_ok else 'error'
            }
        }
        
        return report

    def start_development_server(self) -> Dict:
        """Start the Flask development server using pipenv"""
        print("Starting Flask development server...")
        
        try:
            # Use pipenv run start as defined in WARP.md
            process = subprocess.Popen(
                ['pipenv', 'run', 'start'],
                cwd=self.project_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait a bit and check if it's running
            time.sleep(3)
            server_check = self.check_flask_server()
            
            return {
                'started': True,
                'pid': process.pid,
                'server_accessible': server_check.get('accessible', False),
                'server_status': server_check
            }
            
        except Exception as e:
            return {
                'started': False,
                'error': str(e)
            }

    def monitor_continuously(self, interval: int = 30):
        """Monitor development environment continuously"""
        print(f"Starting continuous monitoring (checking every {interval} seconds)...")
        print("Press Ctrl+C to stop monitoring")
        
        self.start_file_monitoring()
        
        try:
            while True:
                report = self.generate_development_report()
                
                # Print summary
                print(f"\n{'='*60}")
                print(f"Development Status Check - {report['timestamp']}")
                print(f"{'='*60}")
                
                status_emoji = "✅" if report['overall_status']['healthy'] else "❌"
                print(f"{status_emoji} Overall Status: {'Healthy' if report['overall_status']['healthy'] else 'Issues Detected'}")
                
                # Component statuses
                for component, status in report['overall_status']['components'].items():
                    emoji = "✅" if status == 'ok' else "❌"
                    print(f"{emoji} {component.title()}: {status}")
                
                # Recent file changes
                recent_changes = len(report['recent_file_changes'])
                if recent_changes > 0:
                    print(f"📄 Recent file changes: {recent_changes}")
                    python_changes = sum(1 for c in report['recent_file_changes'] if c.get('is_python', False))
                    if python_changes > 0:
                        print(f"🐍 Python files changed: {python_changes}")
                
                # Flask processes
                if report['processes']:
                    print(f"⚡ Flask processes running: {len(report['processes'])}")
                
                print(f"Next check in {interval} seconds...")
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n\nMonitoring stopped by user")
        finally:
            self.stop_file_monitoring()

def main():
    parser = argparse.ArgumentParser(description='Monitor local Flask development environment')
    parser.add_argument('--path', '-p', help='Project path (default: current directory)')
    parser.add_argument('--report', '-r', action='store_true', help='Generate single report')
    parser.add_argument('--start', '-s', action='store_true', help='Start Flask development server')
    parser.add_argument('--monitor', '-m', type=int, default=30, help='Continuous monitoring interval in seconds')
    parser.add_argument('--no-files', action='store_true', help='Disable file change monitoring')
    
    args = parser.parse_args()
    
    monitor = LocalMonitor(args.path)
    
    if args.start:
        result = monitor.start_development_server()
        print(json.dumps(result, indent=2))
    elif args.report:
        if not args.no_files:
            monitor.start_file_monitoring()
            time.sleep(1)  # Give it a moment to initialize
        report = monitor.generate_development_report()
        print(json.dumps(report, indent=2))
        if not args.no_files:
            monitor.stop_file_monitoring()
    else:
        if not args.no_files:
            monitor.monitor_continuously(args.monitor)
        else:
            # Monitor without file watching
            try:
                while True:
                    report = monitor.generate_development_report()
                    print(f"\nStatus: {'Healthy' if report['overall_status']['healthy'] else 'Issues'}")
                    for comp, status in report['overall_status']['components'].items():
                        print(f"  {comp}: {status}")
                    time.sleep(args.monitor)
            except KeyboardInterrupt:
                print("\nMonitoring stopped")

if __name__ == "__main__":
    main()