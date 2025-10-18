#!/usr/bin/env python3
"""
Deployment Monitoring Script
Monitors Heroku deployments, build status, and runs post-deployment health checks
"""

import subprocess
import requests
import time
import json
import sys
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import argparse

class DeploymentMonitor:
    def __init__(self, app_name: str = "flask-rest-alm-admin"):
        self.app_name = app_name
        self.base_url = f"https://{app_name}.herokuapp.com"
        
        # Health check endpoints based on Flask REST API structure
        self.health_endpoints = [
            "/",  # Basic root endpoint
            "/admin/",  # Admin interface
            # Add more endpoints specific to your API
        ]
        
        self.deployment_status = {
            'last_check': None,
            'last_deploy': None,
            'current_version': None,
            'health_status': 'unknown'
        }

    def run_heroku_command(self, command: List[str]) -> Tuple[bool, str, str]:
        """Execute Heroku CLI command and return success, stdout, stderr"""
        try:
            full_command = ["heroku"] + command + ["-a", self.app_name]
            result = subprocess.run(
                full_command,
                capture_output=True,
                text=True,
                timeout=60
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except FileNotFoundError:
            return False, "", "Heroku CLI not found"
        except Exception as e:
            return False, "", str(e)

    def get_current_release(self) -> Optional[Dict]:
        """Get current release information"""
        success, stdout, stderr = self.run_heroku_command(["releases", "-n", "1", "--json"])
        if success and stdout:
            try:
                releases = json.loads(stdout)
                if releases:
                    return releases[0]
            except json.JSONDecodeError:
                pass
        return None

    def check_build_status(self) -> Dict:
        """Check current build status"""
        print("Checking build status...")
        
        # Get current release
        current_release = self.get_current_release()
        if not current_release:
            return {"status": "error", "message": "Could not get release information"}
        
        # Get dyno status
        success, stdout, stderr = self.run_heroku_command(["ps"])
        dyno_status = "unknown"
        if success:
            if "up" in stdout.lower():
                dyno_status = "running"
            elif "crashed" in stdout.lower():
                dyno_status = "crashed"
            elif "idle" in stdout.lower():
                dyno_status = "idle"
        
        return {
            "status": "success",
            "release": current_release,
            "dyno_status": dyno_status,
            "raw_ps": stdout if success else stderr
        }

    def run_health_check(self, endpoint: str, timeout: int = 30) -> Dict:
        """Run health check on specific endpoint"""
        url = f"{self.base_url}{endpoint}"
        try:
            response = requests.get(url, timeout=timeout)
            return {
                "endpoint": endpoint,
                "status_code": response.status_code,
                "response_time": response.elapsed.total_seconds(),
                "success": 200 <= response.status_code < 400,
                "headers": dict(response.headers),
                "size": len(response.content)
            }
        except requests.exceptions.Timeout:
            return {
                "endpoint": endpoint,
                "success": False,
                "error": "Timeout"
            }
        except requests.exceptions.ConnectionError:
            return {
                "endpoint": endpoint,
                "success": False,
                "error": "Connection Error"
            }
        except Exception as e:
            return {
                "endpoint": endpoint,
                "success": False,
                "error": str(e)
            }

    def run_all_health_checks(self) -> Dict:
        """Run health checks on all configured endpoints"""
        print("Running health checks...")
        results = []
        
        for endpoint in self.health_endpoints:
            result = self.run_health_check(endpoint)
            results.append(result)
            
            # Print immediate feedback
            status = "✅" if result.get("success", False) else "❌"
            print(f"{status} {endpoint}: {result.get('status_code', 'ERROR')}")
        
        # Calculate overall health
        successful = sum(1 for r in results if r.get("success", False))
        total = len(results)
        health_percentage = (successful / total) * 100 if total > 0 else 0
        
        return {
            "timestamp": datetime.now().isoformat(),
            "results": results,
            "summary": {
                "successful": successful,
                "total": total,
                "health_percentage": health_percentage,
                "overall_status": "healthy" if health_percentage >= 80 else "degraded" if health_percentage >= 50 else "unhealthy"
            }
        }

    def check_database_connectivity(self) -> Dict:
        """Check database connectivity through app endpoint"""
        # This would require a specific health endpoint in your Flask app
        # For now, we'll check if the admin interface loads (which requires DB)
        admin_check = self.run_health_check("/admin/")
        
        return {
            "timestamp": datetime.now().isoformat(),
            "database_accessible": admin_check.get("success", False),
            "details": admin_check
        }

    def monitor_recent_activity(self, minutes: int = 30) -> Dict:
        """Monitor recent application activity"""
        print(f"Checking activity in the last {minutes} minutes...")
        
        # Get recent releases
        success, stdout, stderr = self.run_heroku_command(["releases", "-n", "10"])
        recent_releases = []
        if success:
            lines = stdout.strip().split('\n')[1:]  # Skip header
            for line in lines:
                if line.strip():
                    recent_releases.append(line.strip())
        
        # Get recent log entries with errors
        success, stdout, stderr = self.run_heroku_command([
            "logs", "--tail", "-n", "100"
        ])
        
        error_count = 0
        warning_count = 0
        if success:
            for line in stdout.split('\n'):
                if any(keyword in line.lower() for keyword in ['error', 'exception', 'traceback']):
                    error_count += 1
                elif any(keyword in line.lower() for keyword in ['warning', 'warn']):
                    warning_count += 1
        
        return {
            "timestamp": datetime.now().isoformat(),
            "recent_releases": recent_releases[:5],  # Last 5 releases
            "log_analysis": {
                "error_count": error_count,
                "warning_count": warning_count,
                "severity": "high" if error_count > 10 else "medium" if error_count > 0 or warning_count > 5 else "low"
            }
        }

    def deploy_and_monitor(self, branch: str = "main") -> Dict:
        """Deploy from git and monitor the deployment"""
        print(f"Starting deployment from {branch} branch...")
        
        deployment_log = {
            "start_time": datetime.now().isoformat(),
            "branch": branch,
            "steps": []
        }
        
        # Step 1: Get current state
        deployment_log["steps"].append({
            "step": "pre_deploy_check",
            "timestamp": datetime.now().isoformat(),
            "status": "starting"
        })
        
        pre_deploy_status = self.check_build_status()
        pre_deploy_health = self.run_all_health_checks()
        
        deployment_log["steps"][-1].update({
            "status": "completed",
            "build_status": pre_deploy_status,
            "health_status": pre_deploy_health
        })
        
        # Step 2: Deploy
        deployment_log["steps"].append({
            "step": "git_deploy",
            "timestamp": datetime.now().isoformat(),
            "status": "starting"
        })
        
        print("Pushing to Heroku...")
        try:
            result = subprocess.run([
                "git", "push", "heroku", f"{branch}:main"
            ], capture_output=True, text=True, timeout=300)  # 5 minute timeout
            
            deployment_log["steps"][-1].update({
                "status": "completed" if result.returncode == 0 else "failed",
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode
            })
        except subprocess.TimeoutExpired:
            deployment_log["steps"][-1].update({
                "status": "timeout",
                "error": "Deployment timed out after 5 minutes"
            })
        except Exception as e:
            deployment_log["steps"][-1].update({
                "status": "error",
                "error": str(e)
            })
        
        # Step 3: Wait for deployment to complete
        deployment_log["steps"].append({
            "step": "wait_for_deploy",
            "timestamp": datetime.now().isoformat(),
            "status": "starting"
        })
        
        print("Waiting for deployment to complete...")
        time.sleep(30)  # Wait for deployment to propagate
        
        # Step 4: Post-deployment checks
        deployment_log["steps"].append({
            "step": "post_deploy_check",
            "timestamp": datetime.now().isoformat(),
            "status": "starting"
        })
        
        post_deploy_status = self.check_build_status()
        post_deploy_health = self.run_all_health_checks()
        
        deployment_log["steps"][-1].update({
            "status": "completed",
            "build_status": post_deploy_status,
            "health_status": post_deploy_health
        })
        
        deployment_log.update({
            "end_time": datetime.now().isoformat(),
            "success": all(step.get("status") != "failed" for step in deployment_log["steps"])
        })
        
        return deployment_log

    def generate_report(self) -> Dict:
        """Generate comprehensive deployment and health report"""
        print("Generating comprehensive report...")
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "app_name": self.app_name,
            "build_status": self.check_build_status(),
            "health_checks": self.run_all_health_checks(),
            "database_check": self.check_database_connectivity(),
            "recent_activity": self.monitor_recent_activity(),
        }
        
        # Overall status determination
        build_ok = report["build_status"].get("status") == "success"
        health_ok = report["health_checks"]["summary"]["overall_status"] in ["healthy", "degraded"]
        db_ok = report["database_check"]["database_accessible"]
        activity_ok = report["recent_activity"]["log_analysis"]["severity"] != "high"
        
        report["overall_status"] = {
            "status": "healthy" if all([build_ok, health_ok, db_ok, activity_ok]) else "unhealthy",
            "components": {
                "build": "ok" if build_ok else "error",
                "health": report["health_checks"]["summary"]["overall_status"],
                "database": "ok" if db_ok else "error",
                "activity": report["recent_activity"]["log_analysis"]["severity"]
            }
        }
        
        return report

def main():
    parser = argparse.ArgumentParser(description='Monitor Heroku deployments and app health')
    parser.add_argument('--app', '-a', default='flask-rest-alm-admin', help='Heroku app name')
    parser.add_argument('--deploy', '-d', help='Deploy from specified branch and monitor')
    parser.add_argument('--health', action='store_true', help='Run health checks only')
    parser.add_argument('--report', '-r', action='store_true', help='Generate full report')
    parser.add_argument('--watch', '-w', type=int, help='Watch mode: repeat checks every N seconds')
    
    args = parser.parse_args()
    
    monitor = DeploymentMonitor(args.app)
    
    def run_checks():
        if args.deploy:
            result = monitor.deploy_and_monitor(args.deploy)
            print("\n" + "="*60)
            print("DEPLOYMENT SUMMARY")
            print("="*60)
            print(f"Success: {result['success']}")
            print(f"Duration: {result['start_time']} to {result['end_time']}")
            for step in result['steps']:
                status_emoji = "✅" if step['status'] == 'completed' else "❌" if step['status'] == 'failed' else "⏳"
                print(f"{status_emoji} {step['step']}: {step['status']}")
        elif args.health:
            result = monitor.run_all_health_checks()
            print(f"\nHealth Status: {result['summary']['overall_status']}")
            print(f"Success Rate: {result['summary']['health_percentage']:.1f}%")
        elif args.report:
            result = monitor.generate_report()
            print(json.dumps(result, indent=2))
        else:
            # Default: show current status
            result = monitor.generate_report()
            print(f"\nApp: {result['app_name']}")
            print(f"Overall Status: {result['overall_status']['status']}")
            print(f"Health: {result['health_checks']['summary']['overall_status']}")
            print(f"Database: {'✅' if result['database_check']['database_accessible'] else '❌'}")
    
    if args.watch:
        print(f"Starting watch mode (checking every {args.watch} seconds)...")
        try:
            while True:
                run_checks()
                print(f"\nNext check in {args.watch} seconds...")
                time.sleep(args.watch)
        except KeyboardInterrupt:
            print("\nWatch mode stopped by user")
    else:
        run_checks()

if __name__ == "__main__":
    main()