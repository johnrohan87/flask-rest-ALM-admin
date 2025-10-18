#!/usr/bin/env python3
"""
Database Synchronization Utility
Provides commands to sync data between local and remote databases
"""

import os
import sys
import argparse
import subprocess
import json
import tempfile
from datetime import datetime
from urllib.parse import urlparse
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from models import db, User, Feed, Story, UserFeed, UserStory

# Load environment variables
load_dotenv()

class DatabaseSync:
    def __init__(self):
        self.local_db_url = os.environ.get('DB_CONNECTION_STRING')
        self.remote_db_url = os.environ.get('REMOTE_DB_CONNECTION_STRING')
        
        if not self.local_db_url:
            raise ValueError("DB_CONNECTION_STRING not found in environment")
            
        self.local_engine = create_engine(self.local_db_url)
        self.remote_engine = create_engine(self.remote_db_url) if self.remote_db_url else None
        
    def parse_db_url(self, url):
        """Parse database URL to extract connection details"""
        parsed = urlparse(url)
        return {
            'host': parsed.hostname,
            'port': parsed.port or 3306,
            'username': parsed.username,
            'password': parsed.password,
            'database': parsed.path.lstrip('/')
        }
    
    def get_mysql_dump_cmd(self, db_url, output_file=None):
        """Generate mysqldump command for given database URL"""
        db_info = self.parse_db_url(db_url)
        
        cmd = [
            'mysqldump',
            f'--host={db_info["host"]}',
            f'--port={db_info["port"]}',
            f'--user={db_info["username"]}',
            f'--password={db_info["password"]}',
            '--single-transaction',
            '--routines',
            '--triggers',
            db_info['database']
        ]
        
        if output_file:
            cmd.extend(['>', output_file])
        
        return cmd, db_info
    
    def get_mysql_import_cmd(self, db_url, input_file):
        """Generate mysql import command for given database URL"""
        db_info = self.parse_db_url(db_url)
        
        cmd = [
            'mysql',
            f'--host={db_info["host"]}',
            f'--port={db_info["port"]}',
            f'--user={db_info["username"]}',
            f'--password={db_info["password"]}',
            db_info['database']
        ]
        
        return cmd, db_info
    
    def check_connection(self, engine, db_name="Database"):
        """Test database connection"""
        try:
            with engine.connect() as conn:
                result = conn.execute(text("SELECT 1"))
                print(f"✅ {db_name} connection: OK")
                return True
        except Exception as e:
            print(f"❌ {db_name} connection: FAILED - {str(e)}")
            return False
    
    def get_table_counts(self, engine):
        """Get record counts for all main tables"""
        counts = {}
        tables = ['user', 'feed', 'story', 'user_feed', 'user_story']
        
        try:
            with engine.connect() as conn:
                for table in tables:
                    try:
                        result = conn.execute(text(f"SELECT COUNT(*) as count FROM {table}"))
                        counts[table] = result.fetchone()[0]
                    except Exception as e:
                        counts[table] = f"Error: {str(e)}"
        except Exception as e:
            print(f"Error getting table counts: {e}")
            
        return counts
    
    def compare_databases(self):
        """Compare local and remote database schemas and data"""
        if not self.remote_engine:
            print("❌ Remote database not configured")
            return False
            
        print("🔍 Comparing databases...")
        print("=" * 50)
        
        # Check connections
        local_ok = self.check_connection(self.local_engine, "Local")
        remote_ok = self.check_connection(self.remote_engine, "Remote")
        
        if not (local_ok and remote_ok):
            return False
        
        # Compare table counts
        print("\n📊 Table Counts:")
        print("-" * 30)
        
        local_counts = self.get_table_counts(self.local_engine)
        remote_counts = self.get_table_counts(self.remote_engine)
        
        in_sync = True
        for table in local_counts:
            local_count = local_counts[table]
            remote_count = remote_counts.get(table, 'N/A')
            
            status = "✅" if local_count == remote_count else "⚠️"
            if local_count != remote_count:
                in_sync = False
                
            print(f"{status} {table}: Local({local_count}) | Remote({remote_count})")
        
        print(f"\n🔄 Databases in sync: {'✅ YES' if in_sync else '❌ NO'}")
        return in_sync
    
    def backup_database(self, db_url, backup_file=None):
        """Create database backup"""
        if backup_file is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            db_info = self.parse_db_url(db_url)
            backup_file = f"backup_{db_info['database']}_{timestamp}.sql"
        
        print(f"📦 Creating backup: {backup_file}")
        
        cmd, db_info = self.get_mysql_dump_cmd(db_url)
        
        try:
            with open(backup_file, 'w') as f:
                result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)
                
            if result.returncode == 0:
                print(f"✅ Backup created successfully: {backup_file}")
                return backup_file
            else:
                print(f"❌ Backup failed: {result.stderr}")
                return None
                
        except Exception as e:
            print(f"❌ Backup failed: {str(e)}")
            return None
    
    def sync_local_to_remote(self, backup_first=True):
        """Sync local database to remote"""
        if not self.remote_engine:
            print("❌ Remote database not configured")
            return False
            
        print("🔄 Syncing local → remote...")
        
        # Create remote backup first
        if backup_first:
            remote_backup = self.backup_database(self.remote_db_url)
            if not remote_backup:
                print("❌ Failed to backup remote database")
                return False
        
        # Create local dump
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sql', delete=False) as f:
            temp_dump = f.name
            
        try:
            # Export local database
            cmd, _ = self.get_mysql_dump_cmd(self.local_db_url)
            
            with open(temp_dump, 'w') as f:
                result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)
                
            if result.returncode != 0:
                print(f"❌ Local export failed: {result.stderr}")
                return False
            
            print("✅ Local database exported")
            
            # Import to remote database  
            cmd, _ = self.get_mysql_import_cmd(self.remote_db_url, temp_dump)
            
            with open(temp_dump, 'r') as f:
                result = subprocess.run(cmd, stdin=f, stderr=subprocess.PIPE, text=True)
                
            if result.returncode == 0:
                print("✅ Remote database updated successfully")
                return True
            else:
                print(f"❌ Remote import failed: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Sync failed: {str(e)}")
            return False
        finally:
            # Cleanup temp file
            try:
                os.unlink(temp_dump)
            except:
                pass
    
    def sync_remote_to_local(self, backup_first=True):
        """Sync remote database to local"""
        if not self.remote_engine:
            print("❌ Remote database not configured")
            return False
            
        print("🔄 Syncing remote → local...")
        
        # Create local backup first
        if backup_first:
            local_backup = self.backup_database(self.local_db_url)
            if not local_backup:
                print("❌ Failed to backup local database")
                return False
        
        # Create remote dump
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sql', delete=False) as f:
            temp_dump = f.name
            
        try:
            # Export remote database
            cmd, _ = self.get_mysql_dump_cmd(self.remote_db_url)
            
            with open(temp_dump, 'w') as f:
                result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)
                
            if result.returncode != 0:
                print(f"❌ Remote export failed: {result.stderr}")
                return False
            
            print("✅ Remote database exported")
            
            # Import to local database
            cmd, _ = self.get_mysql_import_cmd(self.local_db_url, temp_dump)
            
            with open(temp_dump, 'r') as f:
                result = subprocess.run(cmd, stdin=f, stderr=subprocess.PIPE, text=True)
                
            if result.returncode == 0:
                print("✅ Local database updated successfully")
                return True
            else:
                print(f"❌ Local import failed: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Sync failed: {str(e)}")
            return False
        finally:
            # Cleanup temp file
            try:
                os.unlink(temp_dump)
            except:
                pass


def main():
    parser = argparse.ArgumentParser(description='Database Synchronization Utility')
    parser.add_argument('command', choices=['check', 'sync-to-remote', 'sync-to-local', 'backup-local', 'backup-remote'], 
                       help='Command to execute')
    parser.add_argument('--no-backup', action='store_true', help='Skip backup before sync')
    
    args = parser.parse_args()
    
    try:
        db_sync = DatabaseSync()
        
        if args.command == 'check':
            db_sync.compare_databases()
            
        elif args.command == 'sync-to-remote':
            success = db_sync.sync_local_to_remote(backup_first=not args.no_backup)
            sys.exit(0 if success else 1)
            
        elif args.command == 'sync-to-local':
            success = db_sync.sync_remote_to_local(backup_first=not args.no_backup)
            sys.exit(0 if success else 1)
            
        elif args.command == 'backup-local':
            backup_file = db_sync.backup_database(db_sync.local_db_url)
            sys.exit(0 if backup_file else 1)
            
        elif args.command == 'backup-remote':
            if not db_sync.remote_db_url:
                print("❌ Remote database not configured")
                sys.exit(1)
            backup_file = db_sync.backup_database(db_sync.remote_db_url)
            sys.exit(0 if backup_file else 1)
            
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()