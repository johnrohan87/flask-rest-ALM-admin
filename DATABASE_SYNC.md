# Database Synchronization Guide

This document explains how to manage and synchronize databases between local development and remote production environments.

## Setup

### 1. Configure Remote Database
Add your remote database connection string to `.env`:

```bash
# Remote Database Configuration (Production)
REMOTE_DB_CONNECTION_STRING=mysql://username:password@remote-host:3306/production_db
```

### 2. Available Commands

All database sync commands are available through pipenv:

```bash
# Check if databases are in sync
pipenv run db-check

# Sync local database TO remote (local → remote) 
pipenv run db-sync-to-remote

# Sync remote database TO local (remote → local)
pipenv run db-sync-to-local  

# Create backup of local database
pipenv run db-backup-local

# Create backup of remote database
pipenv run db-backup-remote
```

## Usage Examples

### Check Database Synchronization Status
```bash
pipenv run db-check
```
**Output:**
```
🔍 Comparing databases...
==================================================
✅ Local connection: OK
✅ Remote connection: OK

📊 Table Counts:
------------------------------
✅ user: Local(1) | Remote(1)
⚠️ feed: Local(3) | Remote(5)
⚠️ story: Local(15) | Remote(25)
✅ user_feed: Local(3) | Remote(3)
✅ user_story: Local(8) | Remote(8)

🔄 Databases in sync: ❌ NO
```

### Sync Local Changes to Remote (Deploy)
```bash
# Creates backup of remote DB first, then syncs local → remote
pipenv run db-sync-to-remote
```

**Output:**
```
🔄 Syncing local → remote...
📦 Creating backup: backup_production_db_20231018_161500.sql
✅ Backup created successfully: backup_production_db_20231018_161500.sql
✅ Local database exported
✅ Remote database updated successfully
```

### Sync Remote Changes to Local (Pull Updates)
```bash
# Creates backup of local DB first, then syncs remote → local  
pipenv run db-sync-to-local
```

### Create Backups
```bash
# Backup local database
pipenv run db-backup-local

# Backup remote database (requires remote DB config)
pipenv run db-backup-remote
```

## Safety Features

### Automatic Backups
- **Before syncing**: Automatic backups are created of the target database
- **Timestamped files**: Backups include timestamp (e.g., `backup_example_20231018_161500.sql`)
- **Skip backups**: Use `--no-backup` flag to skip automatic backups

### Connection Validation
- Tests database connections before performing operations
- Shows clear error messages for connection issues
- Validates both source and target databases

### Data Comparison
- Compares table record counts between databases
- Shows which tables are out of sync
- Provides clear sync status indicators

## Direct Script Usage

You can also run the sync script directly:

```bash
# Check sync status
python src/db_sync.py check

# Sync local to remote (with backup)
python src/db_sync.py sync-to-remote

# Sync local to remote (without backup) 
python src/db_sync.py sync-to-remote --no-backup

# Sync remote to local
python src/db_sync.py sync-to-local

# Create backups
python src/db_sync.py backup-local
python src/db_sync.py backup-remote
```

## Workflow Recommendations

### Development Workflow
1. **Before making changes**: `pipenv run db-check`
2. **After local changes**: `pipenv run db-backup-local` 
3. **Deploy to remote**: `pipenv run db-sync-to-remote`
4. **Verify deployment**: `pipenv run db-check`

### Production Sync Workflow  
1. **Pull latest changes**: `pipenv run db-sync-to-local`
2. **Verify local state**: `pipenv run db-check`
3. **Continue development**: Make your changes locally

## Security Notes

### Environment Variables
- Never commit `.env` files with production database credentials
- Use different credentials for development vs production
- Ensure database users have appropriate permissions

### Backup Strategy
- Backups are created automatically before destructive operations
- Store important backups in secure, versioned locations
- Test backup restoration procedures regularly

### Network Security
- Use SSL/TLS connections for remote database access
- Restrict database access to authorized IP addresses
- Use strong, unique passwords for database users

## Troubleshooting

### Common Issues

#### Remote Database Not Configured
```
❌ Remote database not configured
```
**Solution:** Add `REMOTE_DB_CONNECTION_STRING` to your `.env` file

#### Connection Failed  
```
❌ Remote connection: FAILED - (2003, "Can't connect to MySQL server")
```
**Solutions:**
- Check network connectivity to remote host
- Verify database credentials 
- Ensure remote database server is running
- Check firewall settings

#### Permission Denied
```
❌ Backup failed: mysqldump: Got error: 1045: Access denied
```
**Solutions:**
- Verify database username and password
- Check user permissions for backup operations
- Ensure user has SELECT, SHOW DATABASES, LOCK TABLES privileges

#### Table Not Found
```
⚠️ user: Local(5) | Remote(Error: Table 'production_db.user' doesn't exist)
```
**Solutions:**
- Run migrations on the target database: `pipenv run upgrade`
- Check database schema versions
- Ensure both databases have the same table structure

## File Locations

- **Sync Script**: `src/db_sync.py`
- **Configuration**: `.env` (DATABASE_SYNC section)
- **Backups**: Root directory with timestamp format
- **Migrations**: `migrations/` directory

## Support

For issues with database synchronization:
1. Check connection settings in `.env`
2. Verify database credentials and permissions
3. Review backup files for data integrity
4. Test sync operations on development data first