# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Development Commands

### Environment Setup
```bash
pipenv install                  # Install dependencies
pipenv shell                   # Activate virtual environment
```

### Database Management
```bash
pipenv run init                # Initialize Flask-Migrate
pipenv run migrate             # Create new migrations after model changes
pipenv run upgrade             # Apply migrations to database
```

### Running the Application
```bash
pipenv run start              # Start Flask development server on port 3000
python src/main.py            # Alternative way to run the app
```

### Code Quality
```bash
pylint src/                   # Run linting (configured via .pylintrc)
# Pycodestyle ignores E501 (line too long) and E302 (expected 2 blank lines)
```

### Database Access
```bash
mysql                         # Access MySQL terminal
# Then: CREATE DATABASE example; USE example; SHOW TABLES;
```

## High-Level Architecture

### Core Application Structure
This is a **Flask REST API for RSS feed management** with Auth0 authentication:

- **`src/main.py`**: Central application file containing all REST endpoints and RSS processing logic
- **`src/models.py`**: SQLAlchemy models defining the database schema
- **`src/utils.py`**: Authentication utilities, JWT handling, and helper functions
- **`src/admin.py`**: Flask-Admin configuration for database management
- **`src/services.py`**: External service integrations (RSS feed fetching)

### Database Architecture
The application uses **MySQL** with a multi-tenant feed management system:

**Core Models:**
- **User**: Auth0-authenticated users with role-based access
- **Feed**: RSS feed sources with public sharing tokens
- **Story**: Individual RSS feed items with JSON metadata storage
- **UserFeed**: Many-to-many relationship tracking user subscriptions
- **UserStory**: User-specific story states (saved, watched)

**Legacy Models** (inherited from previous version):
- Person, TextFile, FeedPost, Todo - these appear to be from an older system

### Key Features & Workflow

**RSS Feed Processing:**
1. Users import RSS feeds via URL
2. Raw XML is parsed and normalized to JSON
3. Stories are extracted and stored with custom metadata
4. Feeds can be made public via shareable tokens
5. Public feeds can export as RSS or JSON

**Authentication Flow:**
- Auth0 JWT tokens required for all endpoints
- Role-based access control (Admin vs regular users)  
- Automatic user creation from Auth0 profile data

**API Structure:**
- `/feeds` - CRUD operations for RSS feeds
- `/stories` - Story management with pagination  
- `/admin/*` - Admin-only user management
- `/feeds/public/*` - Public feed sharing (no auth required)

## Important Development Notes

### Database Considerations
- **Always run migrations** after model changes: `pipenv run migrate && pipenv run upgrade`
- Database connection string must be set in `.env` as `DB_CONNECTION_STRING`
- The app supports both MySQL and PostgreSQL (psycopg2-binary included)

### Auth0 Configuration
Required environment variables:
- `AUTH0_DOMAIN`
- `API_AUDIENCE` 
- `JWT_SECRET_KEY`

Custom claims are expected at: `https://voluble-boba-2e3a2e.netlify.app/email` and `/roles`

### RSS Processing Architecture
- **Raw XML preservation**: Original feed content stored for re-export
- **Flexible metadata**: Custom fields captured in `custom_metadata` JSON column
- **Bi-directional conversion**: JSON ↔ RSS with metadata flattening options
- **Public sharing**: UUID-based tokens for anonymous access

### Legacy Code Warning  
The codebase contains legacy models (Person, TextFile, FeedPost) that are still referenced in admin.py but may not be actively used. Consider these when making schema changes.

### Admin Interface
Flask-Admin is configured for database management at `/admin/` route. Admin users (with "Admin" role) can manage all users and data through the web interface.

## Security Guidelines

### Environment Variables & Secrets
- **NEVER commit `.env` files** - they contain sensitive information including database credentials and Auth0 secrets
- All secrets must be stored in `.env` file and loaded via `os.environ.get()`
- Required environment variables:
  - `DB_CONNECTION_STRING` - Database connection with credentials
  - `JWT_SECRET_KEY` - JWT signing secret
  - `AUTH0_DOMAIN` - Auth0 tenant domain
  - `AUTH0_CLIENT_ID` - Auth0 application client ID
  - `AUTH0_CLIENT_SECRET` - Auth0 application secret
  - `API_AUDIENCE` - Auth0 API identifier

### Hardcoded Values Warning
- The Auth0 custom claims namespace `https://voluble-boba-2e3a2e.netlify.app` is hardcoded in `utils.py`
- This should be moved to an environment variable if the frontend URL changes

### Database Security
- Database passwords are stored in connection string - ensure strong passwords
- Use separate database users for development vs production
- Regularly rotate database credentials

### Auth0 Security
- Auth0 tokens have expiration times configured (15min access, 30 days refresh)
- RSA256 algorithm used for JWT verification
- Role-based access control implemented for admin functions
