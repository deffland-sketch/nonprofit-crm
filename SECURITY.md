# Security Features - WA Charters CRM

This document describes the security features implemented in the WA Charters CRM system.

## Features Overview

| Feature | Status | Description |
|---------|--------|-------------|
| Email Domain Restriction | Active | Only @wacharters.org emails can register |
| HTTPS Enforcement | Active (production) | Automatic HTTP to HTTPS redirect |
| Session Timeout | Active | 30-minute inactivity logout |
| Audit Logging | Active | Tracks all sensitive actions |
| Rate Limiting | Active | Prevents brute-force attacks |
| Role-Based Access Control | Active | Three permission levels |
| Password Reset | Active | Secure email-based reset |
| Security Headers | Active | XSS, clickjacking protection |
| File Upload Limits | Active | 10MB maximum |

## Email Domain Restriction

Only the following can register:
- Any `@wacharters.org` email address
- `deffland@summitps.org` (exception)

## User Roles

| Role | View | Create/Edit | Delete | Import/Export | Admin |
|------|------|-------------|--------|---------------|-------|
| Viewer | Yes | No | No | No | No |
| Editor | Yes | Yes | No | No | No |
| Admin | Yes | Yes | Yes | Yes | Yes |

- First registered user automatically becomes Admin
- Admins can change roles at `/admin/users`

## Audit Log

Tracked actions:
- `login` / `logout` / `login_failed`
- `view` / `create` / `edit` / `delete`
- `export`
- `password_reset_request` / `password_reset`
- `update_role`

View audit log at `/admin/audit-log` (Admin only)

## Rate Limits

- Login: 5 attempts per minute
- Registration: 3 attempts per minute
- Password reset: 3 attempts per minute
- Global: 200 requests/day, 50 requests/hour

## Deployment Checklist

### Required Environment Variables

```bash
# REQUIRED - Generate a secure random key
SECRET_KEY=your-secure-random-key-here

# REQUIRED for production
FLASK_ENV=production
DATABASE_URL=postgresql://user:pass@host:port/dbname

# REQUIRED for password reset
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=noreply@wacharters.org
```

### First-Time Setup

1. Set environment variables
2. Run database migration: `python migrate.py`
3. Register first user (becomes Admin automatically)

### Upgrading Existing Installation

1. Update code from repository
2. Install new requirements: `pip install -r requirements.txt`
3. Run migration: `python migrate.py`
4. Restart application

## Security Headers

All responses include:
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Content-Security-Policy: ...`
- `Permissions-Policy: geolocation=(), microphone=(), camera=()`

## Session Security

- Cookies: HttpOnly, SameSite=Lax, Secure (production)
- 30-minute inactivity timeout
- Session refreshes on activity

## Recommendations

1. **Use strong passwords**: Minimum 8 characters required
2. **Keep software updated**: Regularly update dependencies
3. **Monitor audit logs**: Review for suspicious activity
4. **Backup database**: Regular encrypted backups
5. **Use HTTPS**: Always in production

## Reporting Security Issues

Contact the system administrator immediately if you discover a security vulnerability.
