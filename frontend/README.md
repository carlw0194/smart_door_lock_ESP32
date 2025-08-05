# Frontend

Web interface and user experience components for the smart door lock system.

## Contents

- `templates/` - HTML templates (Jinja2)
- `static/css/` - Stylesheets
- `static/js/` - JavaScript files
- `static/` - Static assets (images, fonts, etc.)

## Team Responsibility

- Frontend developers
- UI/UX designers
- Web developers

## Pages

- **Dashboard** - Main overview with statistics
- **Users** - User management interface
- **Access Logs** - Access history and monitoring
- **Analytics** - ML insights and security analytics
- **Security Events** - Security audit trail
- **API Keys** - ESP32 device management
- **Settings** - Admin configuration

## Templates

- `base.html` - Base template with navigation
- `dashboard.html` - Main dashboard
- `users.html` - User listing
- `add_user.html` - Add new user form
- `edit_user.html` - Edit user form
- `access_logs.html` - Access logs table
- `analytics.html` - ML analytics dashboard
- `security_events.html` - Security events log
- `api_keys.html` - API key management
- `login.html` - Admin login page
- `index.html` - Landing page

## Technology Stack

- **Templates**: Jinja2 (Flask templating)
- **CSS**: Bootstrap 5 + Custom styles
- **JavaScript**: Vanilla JS + Chart.js (for analytics)
- **Icons**: Font Awesome
- **Responsive**: Mobile-first design

## Development

Frontend templates are served by the Flask backend but organized separately for clear separation of concerns.
