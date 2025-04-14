# User Management System

A comprehensive user management system with role-based access control, service flags, and audit logging.

## Features

- User authentication and authorization
- Role-based access control (RBAC)
- Permission management
- Service flags for feature toggling
- Audit logging
- User settings and preferences
- Admin dashboard
- Super admin controls

## Tech Stack

- **Backend**: FastAPI, SQLAlchemy, Pydantic
- **Database**: PostgreSQL
- **Authentication**: JWT
- **Frontend**: Jinja2 Templates, Bootstrap 5, Chart.js

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/user-management-system.git
   cd user-management-system
   ```

2. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Configure the database in `config/config_file.yaml`

5. Run the application:
   ```
   uvicorn main:app --reload
   ```

6. Access the application at http://localhost:8095

## Default Credentials

- **Username**: superadmin
- **Password**: superadmin123

**Important**: Change the default password immediately after first login.

## Project Structure

```
user-management-system/
├── app/
│   ├── controllers/       # API endpoints
│   ├── models/            # Database models
│   ├── schemas/           # Pydantic schemas
│   ├── services/          # Business logic
│   └── database.py        # Database connection
├── config/                # Configuration files
├── static/                # Static assets
│   ├── css/
│   └── js/
├── templates/             # Jinja2 templates
├── main.py                # Application entry point
└── requirements.txt       # Dependencies
```

## Service Flags

Service flags allow you to enable or disable features at runtime. The system comes with several built-in flags:

- `user_registration`: Controls whether new users can register
- `password_reset`: Controls password reset functionality
- `audit_logging`: Controls audit logging
- `maintenance_mode`: Puts the system in maintenance mode (super admin only)

## Roles and Permissions

The system has three built-in roles:

- **Super Admin**: Full system access
- **Admin**: Management access with some restrictions
- **User**: Basic access

Permissions are organized by resource and action (e.g., `user:create`, `role:read`).

## License

MIT