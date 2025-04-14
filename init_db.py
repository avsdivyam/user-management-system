import os
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import yaml

from app.models.user import Base, User, Role, Permission, ServiceFlag
from app.database import get_db

def init_db():
    # Load configuration
    config_path = os.path.join(os.path.dirname(__file__), 'config', 'config_file.yaml')

    try:
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)
        db_config = config.get('database', {})
    except Exception as e:
        print(f"Error loading configuration: {e}")
        # Default configuration
        db_config = {
            'host': 'localhost',
            'port': 5432,
            'name': 'user_management',
            'user': 'postgres',
            'password': 'postgres',
        }

    # Construct database URL
    DB_URL = f"postgresql://{db_config.get('user')}:{db_config.get('password')}@{db_config.get('host')}:{db_config.get('port')}/{db_config.get('name')}"

    # Create SQLAlchemy engine
    engine = create_engine(DB_URL)

    # Create all tables
    Base.metadata.create_all(engine)
    
    # Create session
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    
    try:
        # Check if we already have a superadmin role
        superadmin_role = db.query(Role).filter(Role.name == "super_admin").first()
        if not superadmin_role:
            print("Creating initial roles...")
            # Create roles
            superadmin_role = Role(
                name="super_admin",
                description="Super Administrator with full system access",
                is_system_role=True
            )
            admin_role = Role(
                name="admin",
                description="Administrator with management access",
                is_system_role=True
            )
            user_role = Role(
                name="user",
                description="Regular user with basic access",
                is_system_role=True
            )
            
            db.add_all([superadmin_role, admin_role, user_role])
            db.commit()
            
            print("Creating permissions...")
            # Create permissions
            permissions = [
                Permission(name="user:create", description="Create users", resource="users", action="create"),
                Permission(name="user:read", description="Read users", resource="users", action="read"),
                Permission(name="user:update", description="Update users", resource="users", action="update"),
                Permission(name="user:delete", description="Delete users", resource="users", action="delete"),
                Permission(name="role:create", description="Create roles", resource="roles", action="create"),
                Permission(name="role:read", description="Read roles", resource="roles", action="read"),
                Permission(name="role:update", description="Update roles", resource="roles", action="update"),
                Permission(name="role:delete", description="Delete roles", resource="roles", action="delete"),
                Permission(name="permission:create", description="Create permissions", resource="permissions", action="create"),
                Permission(name="permission:read", description="Read permissions", resource="permissions", action="read"),
                Permission(name="permission:update", description="Update permissions", resource="permissions", action="update"),
                Permission(name="permission:delete", description="Delete permissions", resource="permissions", action="delete"),
                Permission(name="service_flag:create", description="Create service flags", resource="service_flags", action="create"),
                Permission(name="service_flag:read", description="Read service flags", resource="service_flags", action="read"),
                Permission(name="service_flag:update", description="Update service flags", resource="service_flags", action="update"),
                Permission(name="service_flag:delete", description="Delete service flags", resource="service_flags", action="delete"),
                Permission(name="audit:read", description="Read audit logs", resource="audit_logs", action="read"),
            ]
            
            db.add_all(permissions)
            db.commit()
            
            print("Assigning permissions to roles...")
            # Assign permissions to roles
            superadmin_role = db.query(Role).filter(Role.name == "super_admin").first()
            admin_role = db.query(Role).filter(Role.name == "admin").first()
            user_role = db.query(Role).filter(Role.name == "user").first()
            
            # Super admin gets all permissions
            all_permissions = db.query(Permission).all()
            superadmin_role.permissions = all_permissions
            
            # Admin gets most permissions except some critical ones
            admin_permissions = db.query(Permission).filter(
                Permission.name.notin_(["role:delete", "permission:delete"])
            ).all()
            admin_role.permissions = admin_permissions
            
            # Regular users get basic read permissions
            user_permissions = db.query(Permission).filter(
                Permission.name.in_(["user:read", "role:read"])
            ).all()
            user_role.permissions = user_permissions
            
            db.commit()
            
            print("Creating default superadmin user...")
            # Create default superadmin user
            superadmin = User(
                username="superadmin",
                email="superadmin@example.com",
                first_name="Super",
                last_name="Admin",
                is_active=True,
                is_verified=True
            )
            superadmin.set_password("superadmin123")  # This should be changed immediately
            superadmin.roles = [superadmin_role]
            
            db.add(superadmin)
            db.commit()
            
            print("Creating service flags...")
            # Create service flags
            service_flags = [
                ServiceFlag(
                    name="user_registration",
                    description="Allow new user registration",
                    is_enabled=True
                ),
                ServiceFlag(
                    name="password_reset",
                    description="Allow password reset functionality",
                    is_enabled=True
                ),
                ServiceFlag(
                    name="audit_logging",
                    description="Enable audit logging",
                    is_enabled=True
                ),
                ServiceFlag(
                    name="maintenance_mode",
                    description="System maintenance mode",
                    is_enabled=False,
                    is_super_admin_only=True
                )
            ]
            
            db.add_all(service_flags)
            db.commit()
            
            print("Database initialization completed successfully!")
        else:
            print("Database already initialized.")
    
    except Exception as e:
        print(f"Error initializing database: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    init_db()