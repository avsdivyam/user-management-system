from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import List, Optional, Dict, Any
from app.models.user import User, Role, Permission, UserSettings, AuditLog
from datetime import datetime
import uuid

def create_user(db: Session, user_data: Dict[str, Any]) -> User:
    """
    Create a new user
    """
    # Create user object
    user = User(
        username=user_data.get("username"),
        email=user_data.get("email"),
        first_name=user_data.get("first_name"),
        last_name=user_data.get("last_name"),
        is_active=user_data.get("is_active", True),
        is_verified=user_data.get("is_verified", False),
        verification_token=str(uuid.uuid4()) if not user_data.get("is_verified", False) else None,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    
    # Set password
    user.set_password(user_data.get("password"))
    
    # Add roles if provided
    if "roles" in user_data and user_data["roles"]:
        roles = db.query(Role).filter(Role.name.in_(user_data["roles"])).all()
        user.roles = roles
    
    # Add to database
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Create user settings
    settings = UserSettings(
        user_id=user.id,
        theme=user_data.get("theme", "light"),
        notifications_enabled=user_data.get("notifications_enabled", True),
        two_factor_enabled=user_data.get("two_factor_enabled", False),
        language=user_data.get("language", "en"),
        timezone=user_data.get("timezone", "UTC")
    )
    
    db.add(settings)
    db.commit()
    
    # Log user creation
    log_user_activity(db, user.id, "user_created", "users", user.id, 
                     f"User {user.username} created", user_data.get("ip_address"), user_data.get("user_agent"))
    
    return user

def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
    """
    Get a user by ID
    """
    return db.query(User).filter(User.id == user_id).first()

def get_user_by_username(db: Session, username: str) -> Optional[User]:
    """
    Get a user by username
    """
    return db.query(User).filter(User.username == username).first()

def get_user_by_email(db: Session, email: str) -> Optional[User]:
    """
    Get a user by email
    """
    return db.query(User).filter(User.email == email).first()

def get_users(db: Session, skip: int = 0, limit: int = 100, search: str = None) -> List[User]:
    """
    Get a list of users with optional search
    """
    query = db.query(User)
    
    if search:
        query = query.filter(
            or_(
                User.username.ilike(f"%{search}%"),
                User.email.ilike(f"%{search}%"),
                User.first_name.ilike(f"%{search}%"),
                User.last_name.ilike(f"%{search}%")
            )
        )
    
    return query.offset(skip).limit(limit).all()

def update_user(db: Session, user_id: int, user_data: Dict[str, Any]) -> Optional[User]:
    """
    Update a user
    """
    user = get_user_by_id(db, user_id)
    if not user:
        return None
    
    # Update user fields
    if "username" in user_data:
        user.username = user_data["username"]
    if "email" in user_data:
        user.email = user_data["email"]
    if "first_name" in user_data:
        user.first_name = user_data["first_name"]
    if "last_name" in user_data:
        user.last_name = user_data["last_name"]
    if "is_active" in user_data:
        user.is_active = user_data["is_active"]
    if "is_verified" in user_data:
        user.is_verified = user_data["is_verified"]
    if "password" in user_data:
        user.set_password(user_data["password"])
    
    # Update roles if provided
    if "roles" in user_data:
        roles = db.query(Role).filter(Role.name.in_(user_data["roles"])).all()
        user.roles = roles
    
    user.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(user)
    
    # Update user settings if provided
    if any(key in user_data for key in ["theme", "notifications_enabled", "two_factor_enabled", "language", "timezone"]):
        settings = db.query(UserSettings).filter(UserSettings.user_id == user_id).first()
        
        if not settings:
            settings = UserSettings(user_id=user_id)
            db.add(settings)
        
        if "theme" in user_data:
            settings.theme = user_data["theme"]
        if "notifications_enabled" in user_data:
            settings.notifications_enabled = user_data["notifications_enabled"]
        if "two_factor_enabled" in user_data:
            settings.two_factor_enabled = user_data["two_factor_enabled"]
        if "language" in user_data:
            settings.language = user_data["language"]
        if "timezone" in user_data:
            settings.timezone = user_data["timezone"]
        
        db.commit()
    
    # Log user update
    log_user_activity(db, user_id, "user_updated", "users", user_id, 
                     f"User {user.username} updated", user_data.get("ip_address"), user_data.get("user_agent"))
    
    return user

def delete_user(db: Session, user_id: int, actor_id: int, ip_address: str = None, user_agent: str = None) -> bool:
    """
    Delete a user
    """
    user = get_user_by_id(db, user_id)
    if not user:
        return False
    
    username = user.username
    
    # Delete user settings
    db.query(UserSettings).filter(UserSettings.user_id == user_id).delete()
    
    # Delete user
    db.delete(user)
    db.commit()
    
    # Log user deletion
    log_user_activity(db, actor_id, "user_deleted", "users", user_id, 
                     f"User {username} deleted", ip_address, user_agent)
    
    return True

def verify_user(db: Session, token: str) -> Optional[User]:
    """
    Verify a user using verification token
    """
    user = db.query(User).filter(User.verification_token == token).first()
    if not user:
        return None
    
    user.is_verified = True
    user.verification_token = None
    user.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(user)
    
    # Log user verification
    log_user_activity(db, user.id, "user_verified", "users", user.id, 
                     f"User {user.username} verified")
    
    return user

def reset_password(db: Session, token: str, new_password: str) -> Optional[User]:
    """
    Reset a user's password using reset token
    """
    user = db.query(User).filter(User.reset_token == token).first()
    if not user:
        return None
    
    user.set_password(new_password)
    user.reset_token = None
    user.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(user)
    
    # Log password reset
    log_user_activity(db, user.id, "password_reset", "users", user.id, 
                     f"Password reset for user {user.username}")
    
    return user

def generate_password_reset_token(db: Session, email: str) -> Optional[str]:
    """
    Generate a password reset token for a user
    """
    user = get_user_by_email(db, email)
    if not user:
        return None
    
    token = user.generate_reset_token()
    user.updated_at = datetime.utcnow()
    
    db.commit()
    
    # Log password reset request
    log_user_activity(db, user.id, "password_reset_requested", "users", user.id, 
                     f"Password reset requested for user {user.username}")
    
    return token

def log_user_activity(db: Session, user_id: int, action: str, resource: str = None, 
                     resource_id: int = None, details: str = None, ip_address: str = None, 
                     user_agent: str = None) -> AuditLog:
    """
    Log user activity
    """
    log = AuditLog(
        user_id=user_id,
        action=action,
        resource=resource,
        resource_id=resource_id,
        details=details,
        ip_address=ip_address,
        user_agent=user_agent,
        timestamp=datetime.utcnow()
    )
    
    db.add(log)
    db.commit()
    db.refresh(log)
    
    return log

def update_last_login(db: Session, user_id: int) -> Optional[User]:
    """
    Update a user's last login timestamp
    """
    user = get_user_by_id(db, user_id)
    if not user:
        return None
    
    user.last_login = datetime.utcnow()
    db.commit()
    db.refresh(user)
    
    return user