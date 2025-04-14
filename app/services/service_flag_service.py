from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import List, Optional, Dict, Any
from app.models.user import ServiceFlag, AuditLog
from datetime import datetime

def create_service_flag(db: Session, flag_data: Dict[str, Any], actor_id: int) -> ServiceFlag:
    """
    Create a new service flag
    """
    # Create service flag object
    flag = ServiceFlag(
        name=flag_data.get("name"),
        description=flag_data.get("description"),
        is_enabled=flag_data.get("is_enabled", True),
        is_developer_only=flag_data.get("is_developer_only", False),
        is_admin_only=flag_data.get("is_admin_only", False),
        is_super_admin_only=flag_data.get("is_super_admin_only", False),
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    
    # Add to database
    db.add(flag)
    db.commit()
    db.refresh(flag)
    
    # Log flag creation
    log_activity(db, actor_id, "service_flag_created", "service_flags", flag.id, 
                f"Service flag {flag.name} created", flag_data.get("ip_address"), flag_data.get("user_agent"))
    
    return flag

def get_service_flag_by_id(db: Session, flag_id: int) -> Optional[ServiceFlag]:
    """
    Get a service flag by ID
    """
    return db.query(ServiceFlag).filter(ServiceFlag.id == flag_id).first()

def get_service_flag_by_name(db: Session, name: str) -> Optional[ServiceFlag]:
    """
    Get a service flag by name
    """
    return db.query(ServiceFlag).filter(ServiceFlag.name == name).first()

def get_service_flags(db: Session, skip: int = 0, limit: int = 100, search: str = None, 
                     include_developer_only: bool = False, include_admin_only: bool = False, 
                     include_super_admin_only: bool = False) -> List[ServiceFlag]:
    """
    Get a list of service flags with optional filters
    """
    query = db.query(ServiceFlag)
    
    if search:
        query = query.filter(
            or_(
                ServiceFlag.name.ilike(f"%{search}%"),
                ServiceFlag.description.ilike(f"%{search}%")
            )
        )
    
    # Apply access filters
    if not include_developer_only:
        query = query.filter(ServiceFlag.is_developer_only == False)
    
    if not include_admin_only:
        query = query.filter(ServiceFlag.is_admin_only == False)
    
    if not include_super_admin_only:
        query = query.filter(ServiceFlag.is_super_admin_only == False)
    
    return query.offset(skip).limit(limit).all()

def update_service_flag(db: Session, flag_id: int, flag_data: Dict[str, Any], actor_id: int) -> Optional[ServiceFlag]:
    """
    Update a service flag
    """
    flag = get_service_flag_by_id(db, flag_id)
    if not flag:
        return None
    
    # Update flag fields
    if "name" in flag_data:
        flag.name = flag_data["name"]
    if "description" in flag_data:
        flag.description = flag_data["description"]
    if "is_enabled" in flag_data:
        flag.is_enabled = flag_data["is_enabled"]
    if "is_developer_only" in flag_data:
        flag.is_developer_only = flag_data["is_developer_only"]
    if "is_admin_only" in flag_data:
        flag.is_admin_only = flag_data["is_admin_only"]
    if "is_super_admin_only" in flag_data:
        flag.is_super_admin_only = flag_data["is_super_admin_only"]
    
    flag.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(flag)
    
    # Log flag update
    log_activity(db, actor_id, "service_flag_updated", "service_flags", flag_id, 
                f"Service flag {flag.name} updated", flag_data.get("ip_address"), flag_data.get("user_agent"))
    
    return flag

def delete_service_flag(db: Session, flag_id: int, actor_id: int, ip_address: str = None, user_agent: str = None) -> bool:
    """
    Delete a service flag
    """
    flag = get_service_flag_by_id(db, flag_id)
    if not flag:
        return False
    
    flag_name = flag.name
    
    # Delete flag
    db.delete(flag)
    db.commit()
    
    # Log flag deletion
    log_activity(db, actor_id, "service_flag_deleted", "service_flags", flag_id, 
                f"Service flag {flag_name} deleted", ip_address, user_agent)
    
    return True

def check_service_flag_access(db: Session, flag_name: str, is_developer: bool = False, 
                             is_admin: bool = False, is_super_admin: bool = False) -> bool:
    """
    Check if a user has access to a service flag based on their role
    """
    flag = get_service_flag_by_name(db, flag_name)
    if not flag:
        return False
    
    # Check if the flag is enabled
    if not flag.is_enabled:
        return False
    
    # Check access based on role
    if flag.is_developer_only and not is_developer:
        return False
    
    if flag.is_admin_only and not is_admin and not is_super_admin:
        return False
    
    if flag.is_super_admin_only and not is_super_admin:
        return False
    
    return True

def log_activity(db: Session, user_id: int, action: str, resource: str = None, 
               resource_id: int = None, details: str = None, ip_address: str = None, 
               user_agent: str = None) -> AuditLog:
    """
    Log activity
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