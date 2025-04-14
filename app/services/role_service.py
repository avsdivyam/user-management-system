from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import List, Optional, Dict, Any
from app.models.user import Role, Permission, AuditLog, user_roles, role_permissions
from datetime import datetime

def create_role(db: Session, role_data: Dict[str, Any], actor_id: int) -> Role:
    """
    Create a new role
    """
    # Create role object
    role = Role(
        name=role_data.get("name"),
        description=role_data.get("description"),
        is_system_role=role_data.get("is_system_role", False),
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    
    # Add permissions if provided
    if "permissions" in role_data and role_data["permissions"]:
        permissions = db.query(Permission).filter(Permission.name.in_(role_data["permissions"])).all()
        role.permissions = permissions
    
    # Add to database
    db.add(role)
    db.commit()
    db.refresh(role)
    
    # Log role creation
    log_activity(db, actor_id, "role_created", "roles", role.id, 
                f"Role {role.name} created", role_data.get("ip_address"), role_data.get("user_agent"))
    
    return role

def get_role_by_id(db: Session, role_id: int) -> Optional[Role]:
    """
    Get a role by ID
    """
    return db.query(Role).filter(Role.id == role_id).first()

def get_role_by_name(db: Session, name: str) -> Optional[Role]:
    """
    Get a role by name
    """
    return db.query(Role).filter(Role.name == name).first()

def get_roles(db: Session, skip: int = 0, limit: int = 100, search: str = None) -> List[Role]:
    """
    Get a list of roles with optional search
    """
    query = db.query(Role)
    
    if search:
        query = query.filter(
            or_(
                Role.name.ilike(f"%{search}%"),
                Role.description.ilike(f"%{search}%")
            )
        )
    
    return query.offset(skip).limit(limit).all()

def update_role(db: Session, role_id: int, role_data: Dict[str, Any], actor_id: int) -> Optional[Role]:
    """
    Update a role
    """
    role = get_role_by_id(db, role_id)
    if not role:
        return None
    
    # Check if this is a system role and we're trying to change the name
    if role.is_system_role and "name" in role_data and role_data["name"] != role.name:
        raise ValueError("Cannot change the name of a system role")
    
    # Update role fields
    if "name" in role_data:
        role.name = role_data["name"]
    if "description" in role_data:
        role.description = role_data["description"]
    
    # Update permissions if provided
    if "permissions" in role_data:
        permissions = db.query(Permission).filter(Permission.name.in_(role_data["permissions"])).all()
        role.permissions = permissions
    
    role.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(role)
    
    # Log role update
    log_activity(db, actor_id, "role_updated", "roles", role_id, 
                f"Role {role.name} updated", role_data.get("ip_address"), role_data.get("user_agent"))
    
    return role

def delete_role(db: Session, role_id: int, actor_id: int, ip_address: str = None, user_agent: str = None) -> bool:
    """
    Delete a role
    """
    role = get_role_by_id(db, role_id)
    if not role:
        return False
    
    # Check if this is a system role
    if role.is_system_role:
        raise ValueError("Cannot delete a system role")
    
    role_name = role.name
    
    # Delete role
    db.delete(role)
    db.commit()
    
    # Log role deletion
    log_activity(db, actor_id, "role_deleted", "roles", role_id, 
                f"Role {role_name} deleted", ip_address, user_agent)
    
    return True

def create_permission(db: Session, permission_data: Dict[str, Any], actor_id: int) -> Permission:
    """
    Create a new permission
    """
    # Create permission object
    permission = Permission(
        name=permission_data.get("name"),
        description=permission_data.get("description"),
        resource=permission_data.get("resource"),
        action=permission_data.get("action"),
        created_at=datetime.utcnow()
    )
    
    # Add to database
    db.add(permission)
    db.commit()
    db.refresh(permission)
    
    # Log permission creation
    log_activity(db, actor_id, "permission_created", "permissions", permission.id, 
                f"Permission {permission.name} created", permission_data.get("ip_address"), permission_data.get("user_agent"))
    
    return permission

def get_permission_by_id(db: Session, permission_id: int) -> Optional[Permission]:
    """
    Get a permission by ID
    """
    return db.query(Permission).filter(Permission.id == permission_id).first()

def get_permission_by_name(db: Session, name: str) -> Optional[Permission]:
    """
    Get a permission by name
    """
    return db.query(Permission).filter(Permission.name == name).first()

def get_permissions(db: Session, skip: int = 0, limit: int = 100, search: str = None, resource: str = None) -> List[Permission]:
    """
    Get a list of permissions with optional search and resource filter
    """
    query = db.query(Permission)
    
    if search:
        query = query.filter(
            or_(
                Permission.name.ilike(f"%{search}%"),
                Permission.description.ilike(f"%{search}%"),
                Permission.resource.ilike(f"%{search}%"),
                Permission.action.ilike(f"%{search}%")
            )
        )
    
    if resource:
        query = query.filter(Permission.resource == resource)
    
    return query.offset(skip).limit(limit).all()

def update_permission(db: Session, permission_id: int, permission_data: Dict[str, Any], actor_id: int) -> Optional[Permission]:
    """
    Update a permission
    """
    permission = get_permission_by_id(db, permission_id)
    if not permission:
        return None
    
    # Update permission fields
    if "name" in permission_data:
        permission.name = permission_data["name"]
    if "description" in permission_data:
        permission.description = permission_data["description"]
    if "resource" in permission_data:
        permission.resource = permission_data["resource"]
    if "action" in permission_data:
        permission.action = permission_data["action"]
    
    db.commit()
    db.refresh(permission)
    
    # Log permission update
    log_activity(db, actor_id, "permission_updated", "permissions", permission_id, 
                f"Permission {permission.name} updated", permission_data.get("ip_address"), permission_data.get("user_agent"))
    
    return permission

def delete_permission(db: Session, permission_id: int, actor_id: int, ip_address: str = None, user_agent: str = None) -> bool:
    """
    Delete a permission
    """
    permission = get_permission_by_id(db, permission_id)
    if not permission:
        return False
    
    permission_name = permission.name
    
    # Delete permission
    db.delete(permission)
    db.commit()
    
    # Log permission deletion
    log_activity(db, actor_id, "permission_deleted", "permissions", permission_id, 
                f"Permission {permission_name} deleted", ip_address, user_agent)
    
    return True

def assign_role_to_user(db: Session, user_id: int, role_id: int, actor_id: int) -> bool:
    """
    Assign a role to a user
    """
    # Check if the role assignment already exists
    existing = db.query(user_roles).filter_by(user_id=user_id, role_id=role_id).first()
    if existing:
        return False
    
    # Add the role assignment
    stmt = user_roles.insert().values(user_id=user_id, role_id=role_id)
    db.execute(stmt)
    db.commit()
    
    # Get role name for logging
    role = get_role_by_id(db, role_id)
    
    # Log role assignment
    log_activity(db, actor_id, "role_assigned", "users", user_id, 
                f"Role {role.name if role else role_id} assigned to user {user_id}")
    
    return True

def remove_role_from_user(db: Session, user_id: int, role_id: int, actor_id: int) -> bool:
    """
    Remove a role from a user
    """
    # Check if the role assignment exists
    existing = db.query(user_roles).filter_by(user_id=user_id, role_id=role_id).first()
    if not existing:
        return False
    
    # Remove the role assignment
    stmt = user_roles.delete().where(user_roles.c.user_id == user_id).where(user_roles.c.role_id == role_id)
    db.execute(stmt)
    db.commit()
    
    # Get role name for logging
    role = get_role_by_id(db, role_id)
    
    # Log role removal
    log_activity(db, actor_id, "role_removed", "users", user_id, 
                f"Role {role.name if role else role_id} removed from user {user_id}")
    
    return True

def assign_permission_to_role(db: Session, role_id: int, permission_id: int, actor_id: int) -> bool:
    """
    Assign a permission to a role
    """
    # Check if the permission assignment already exists
    existing = db.query(role_permissions).filter_by(role_id=role_id, permission_id=permission_id).first()
    if existing:
        return False
    
    # Add the permission assignment
    stmt = role_permissions.insert().values(role_id=role_id, permission_id=permission_id)
    db.execute(stmt)
    db.commit()
    
    # Get role and permission names for logging
    role = get_role_by_id(db, role_id)
    permission = get_permission_by_id(db, permission_id)
    
    # Log permission assignment
    log_activity(db, actor_id, "permission_assigned", "roles", role_id, 
                f"Permission {permission.name if permission else permission_id} assigned to role {role.name if role else role_id}")
    
    return True

def remove_permission_from_role(db: Session, role_id: int, permission_id: int, actor_id: int) -> bool:
    """
    Remove a permission from a role
    """
    # Check if the permission assignment exists
    existing = db.query(role_permissions).filter_by(role_id=role_id, permission_id=permission_id).first()
    if not existing:
        return False
    
    # Remove the permission assignment
    stmt = role_permissions.delete().where(role_permissions.c.role_id == role_id).where(role_permissions.c.permission_id == permission_id)
    db.execute(stmt)
    db.commit()
    
    # Get role and permission names for logging
    role = get_role_by_id(db, role_id)
    permission = get_permission_by_id(db, permission_id)
    
    # Log permission removal
    log_activity(db, actor_id, "permission_removed", "roles", role_id, 
                f"Permission {permission.name if permission else permission_id} removed from role {role.name if role else role_id}")
    
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