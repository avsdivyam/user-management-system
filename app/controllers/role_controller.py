from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session
from typing import List, Optional
import math

from app.database import get_db
from app.schemas.role import (
    RoleCreate, RoleUpdate, RoleInDB, RoleList, 
    PermissionCreate, PermissionUpdate, PermissionInDB, PermissionList,
    RoleAssignment, PermissionAssignment
)
from app.services.auth_service import (
    get_current_user, check_admin_access, check_super_admin_access, check_permission
)
from app.services.role_service import (
    create_role, get_role_by_id, get_roles, update_role, delete_role,
    create_permission, get_permission_by_id, get_permissions, update_permission, delete_permission,
    assign_role_to_user, remove_role_from_user, assign_permission_to_role, remove_permission_from_role
)
from app.models.user import User, Role, Permission

router = APIRouter()

# Role endpoints
@router.post("/", response_model=RoleInDB, status_code=status.HTTP_201_CREATED)
async def create_new_role(
    role_data: RoleCreate,
    db: Session = Depends(get_db),
    request: Request = None,
    current_user: User = Depends(check_permission("role:create"))
):
    # Check if role with same name already exists
    existing_role = db.query(Role).filter(Role.name == role_data.name).first()
    if existing_role:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role with this name already exists"
        )
    
    # Add request metadata
    role_dict = role_data.dict()
    role_dict["ip_address"] = request.client.host if request else None
    role_dict["user_agent"] = request.headers.get("User-Agent") if request else None
    
    # Create role
    role = create_role(db, role_dict, current_user.id)
    
    return role

@router.get("/", response_model=RoleList)
async def read_roles(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(check_permission("role:read"))
):
    roles = get_roles(db, skip, limit, search)
    total = db.query(Role).count()
    
    return {
        "roles": roles,
        "total": total,
        "page": math.floor(skip / limit) + 1,
        "page_size": limit,
        "total_pages": math.ceil(total / limit)
    }

@router.get("/{role_id}", response_model=RoleInDB)
async def read_role(
    role_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(check_permission("role:read"))
):
    role = get_role_by_id(db, role_id)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )
    
    return role

@router.put("/{role_id}", response_model=RoleInDB)
async def update_role_info(
    role_id: int,
    role_data: RoleUpdate,
    db: Session = Depends(get_db),
    request: Request = None,
    current_user: User = Depends(check_permission("role:update"))
):
    # Check if role exists
    role = get_role_by_id(db, role_id)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )
    
    # Only super admins can modify system roles
    if role.is_system_role and not current_user.is_super_admin():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only super admins can modify system roles"
        )
    
    # Add request metadata
    role_dict = role_data.dict(exclude_unset=True)
    role_dict["ip_address"] = request.client.host if request else None
    role_dict["user_agent"] = request.headers.get("User-Agent") if request else None
    
    try:
        # Update role
        updated_role = update_role(db, role_id, role_dict, current_user.id)
        return updated_role
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.delete("/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role_record(
    role_id: int,
    db: Session = Depends(get_db),
    request: Request = None,
    current_user: User = Depends(check_permission("role:delete"))
):
    # Check if role exists
    role = get_role_by_id(db, role_id)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )
    
    # Only super admins can delete roles
    if not current_user.is_super_admin():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only super admins can delete roles"
        )
    
    try:
        # Delete role
        ip_address = request.client.host if request else None
        user_agent = request.headers.get("User-Agent") if request else None
        
        delete_role(db, role_id, current_user.id, ip_address, user_agent)
        
        return None
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

# Permission endpoints
@router.post("/permissions", response_model=PermissionInDB, status_code=status.HTTP_201_CREATED)
async def create_new_permission(
    permission_data: PermissionCreate,
    db: Session = Depends(get_db),
    request: Request = None,
    current_user: User = Depends(check_super_admin_access)
):
    # Check if permission with same name already exists
    existing_permission = db.query(Permission).filter(Permission.name == permission_data.name).first()
    if existing_permission:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Permission with this name already exists"
        )
    
    # Add request metadata
    permission_dict = permission_data.dict()
    permission_dict["ip_address"] = request.client.host if request else None
    permission_dict["user_agent"] = request.headers.get("User-Agent") if request else None
    
    # Create permission
    permission = create_permission(db, permission_dict, current_user.id)
    
    return permission

@router.get("/permissions", response_model=PermissionList)
async def read_permissions(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    resource: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(check_permission("permission:read"))
):
    permissions = get_permissions(db, skip, limit, search, resource)
    total = db.query(Permission).count()
    
    return {
        "permissions": permissions,
        "total": total,
        "page": math.floor(skip / limit) + 1,
        "page_size": limit,
        "total_pages": math.ceil(total / limit)
    }

@router.get("/permissions/{permission_id}", response_model=PermissionInDB)
async def read_permission(
    permission_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(check_permission("permission:read"))
):
    permission = get_permission_by_id(db, permission_id)
    if not permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission not found"
        )
    
    return permission

@router.put("/permissions/{permission_id}", response_model=PermissionInDB)
async def update_permission_info(
    permission_id: int,
    permission_data: PermissionUpdate,
    db: Session = Depends(get_db),
    request: Request = None,
    current_user: User = Depends(check_super_admin_access)
):
    # Check if permission exists
    permission = get_permission_by_id(db, permission_id)
    if not permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission not found"
        )
    
    # Add request metadata
    permission_dict = permission_data.dict(exclude_unset=True)
    permission_dict["ip_address"] = request.client.host if request else None
    permission_dict["user_agent"] = request.headers.get("User-Agent") if request else None
    
    # Update permission
    updated_permission = update_permission(db, permission_id, permission_dict, current_user.id)
    
    return updated_permission

@router.delete("/permissions/{permission_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_permission_record(
    permission_id: int,
    db: Session = Depends(get_db),
    request: Request = None,
    current_user: User = Depends(check_super_admin_access)
):
    # Check if permission exists
    permission = get_permission_by_id(db, permission_id)
    if not permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission not found"
        )
    
    # Delete permission
    ip_address = request.client.host if request else None
    user_agent = request.headers.get("User-Agent") if request else None
    
    delete_permission(db, permission_id, current_user.id, ip_address, user_agent)
    
    return None

# Role-User assignment endpoints
@router.post("/assign-to-user", status_code=status.HTTP_200_OK)
async def assign_role_to_user_endpoint(
    assignment: RoleAssignment,
    db: Session = Depends(get_db),
    current_user: User = Depends(check_admin_access)
):
    # Check if user exists
    user = db.query(User).filter(User.id == assignment.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Check if role exists
    role = get_role_by_id(db, assignment.role_id)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )
    
    # Only super admins can assign super_admin role
    if role.name == "super_admin" and not current_user.is_super_admin():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only super admins can assign the super_admin role"
        )
    
    # Assign role to user
    result = assign_role_to_user(db, assignment.user_id, assignment.role_id, current_user.id)
    
    if not result:
        return {"message": "Role is already assigned to user"}
    
    return {"message": f"Role '{role.name}' assigned to user successfully"}

@router.post("/remove-from-user", status_code=status.HTTP_200_OK)
async def remove_role_from_user_endpoint(
    assignment: RoleAssignment,
    db: Session = Depends(get_db),
    current_user: User = Depends(check_admin_access)
):
    # Check if user exists
    user = db.query(User).filter(User.id == assignment.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Check if role exists
    role = get_role_by_id(db, assignment.role_id)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )
    
    # Only super admins can remove super_admin role
    if role.name == "super_admin" and not current_user.is_super_admin():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only super admins can remove the super_admin role"
        )
    
    # Remove role from user
    result = remove_role_from_user(db, assignment.user_id, assignment.role_id, current_user.id)
    
    if not result:
        return {"message": "Role is not assigned to user"}
    
    return {"message": f"Role '{role.name}' removed from user successfully"}

# Permission-Role assignment endpoints
@router.post("/assign-permission", status_code=status.HTTP_200_OK)
async def assign_permission_to_role_endpoint(
    assignment: PermissionAssignment,
    db: Session = Depends(get_db),
    current_user: User = Depends(check_super_admin_access)
):
    # Check if role exists
    role = get_role_by_id(db, assignment.role_id)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )
    
    # Check if permission exists
    permission = get_permission_by_id(db, assignment.permission_id)
    if not permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission not found"
        )
    
    # Assign permission to role
    result = assign_permission_to_role(db, assignment.role_id, assignment.permission_id, current_user.id)
    
    if not result:
        return {"message": "Permission is already assigned to role"}
    
    return {"message": f"Permission '{permission.name}' assigned to role '{role.name}' successfully"}

@router.post("/remove-permission", status_code=status.HTTP_200_OK)
async def remove_permission_from_role_endpoint(
    assignment: PermissionAssignment,
    db: Session = Depends(get_db),
    current_user: User = Depends(check_super_admin_access)
):
    # Check if role exists
    role = get_role_by_id(db, assignment.role_id)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )
    
    # Check if permission exists
    permission = get_permission_by_id(db, assignment.permission_id)
    if not permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission not found"
        )
    
    # Remove permission from role
    result = remove_permission_from_role(db, assignment.role_id, assignment.permission_id, current_user.id)
    
    if not result:
        return {"message": "Permission is not assigned to role"}
    
    return {"message": f"Permission '{permission.name}' removed from role '{role.name}' successfully"}