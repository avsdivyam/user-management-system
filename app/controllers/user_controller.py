from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session
from typing import List, Optional
import math

from app.database import get_db
from app.schemas.user import (
    UserCreate, UserUpdate, UserResponse, UserList, UserSettingsUpdate
)
from app.services.auth_service import (
    get_current_user, check_admin_access, check_permission
)
from app.services.user_service import (
    create_user, get_user_by_id, get_users, update_user, delete_user,
    log_user_activity
)
from app.services.service_flag_service import check_service_flag_access
from app.models.user import User

router = APIRouter()

@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_new_user(
    user_data: UserCreate,
    db: Session = Depends(get_db),
    request: Request = None,
    current_user: User = Depends(check_permission("user:create"))
):
    # Check if user with same username or email already exists
    existing_user = db.query(User).filter(
        (User.username == user_data.username) | (User.email == user_data.email)
    ).first()
    
    if existing_user:
        if existing_user.username == user_data.username:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already registered"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
    
    # Add request metadata
    user_dict = user_data.dict()
    user_dict["ip_address"] = request.client.host if request else None
    user_dict["user_agent"] = request.headers.get("User-Agent") if request else None
    
    # Create user
    user = create_user(db, user_dict)
    
    # Get user with relationships
    return get_user_by_id(db, user.id)

@router.get("/", response_model=UserList)
async def read_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(check_permission("user:read"))
):
    users = get_users(db, skip, limit, search)
    total = db.query(User).count()
    
    return {
        "users": users,
        "total": total,
        "page": math.floor(skip / limit) + 1,
        "page_size": limit,
        "total_pages": math.ceil(total / limit)
    }

@router.get("/{user_id}", response_model=UserResponse)
async def read_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(check_permission("user:read"))
):
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Regular users can only view their own profile
    if not current_user.is_admin() and not current_user.is_super_admin() and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions to view other users"
        )
    
    return user

@router.put("/{user_id}", response_model=UserResponse)
async def update_user_info(
    user_id: int,
    user_data: UserUpdate,
    db: Session = Depends(get_db),
    request: Request = None,
    current_user: User = Depends(check_permission("user:update"))
):
    # Check if user exists
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Regular users can only update their own profile
    if not current_user.is_admin() and not current_user.is_super_admin() and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions to update other users"
        )
    
    # Regular users cannot change roles
    if user_data.roles and not current_user.is_admin() and not current_user.is_super_admin():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions to change roles"
        )
    
    # Add request metadata
    user_dict = user_data.dict(exclude_unset=True)
    user_dict["ip_address"] = request.client.host if request else None
    user_dict["user_agent"] = request.headers.get("User-Agent") if request else None
    
    # Update user
    updated_user = update_user(db, user_id, user_dict)
    
    return updated_user

@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user_account(
    user_id: int,
    db: Session = Depends(get_db),
    request: Request = None,
    current_user: User = Depends(check_permission("user:delete"))
):
    # Check if user exists
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Regular users can only delete their own account
    if not current_user.is_admin() and not current_user.is_super_admin() and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions to delete other users"
        )
    
    # Super admins cannot be deleted except by themselves
    if user.is_super_admin() and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super admin accounts can only be deleted by themselves"
        )
    
    # Delete user
    ip_address = request.client.host if request else None
    user_agent = request.headers.get("User-Agent") if request else None
    
    delete_user(db, user_id, current_user.id, ip_address, user_agent)
    
    return None

@router.put("/{user_id}/settings", response_model=UserResponse)
async def update_user_settings(
    user_id: int,
    settings_data: UserSettingsUpdate,
    db: Session = Depends(get_db),
    request: Request = None,
    current_user: User = Depends(get_current_user)
):
    # Check if user exists
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Users can only update their own settings
    if current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only update your own settings"
        )
    
    # Add request metadata
    settings_dict = settings_data.dict(exclude_unset=True)
    settings_dict["ip_address"] = request.client.host if request else None
    settings_dict["user_agent"] = request.headers.get("User-Agent") if request else None
    
    # Update user settings
    updated_user = update_user(db, user_id, settings_dict)
    
    return updated_user