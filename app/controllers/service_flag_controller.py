from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session
from typing import List, Optional
import math

from app.database import get_db
from app.schemas.service_flag import (
    ServiceFlagCreate, ServiceFlagUpdate, ServiceFlagInDB, ServiceFlagList, ServiceFlagAccess
)
from app.services.auth_service import (
    get_current_user, check_admin_access, check_super_admin_access, check_permission
)
from app.services.service_flag_service import (
    create_service_flag, get_service_flag_by_id, get_service_flags, 
    update_service_flag, delete_service_flag, check_service_flag_access
)
from app.models.user import User, ServiceFlag

router = APIRouter()

@router.post("/", response_model=ServiceFlagInDB, status_code=status.HTTP_201_CREATED)
async def create_new_service_flag(
    flag_data: ServiceFlagCreate,
    db: Session = Depends(get_db),
    request: Request = None,
    current_user: User = Depends(check_super_admin_access)
):
    # Check if flag with same name already exists
    existing_flag = db.query(ServiceFlag).filter(ServiceFlag.name == flag_data.name).first()
    if existing_flag:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Service flag with this name already exists"
        )
    
    # Add request metadata
    flag_dict = flag_data.dict()
    flag_dict["ip_address"] = request.client.host if request else None
    flag_dict["user_agent"] = request.headers.get("User-Agent") if request else None
    
    # Create service flag
    flag = create_service_flag(db, flag_dict, current_user.id)
    
    return flag

@router.get("/", response_model=ServiceFlagList)
async def read_service_flags(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(check_permission("service_flag:read"))
):
    # Determine which flags to include based on user role
    include_developer_only = current_user.has_role("developer") or current_user.is_admin() or current_user.is_super_admin()
    include_admin_only = current_user.is_admin() or current_user.is_super_admin()
    include_super_admin_only = current_user.is_super_admin()
    
    flags = get_service_flags(
        db, skip, limit, search, 
        include_developer_only, include_admin_only, include_super_admin_only
    )
    
    # Count total flags accessible to this user
    query = db.query(ServiceFlag)
    
    if not include_developer_only:
        query = query.filter(ServiceFlag.is_developer_only == False)
    
    if not include_admin_only:
        query = query.filter(ServiceFlag.is_admin_only == False)
    
    if not include_super_admin_only:
        query = query.filter(ServiceFlag.is_super_admin_only == False)
    
    total = query.count()
    
    return {
        "flags": flags,
        "total": total,
        "page": math.floor(skip / limit) + 1,
        "page_size": limit,
        "total_pages": math.ceil(total / limit)
    }

@router.get("/{flag_id}", response_model=ServiceFlagInDB)
async def read_service_flag(
    flag_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(check_permission("service_flag:read"))
):
    flag = get_service_flag_by_id(db, flag_id)
    if not flag:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Service flag not found"
        )
    
    # Check if user has access to this flag
    is_developer = current_user.has_role("developer")
    is_admin = current_user.is_admin()
    is_super_admin = current_user.is_super_admin()
    
    if (flag.is_developer_only and not is_developer and not is_admin and not is_super_admin) or \
       (flag.is_admin_only and not is_admin and not is_super_admin) or \
       (flag.is_super_admin_only and not is_super_admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have access to this service flag"
        )
    
    return flag

@router.put("/{flag_id}", response_model=ServiceFlagInDB)
async def update_service_flag_info(
    flag_id: int,
    flag_data: ServiceFlagUpdate,
    db: Session = Depends(get_db),
    request: Request = None,
    current_user: User = Depends(check_permission("service_flag:update"))
):
    # Check if flag exists
    flag = get_service_flag_by_id(db, flag_id)
    if not flag:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Service flag not found"
        )
    
    # Only super admins can modify access restrictions
    if (flag_data.is_developer_only is not None or 
        flag_data.is_admin_only is not None or 
        flag_data.is_super_admin_only is not None) and not current_user.is_super_admin():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only super admins can modify access restrictions"
        )
    
    # Add request metadata
    flag_dict = flag_data.dict(exclude_unset=True)
    flag_dict["ip_address"] = request.client.host if request else None
    flag_dict["user_agent"] = request.headers.get("User-Agent") if request else None
    
    # Update service flag
    updated_flag = update_service_flag(db, flag_id, flag_dict, current_user.id)
    
    return updated_flag

@router.delete("/{flag_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_service_flag_record(
    flag_id: int,
    db: Session = Depends(get_db),
    request: Request = None,
    current_user: User = Depends(check_super_admin_access)
):
    # Check if flag exists
    flag = get_service_flag_by_id(db, flag_id)
    if not flag:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Service flag not found"
        )
    
    # Delete service flag
    ip_address = request.client.host if request else None
    user_agent = request.headers.get("User-Agent") if request else None
    
    delete_service_flag(db, flag_id, current_user.id, ip_address, user_agent)
    
    return None

@router.get("/check/{flag_name}", response_model=ServiceFlagAccess)
async def check_flag_access(
    flag_name: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Check if user has access to this flag
    is_developer = current_user.has_role("developer")
    is_admin = current_user.is_admin()
    is_super_admin = current_user.is_super_admin()
    
    has_access = check_service_flag_access(db, flag_name, is_developer, is_admin, is_super_admin)
    
    return {
        "flag_name": flag_name,
        "has_access": has_access
    }

@router.post("/{flag_id}/toggle", response_model=ServiceFlagInDB)
async def toggle_service_flag(
    flag_id: int,
    db: Session = Depends(get_db),
    request: Request = None,
    current_user: User = Depends(check_permission("service_flag:update"))
):
    # Check if flag exists
    flag = get_service_flag_by_id(db, flag_id)
    if not flag:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Service flag not found"
        )
    
    # Check if user has access to toggle this flag
    is_developer = current_user.has_role("developer")
    is_admin = current_user.is_admin()
    is_super_admin = current_user.is_super_admin()
    
    if (flag.is_developer_only and not is_developer and not is_admin and not is_super_admin) or \
       (flag.is_admin_only and not is_admin and not is_super_admin) or \
       (flag.is_super_admin_only and not is_super_admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have access to toggle this service flag"
        )
    
    # Toggle flag
    flag_dict = {
        "is_enabled": not flag.is_enabled,
        "ip_address": request.client.host if request else None,
        "user_agent": request.headers.get("User-Agent") if request else None
    }
    
    updated_flag = update_service_flag(db, flag_id, flag_dict, current_user.id)
    
    return updated_flag