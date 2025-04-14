from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class RoleBase(BaseModel):
    name: str
    description: Optional[str] = None
    is_system_role: Optional[bool] = False

class RoleCreate(RoleBase):
    permissions: Optional[List[str]] = []

class RoleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    permissions: Optional[List[str]] = None

class RoleInDB(RoleBase):
    id: int
    created_at: datetime
    updated_at: datetime
    permissions: List[str] = []
    
    class Config:
        orm_mode = True

class RoleList(BaseModel):
    roles: List[RoleInDB]
    total: int
    page: int
    page_size: int
    total_pages: int

class PermissionBase(BaseModel):
    name: str
    description: Optional[str] = None
    resource: Optional[str] = None
    action: Optional[str] = None

class PermissionCreate(PermissionBase):
    pass

class PermissionUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    resource: Optional[str] = None
    action: Optional[str] = None

class PermissionInDB(PermissionBase):
    id: int
    created_at: datetime
    
    class Config:
        orm_mode = True

class PermissionList(BaseModel):
    permissions: List[PermissionInDB]
    total: int
    page: int
    page_size: int
    total_pages: int

class RoleAssignment(BaseModel):
    user_id: int
    role_id: int

class PermissionAssignment(BaseModel):
    role_id: int
    permission_id: int