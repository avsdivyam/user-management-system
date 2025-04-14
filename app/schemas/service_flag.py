from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class ServiceFlagBase(BaseModel):
    name: str
    description: Optional[str] = None
    is_enabled: Optional[bool] = True
    is_developer_only: Optional[bool] = False
    is_admin_only: Optional[bool] = False
    is_super_admin_only: Optional[bool] = False

class ServiceFlagCreate(ServiceFlagBase):
    pass

class ServiceFlagUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_enabled: Optional[bool] = None
    is_developer_only: Optional[bool] = None
    is_admin_only: Optional[bool] = None
    is_super_admin_only: Optional[bool] = None

class ServiceFlagInDB(ServiceFlagBase):
    id: int
    created_at: datetime
    updated_at: datetime
    
    class Config:
        orm_mode = True

class ServiceFlagList(BaseModel):
    flags: List[ServiceFlagInDB]
    total: int
    page: int
    page_size: int
    total_pages: int

class ServiceFlagAccess(BaseModel):
    flag_name: str
    has_access: bool