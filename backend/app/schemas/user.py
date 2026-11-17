"""
Pydantic v2 schemas for User entities and roles.
"""
import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, EmailStr

from app.models.user import UserRole


class UserBase(BaseModel):
    email: EmailStr
    full_name: Optional[str] = None
    role: UserRole = UserRole.USER


class UserCreate(UserBase):
    password: str


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    full_name: Optional[str] = None
    role: UserRole
    is_active: bool
    created_at: datetime
    updated_at: datetime

