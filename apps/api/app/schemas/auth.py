"""Authentication request/response schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, StringConstraints

from app.core.permissions import Permission, RoleName
from app.core.security.passwords import MAX_PASSWORD_LENGTH

# Input passwords are length-bounded at the schema level to prevent hashing DoS;
# strength rules are applied by the service so they can consider the email.
PasswordInput = Annotated[str, Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)]
FullName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]


class _Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginRequest(_Input):
    email: EmailStr
    password: PasswordInput


class RegisterRequest(_Input):
    email: EmailStr
    full_name: FullName
    password: PasswordInput


class ChangePasswordRequest(_Input):
    current_password: PasswordInput
    new_password: PasswordInput


class PasswordResetRequest(_Input):
    email: EmailStr


class PasswordResetConfirm(_Input):
    token: Annotated[str, Field(min_length=16, max_length=256)]
    new_password: PasswordInput


class CurrentUser(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str
    role: RoleName
    permissions: list[Permission]


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 - OAuth2 token type
    expires_in: int = Field(description="Access token lifetime in seconds.")
    user: CurrentUser


class SessionRead(BaseModel):
    id: uuid.UUID = Field(description="Session (refresh token family) identifier.")
    started_at: datetime
    last_used_at: datetime
    expires_at: datetime
    user_agent: str | None
    ip_address: str | None
    current: bool


class MessageResponse(BaseModel):
    message: str
