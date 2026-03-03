import os
import jwt
import bcrypt
from datetime import datetime, timedelta
from fastapi import HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from .models import User
from .db import get_db

SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE_THIS_SECRET")
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 6  # 6 hours
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


# PUBLIC_INTERFACE
def hash_password(password: str) -> str:
    """Hash a password for storage."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode()


# PUBLIC_INTERFACE
def verify_password(password: str, hashed: str) -> bool:
    """Check hashed password."""
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


# PUBLIC_INTERFACE
def create_access_token(data: dict, expires_delta: timedelta = None):
    """Generate access JWT token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")
    return encoded_jwt


# PUBLIC_INTERFACE
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    """Get current user by token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id: int = payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid authentication")


# PUBLIC_INTERFACE
def require_role(roles):
    """Role-based access dependency."""
    def role_dependency(current_user: User = Depends(get_current_user)):
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions"
            )
        return current_user
    return role_dependency
