from fastapi import FastAPI, Depends, HTTPException, status, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from typing import List, Optional

from .models import (
    Resident, ResidentCreate, ResidentUpdate, ResidentResponse,
    User, UserCreate, UserBase, TokenResponse, UserRoleEnum,
    ModerationRequest, ModerationRequestResponse,
    AuditLog, AuditLogResponse, Base as SQLABase
)
from .db import get_db, engine
from .auth_utils import (
    hash_password, verify_password, create_access_token, get_current_user, require_role
)
import csv
import io
from datetime import datetime

# --- FastAPI App ---
app = FastAPI(
    title="Resident Directory Backend",
    description="APIs for residential directory CRUD, authentication, moderation, export, and audit logging.",
    version="1.0.0",
    openapi_tags=[
        {"name": "Auth", "description": "Authentication and role-based access."},
        {"name": "Residents", "description": "CRUD for residents directory."},
        {"name": "Moderation", "description": "Review/approve resident info requests."},
        {"name": "AuditLog", "description": "Audit logging for all actions."},
        {"name": "Export", "description": "CSV export of resident directory."},
    ]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create tables if not exist (for dev/first-run)
SQLABase.metadata.create_all(bind=engine)

@app.get("/", tags=["Health"])
def health_check():
    """Health check endpoint."""
    return {"message": "Healthy"}


# ----------------- AUTH -----------------

@app.post("/auth/register", response_model=UserBase, tags=["Auth"])
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    """Register a new user (admin only for production, demo allows open registration)."""
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=409, detail="Email already registered")
    user_obj = User(
        email=user.email,
        password_hash=hash_password(user.password),
        role=user.role,
        name=user.name,
    )
    db.add(user_obj)
    db.commit()
    db.refresh(user_obj)
    return UserBase.from_orm(user_obj)

@app.post("/auth/login", response_model=TokenResponse, tags=["Auth"])
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Authenticate user and return JWT token."""
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )
    access_token = create_access_token(data={"user_id": user.id, "role": user.role})
    return TokenResponse(
        access_token=access_token,
        user=UserBase(email=user.email, role=user.role, name=user.name)
    )


# ----------------- RESIDENTS CRUD -----------------

@app.get("/residents", response_model=List[ResidentResponse], tags=["Residents"])
def list_residents(
    search: Optional[str] = Query(None, description="Search name or unit"),
    skip: int = 0, limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List/search residents."""
    q = db.query(Resident).filter(Resident.is_active == True)
    if search:
        q = q.filter(
            (Resident.name.ilike(f"%{search}%")) |
            (Resident.unit.ilike(f"%{search}%"))
        )
    return [ResidentResponse.from_orm(r) for r in q.offset(skip).limit(limit).all()]

@app.get("/residents/{resident_id}", response_model=ResidentResponse, tags=["Residents"])
def get_resident(resident_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Fetch a single resident."""
    resident = db.query(Resident).filter(Resident.id == resident_id, Resident.is_active == True).first()
    if not resident:
        raise HTTPException(status_code=404, detail="Resident not found")
    return ResidentResponse.from_orm(resident)

@app.post("/residents", response_model=ResidentResponse, tags=["Residents"])
def create_resident(
    resident_data: ResidentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role([UserRoleEnum.admin, UserRoleEnum.moderator]))
):
    """Add a new resident."""
    resident = Resident(
        **resident_data.dict(),
        updated_by=current_user.id,
        updated_at=datetime.utcnow(),
        is_active=True
    )
    db.add(resident)
    db.commit()
    db.refresh(resident)
    # Audit log
    log = AuditLog(
        user_id=current_user.id, action="create", target_type="resident",
        target_id=resident.id,
        changes=str(resident_data.dict()),
        timestamp=datetime.utcnow(),
    )
    db.add(log)
    db.commit()
    return ResidentResponse.from_orm(resident)

@app.put("/residents/{resident_id}", response_model=ResidentResponse, tags=["Residents"])
def update_resident(
    resident_id: int,
    updates: ResidentUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role([UserRoleEnum.admin, UserRoleEnum.moderator, UserRoleEnum.resident]))
):
    """
    Update a resident.
    - Residents may only update their own unit/email/phone/name (creates moderation request if not admin/moderator).
    - Admins and Moderators can update any.
    """
    resident = db.query(Resident).filter(Resident.id == resident_id, Resident.is_active == True).first()
    if not resident:
        raise HTTPException(status_code=404, detail="Resident not found")

    # RBAC: Residents cannot update other units
    if current_user.role == UserRoleEnum.resident and resident.email != current_user.email:
        raise HTTPException(status_code=403, detail="Residents can only update their own profile.")

    # If admin/mod, update directly; if resident, create moderation request
    if current_user.role != UserRoleEnum.resident:
        for attr, value in updates.dict(exclude_unset=True).items():
            setattr(resident, attr, value)
        resident.updated_by = current_user.id
        resident.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(resident)
        log = AuditLog(
            user_id=current_user.id, action="update", target_type="resident",
            target_id=resident.id,
            changes=str(updates.dict(exclude_unset=True)),
            timestamp=datetime.utcnow(),
        )
        db.add(log)
        db.commit()
        return ResidentResponse.from_orm(resident)
    else:
        # Resident - moderation
        for field, value in updates.dict(exclude_unset=True).items():
            if getattr(resident, field) != value:
                mr = ModerationRequest(
                    resident_id=resident.id,
                    requestor_id=current_user.id,
                    field=field,
                    old_value=getattr(resident, field),
                    new_value=value,
                    status="pending",
                    requested_at=datetime.utcnow(),
                )
                db.add(mr)
                db.commit()
        db.refresh(resident)
        return ResidentResponse.from_orm(resident)

@app.delete("/residents/{resident_id}", status_code=204, tags=["Residents"])
def delete_resident(
    resident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role([UserRoleEnum.admin]))
):
    """Deactivate (soft delete) a resident."""
    resident = db.query(Resident).filter(Resident.id == resident_id, Resident.is_active == True).first()
    if not resident:
        raise HTTPException(status_code=404, detail="Resident not found")
    resident.is_active = False
    db.commit()
    # Audit log
    log = AuditLog(
        user_id=current_user.id, action="delete", target_type="resident",
        target_id=resident.id, changes="Set is_active=False", timestamp=datetime.utcnow()
    )
    db.add(log)
    db.commit()
    return Response(status_code=204)


# ----------------- MODERATION QUEUE -----------------

@app.get("/moderation", response_model=List[ModerationRequestResponse], tags=["Moderation"])
def list_moderation_requests(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role([UserRoleEnum.admin, UserRoleEnum.moderator]))
):
    """List all pending moderation requests."""
    mrs = db.query(ModerationRequest).filter(ModerationRequest.status == "pending").all()
    return [ModerationRequestResponse.from_orm(mr) for mr in mrs]

@app.post("/moderation/{request_id}/approve", response_model=ModerationRequestResponse, tags=["Moderation"])
def approve_moderation_request(
    request_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role([UserRoleEnum.admin, UserRoleEnum.moderator]))
):
    """Approve and apply moderation request."""
    mr = db.query(ModerationRequest).filter(ModerationRequest.id == request_id).first()
    if not mr or mr.status != "pending":
        raise HTTPException(status_code=404, detail="Moderation request not found")
    resident = db.query(Resident).filter(Resident.id == mr.resident_id).first()
    if not resident:
        raise HTTPException(status_code=404, detail="Resident not found")
    # Apply the change
    setattr(resident, mr.field, mr.new_value)
    resident.updated_by = current_user.id
    resident.updated_at = datetime.utcnow()
    mr.status = "approved"
    mr.reviewed_by = current_user.id
    mr.reviewed_at = datetime.utcnow()
    db.commit()
    db.refresh(mr)
    # Audit
    log = AuditLog(
        user_id=current_user.id,
        action="moderation-approved",
        target_type="resident",
        target_id=resident.id,
        changes=f"{mr.field} changed from {mr.old_value} to {mr.new_value} (moderated)",
        timestamp=datetime.utcnow()
    )
    db.add(log)
    db.commit()
    return ModerationRequestResponse.from_orm(mr)


@app.post("/moderation/{request_id}/reject", response_model=ModerationRequestResponse, tags=["Moderation"])
def reject_moderation_request(
    request_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role([UserRoleEnum.admin, UserRoleEnum.moderator]))
):
    """Reject a moderation request."""
    mr = db.query(ModerationRequest).filter(ModerationRequest.id == request_id).first()
    if not mr or mr.status != "pending":
        raise HTTPException(status_code=404, detail="Moderation request not found")
    mr.status = "rejected"
    mr.reviewed_by = current_user.id
    mr.reviewed_at = datetime.utcnow()
    db.commit()
    db.refresh(mr)
    # Audit
    log = AuditLog(
        user_id=current_user.id,
        action="moderation-rejected",
        target_type="resident",
        target_id=mr.resident_id,
        changes=f"Field {mr.field} change rejected",
        timestamp=datetime.utcnow()
    )
    db.add(log)
    db.commit()
    return ModerationRequestResponse.from_orm(mr)


# ----------------- EXPORT DIRECTORY (CSV) -----------------

@app.get("/export/csv", response_class=StreamingResponse, tags=["Export"])
def export_residents_csv(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role([UserRoleEnum.admin, UserRoleEnum.moderator]))
):
    """Export resident directory as CSV file."""
    residents = db.query(Resident).filter(Resident.is_active == True).all()
    headers = ["id", "name", "unit", "phone", "email", "updated_by", "updated_at"]
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(headers)
    for r in residents:
        cw.writerow([getattr(r, h) for h in headers])
    si.seek(0)
    # Streaming Response with correct filename
    response = StreamingResponse(
        iter([si.read()]), media_type="text/csv"
    )
    response.headers["Content-Disposition"] = "attachment; filename=residents.csv"
    return response


# ----------------- AUDIT LOGS -----------------

@app.get("/audit", response_model=List[AuditLogResponse], tags=["AuditLog"])
def list_audit_logs(
    skip: int = 0, limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role([UserRoleEnum.admin, UserRoleEnum.moderator]))
):
    """List audit logs."""
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit).all()
    return [AuditLogResponse.from_orm(log) for log in logs]
