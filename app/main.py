from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from argon2 import PasswordHasher

from app.database import SessionLocal, User, ScreeningReport
from app.security import (
    decrypt_data,
    create_access_token,
    decode_access_token
)


# =========================================================
# APPLICATION
# =========================================================

app = FastAPI(
    title="AIRA Secure Medical API",
    description="Secure backend for AIRA medical screening data",
    version="1.0.0"
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,

    # For prototype/demo.
    # In production, replace "*" with the exact frontend URL.
    allow_origins=["https://alaicharan.github.io"],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"],
)


# =========================================================
# SECURITY
# =========================================================

ph = PasswordHasher()

security = HTTPBearer()


# =========================================================
# REQUEST MODELS
# =========================================================

class LoginRequest(BaseModel):
    username: str
    password: str


# =========================================================
# HOME
# =========================================================

@app.get("/api")
def home():

    return {
        "message": "AIRA Secure Medical API",
        "status": "running"
    }


# =========================================================
# LOGIN
# =========================================================

@app.post("/api/login")
def login(data: LoginRequest):

    db = SessionLocal()

    user = db.query(User).filter(
        User.username == data.username
    ).first()

    if not user:

        db.close()

        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    try:

        ph.verify(
            user.password_hash,
            data.password
        )

    except Exception:

        db.close()

        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    token = create_access_token(
        user.username,
        user.role
    )

    username = user.username
    role = user.role

    db.close()

    return {
        "message": "Login successful",
        "access_token": token,
        "token_type": "bearer",
        "username": username,
        "role": role
    }


# =========================================================
# GET CURRENT AUTHENTICATED USER
# =========================================================

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):

    token = credentials.credentials

    try:

        payload = decode_access_token(token)

    except Exception:

        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    username = payload.get("sub")

    if not username:

        raise HTTPException(
            status_code=401,
            detail="Invalid authentication token"
        )

    db = SessionLocal()

    user = db.query(User).filter(
        User.username == username
    ).first()

    if not user:

        db.close()

        raise HTTPException(
            status_code=401,
            detail="User not found"
        )

    user_data = {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "patient_code": user.patient_code
    }

    db.close()

    return user_data


# =========================================================
# PROTECTED MEDICAL REPORT
# =========================================================
@app.get("/api/reports/{patient_code}")
def get_report(
    patient_code: str,
    current_user: dict = Depends(get_current_user)
):

    # -----------------------------------------------------
    # PATIENT AUTHORIZATION
    # -----------------------------------------------------

    if current_user["role"] == "patient":

        # Patient can ONLY access their own report.
        if current_user["patient_code"] != patient_code:

            raise HTTPException(
                status_code=403,
                detail="Access denied"
            )


    # -----------------------------------------------------
    # DOCTOR AUTHORIZATION
    # -----------------------------------------------------

    elif current_user["role"] == "doctor":

        # Demo:
        # doctor01 is assigned to P001.
        if current_user["patient_code"] != patient_code:

            raise HTTPException(
                status_code=403,
                detail="Access denied"
            )


    # -----------------------------------------------------
    # UNKNOWN ROLE
    # -----------------------------------------------------

    else:

        raise HTTPException(
            status_code=403,
            detail="Role not authorized"
        )


    # -----------------------------------------------------
    # GET REPORT FROM DATABASE
    # -----------------------------------------------------

    db = SessionLocal()

    report = db.query(ScreeningReport).filter(
        ScreeningReport.patient_code == patient_code
    ).first()

    if not report:

        db.close()

        raise HTTPException(
            status_code=404,
            detail="Report not found"
        )


    # -----------------------------------------------------
    # DECRYPT SENSITIVE MEDICAL DATA
    # -----------------------------------------------------

    sensor_data = decrypt_data(
        report.sensor_data_encrypted
    )

    risk = decrypt_data(
        report.risk_classification_encrypted
    )

    daily_report = decrypt_data(
        report.daily_report_encrypted
    )

    test_date = report.test_date

    db.close()


    # -----------------------------------------------------
    # RETURN SECURE RESPONSE
    # -----------------------------------------------------

    return {

        "patient_code": patient_code,

        "test_date": test_date,

        "sensor_data": sensor_data,

        "risk_classification": risk,

        "daily_report": daily_report,

        "security": {

            "authentication": "JWT",

            "authorization": "RBAC + patient ownership",

            "data_encryption": "AES-256-GCM"

        }
    }
