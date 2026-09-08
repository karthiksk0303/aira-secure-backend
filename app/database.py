from sqlalchemy import create_engine, Column, Integer, String, Text
from sqlalchemy.orm import declarative_base, sessionmaker


# =========================
# DATABASE CONFIGURATION
# =========================

DATABASE_URL = "sqlite:///./aira_secure.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={
        "check_same_thread": False
    }
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


# =========================
# USER TABLE
# =========================

class User(Base):
    __tablename__ = "users"

    id = Column(
        Integer,
        primary_key=True
    )

    username = Column(
        String,
        unique=True,
        nullable=False
    )

    role = Column(
        String,
        nullable=False
    )

    password_hash = Column(
        String,
        nullable=False
    )

    # Links the authenticated user to a patient record
    patient_code = Column(
        String,
        nullable=True
    )


# =========================
# PATIENT TABLE
# =========================

class Patient(Base):
    __tablename__ = "patients"

    id = Column(
        Integer,
        primary_key=True
    )

    patient_code = Column(
        String,
        unique=True,
        nullable=False
    )

    # Patient name is stored encrypted
    name_encrypted = Column(
        Text,
        nullable=False
    )


# =========================
# SCREENING REPORT TABLE
# =========================

class ScreeningReport(Base):
    __tablename__ = "screening_reports"

    id = Column(
        Integer,
        primary_key=True
    )

    patient_code = Column(
        String,
        nullable=False
    )

    test_date = Column(
        String,
        nullable=False
    )

    # Sensitive sensor measurements
    sensor_data_encrypted = Column(
        Text,
        nullable=False
    )

    # Risk classification stored encrypted
    risk_classification_encrypted = Column(
        Text,
        nullable=False
    )

    # Daily report stored encrypted
    daily_report_encrypted = Column(
        Text,
        nullable=False
    )


# =========================
# CREATE TABLES
# =========================

Base.metadata.create_all(
    bind=engine
)
