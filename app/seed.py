from app.database import SessionLocal, User, Patient, ScreeningReport
from app.security import encrypt_data
from argon2 import PasswordHasher

ph = PasswordHasher()

db = SessionLocal()

# Create users
patient_user = User(
    username="patient01",
    role="patient",
    password_hash=ph.hash("Patient@123")
)

doctor_user = User(
    username="doctor01",
    role="doctor",
    password_hash=ph.hash("Doctor@123")
)

db.add(patient_user)
db.add(doctor_user)

# Create patient
patient = Patient(
    patient_code="P001",
    name_encrypted=encrypt_data("Arun Kumar")
)

db.add(patient)

# Create dummy screening report
report = ScreeningReport(
    patient_code="P001",
    test_date="2026-09-08",

    sensor_data_encrypted=encrypt_data(
        "MQ-2: 120 | MQ-3: 85 | MQ-135: 140 | MQ-138: 95 | Temperature: 29C | Humidity: 62%"
    ),

    risk_classification_encrypted=encrypt_data(
        "LOW RISK - Screening Result"
    ),

    daily_report_encrypted=encrypt_data(
        "Breath screening completed successfully. "
        "Result is for preliminary screening only and is NOT a medical diagnosis."
    )
)

db.add(report)

db.commit()
db.close()

print("DUMMY DATA CREATED SUCCESSFULLY")
print("Patient username: patient01")
print("Doctor username: doctor01")
print("Patient code: P001")
