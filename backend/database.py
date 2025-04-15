# database.py - Keep your SQLAlchemy model definitions
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import datetime

# Database connection
SQLALCHEMY_DATABASE_URL = "postgresql://postgres:dev123@localhost/cyberthreat"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    echo=True  # Set to False in production
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Database models
class ThreatSource(Base):
    __tablename__ = "threat_sources"
   
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True)
    source_type = Column(String)  # e.g., "dark_web", "threat_feed", "cve"
    url = Column(String, nullable=True)
    api_key = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
   
    threats = relationship("RawThreatData", back_populates="source")

class RawThreatData(Base):
    __tablename__ = "raw_threat_data"
   
    id = Column(Integer, primary_key=True, index=True)
    source_id = Column(Integer, ForeignKey("threat_sources.id"), nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    data_type = Column(String, nullable=True)  # e.g., "vulnerability", "exploit", "attack"
    target_sector = Column(String, nullable=True)
    target_technology = Column(String, nullable=True)
    severity = Column(Float, nullable=True)
    raw_data = Column(Text, nullable=True)  # JSON or raw data
    processed = Column(Boolean, default=False)
    threat_type = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    indicators = Column(Text, nullable=True)  # Can store JSON as text
   
    source = relationship("ThreatSource", back_populates="threats")
   
class Prediction(Base):
    __tablename__ = "predictions"
   
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    target_sector = Column(String)
    target_technology = Column(String, nullable=True)
    attack_type = Column(String)
    confidence = Column(Float)
    predicted_timeframe = Column(String, nullable=True)  # e.g., "24h", "7d"
    features_used = Column(Text, nullable=True)  # JSON of features used
    model_version = Column(String, nullable=True)
    verified = Column(Boolean, default=False)
    verified_timestamp = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    reasoning = Column(Text, nullable=True)
    accuracy = Column(Float, nullable=True)