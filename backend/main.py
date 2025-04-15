from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from database import get_db, engine, Base, ThreatSource, RawThreatData, Prediction
from ml_models import CyberThreatPredictor
from typing import List, Optional
from pydantic import BaseModel
import logging
import datetime
import json

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI
app = FastAPI(title="Cyberthreat Prediction API")

# Initialize predictor
model = CyberThreatPredictor()

# Pydantic models for API
class ThreatSourceCreate(BaseModel):
    name: str
    source_type: str
    url: Optional[str] = None
    api_key: Optional[str] = None
    is_active: bool = True

class ThreatSourceResponse(BaseModel):
    id: int
    name: str
    source_type: str
    url: Optional[str] = None
    is_active: bool

    class Config:
        orm_mode = True

class ThreatDataCreate(BaseModel):
    source_id: Optional[int] = None
    data_type: str
    target_sector: str
    target_technology: Optional[str] = None
    severity: float
    raw_data: Optional[dict] = None
    threat_type: Optional[str] = None
    description: Optional[str] = None
    indicators: Optional[dict] = None

class PredictionResponse(BaseModel):
    id: int
    timestamp: datetime.datetime
    target_sector: str
    target_technology: Optional[str] = None
    attack_type: str
    confidence: float
    predicted_timeframe: Optional[str] = None

    class Config:
        orm_mode = True

# Create database tables on startup
@app.on_event("startup")
async def startup_event():
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created")

# Train model in background
def train_model_task():
    try:
        logger.info("Starting model training")
        result = model.train()
        logger.info(f"Model training completed: {result}")
    except Exception as e:
        logger.error(f"Error training model: {str(e)}")

# API Endpoints
@app.post("/api/threat-sources/", response_model=ThreatSourceResponse)
def create_threat_source(source: ThreatSourceCreate, db: Session = Depends(get_db)):
    db_source = ThreatSource(**source.dict())
    db.add(db_source)
    db.commit()
    db.refresh(db_source)
    return db_source

@app.get("/api/threat-sources/", response_model=List[ThreatSourceResponse])
def list_threat_sources(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    sources = db.query(ThreatSource).offset(skip).limit(limit).all()
    return sources

@app.post("/api/threat-data/")
def add_threat_data(data: ThreatDataCreate, db: Session = Depends(get_db)):
    raw_data_json = json.dumps(data.raw_data) if data.raw_data else None
    indicators_json = json.dumps(data.indicators) if data.indicators else None
    
    db_data = RawThreatData(
        source_id=data.source_id,
        data_type=data.data_type,
        target_sector=data.target_sector,
        target_technology=data.target_technology,
        severity=data.severity,
        raw_data=raw_data_json,
        threat_type=data.threat_type,
        description=data.description,
        indicators=indicators_json
    )
    db.add(db_data)
    db.commit()
    db.refresh(db_data)
    return {"id": db_data.id, "message": "Threat data added successfully"}

@app.post("/api/train-model/")
def train_model_endpoint(background_tasks: BackgroundTasks):
    background_tasks.add_task(train_model_task)
    return {"message": "Model training started in background"}

@app.get("/api/predictions/", response_model=List[PredictionResponse])
def get_predictions(days: int = 7, db: Session = Depends(get_db)):
    predictions = model.predict_threats(days_ahead=days)
    return db.query(Prediction).order_by(Prediction.timestamp.desc()).limit(days*5).all()
@app.get("/api/predictions/", response_model=List[PredictionResponse])
def get_predictions(days: int = 7, db: Session = Depends(get_db)):
    # Generate new predictions
    new_predictions = model.predict_threats(days_ahead=days)
    
    # Store them in the database
    for pred in new_predictions:
        db_pred = Prediction(**pred)
        db.add(db_pred)
    db.commit()
    
    # Return all recent predictions
    return db.query(Prediction).order_by(Prediction.timestamp.desc()).limit(days*5).all()

@app.get("/api/health/")
def health_check():
    return {"status": "healthy", "timestamp": datetime.datetime.now().isoformat()}

# Run the application
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)