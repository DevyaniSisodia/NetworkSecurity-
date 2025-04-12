from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta
import json

from database import get_db, Prediction
from models import CyberThreatPredictor

router = APIRouter(
    prefix="/predictions",
    tags=["predictions"],
    responses={404: {"description": "Not found"}},
)

@router.get("/")
async def get_predictions(
    sector: Optional[str] = None,
    technology: Optional[str] = None,
    days: int = 7,
    db: Session = Depends(get_db)
):
    """Get threat predictions for the specified criteria"""
    query = db.query(Prediction)
    
    # Filter by sector if provided
    if sector:
        query = query.filter(Prediction.target_sector == sector)
    
    # Filter by technology if provided
    if technology:
        query = query.filter(Prediction.target_technology == technology)
    
    # Get predictions for the next X days
    cutoff_date = datetime.now() - timedelta(days=1)  # Exclude past predictions
    query = query.filter(Prediction.timestamp > cutoff_date)
    
    # Limit to the requested number of days
    max_date = datetime.now() + timedelta(days=days)
    query = query.filter(Prediction.timestamp <= max_date)
    
    # Order by timestamp and confidence
    predictions = query.order_by(Prediction.timestamp, Prediction.confidence.desc()).all()
    
    return [{
        "id": p.id,
        "timestamp": p.timestamp,
        "target_sector": p.target_sector,
        "target_technology": p.target_technology,
        "attack_type": p.attack_type,
        "confidence": p.confidence,
        "predicted_timeframe": p.predicted_timeframe,
        "verified": p.verified
    } for p in predictions]

@router.post("/generate")
async def generate_predictions(days_ahead: int = 7):
    """Generate new predictions using the AI model"""
    predictor = CyberThreatPredictor(model_path="models/threat_predictor")
    predictions = predictor.predict_threats(days_ahead=days_ahead)
    
    return {"message": f"Generated {len(predictions)} predictions", "predictions": predictions}

@router.get("/sectors")
async def get_target_sectors(db: Session = Depends(get_db)):
    """Get all unique target sectors from predictions"""
    sectors = db.query(Prediction.target_sector).distinct().all()
    return [sector[0] for sector in sectors]

@router.get("/technologies")
async def get_target_technologies(db: Session = Depends(get_db)):
    """Get all unique target technologies from predictions"""
    technologies = db.query(Prediction.target_technology).distinct().all()
    return [tech[0] for tech in technologies]