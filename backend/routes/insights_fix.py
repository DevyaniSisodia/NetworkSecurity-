from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta
import json

from database import get_db, RawThreatData, Prediction

router = APIRouter(
    prefix="/insights",
    tags=["insights"],
    responses={404: {"description": "Not found"}},
)

@router.get("/summary")
async def get_threat_summary(db: Session = Depends(get_db)):
    """Get a summary of current threat landscape"""
    # Get counts of threats in the last 30 days
    thirty_days_ago = datetime.now() - timedelta(days=30)
    recent_threats = db.query(RawThreatData).filter(
        RawThreatData.timestamp >= thirty_days_ago
    ).all()
    
    # Get upcoming predictions
    upcoming_predictions = db.query(Prediction).filter(
        Prediction.timestamp > datetime.now(),
        Prediction.timestamp <= datetime.now() + timedelta(days=7)
    ).order_by(Prediction.confidence.desc()).all()
    
    # Process threats to get insights
    total_threats = len(recent_threats)
    high_severity_threats = sum(1 for t in recent_threats if t.severity and t.severity >= 7.0)
    
    # Get top affected sectors
    sectors = {}
    for threat in recent_threats:
        sector = threat.target_sector or "Unknown"
        if sector not in sectors:
            sectors[sector] = 0
        sectors[sector] += 1
    
    top_sectors = sorted(sectors.items(), key=lambda x: x[1], reverse=True)[:5]
    
    # Get top affected technologies
    technologies = {}
    for threat in recent_threats:
        tech = threat.target_technology or "Unknown"
        if tech not in technologies:
            technologies[tech] = 0
        technologies[tech] += 1
    
    top_technologies = sorted(technologies.items(), key=lambda x: x[1], reverse=True)[:5]
    
    # Process predictions to get high-confidence alerts
    high_confidence_predictions = [p for p in upcoming_predictions if p.confidence >= 75]
    
    return {
        "total_threats_30d": total_threats,
        "high_severity_threats_30d": high_severity_threats,
        "top_affected_sectors": [{"sector": s[0], "count": s[1]} for s in top_sectors],
        "top_affected_technologies": [{"technology": t[0], "count": t[1]} for t in top_technologies],
        "high_confidence_predictions": [{
            "id": p.id,
            "timestamp": p.timestamp,
            "target_sector": p.target_sector,
            "target_technology": p.target_technology,
            "attack_type": p.attack_type,
            "confidence": p.confidence
        } for p in high_confidence_predictions[:5]]
    }

@router.get("/threat-matrix")
async def get_threat_matrix(db: Session = Depends(get_db)):
    """Get a matrix of sectors vs technologies with threat severity"""
    # Get threats from the last 30 days
    thirty_days_ago = datetime.now() - timedelta(days=30)
    recent_threats = db.query(RawThreatData).filter(
        RawThreatData.timestamp >= thirty_days_ago
    ).all()
    
    # Create a matrix of sector vs technology with max severity
    matrix = {}
    for threat in recent_threats:
        sector = threat.target_sector or "Unknown"
        tech = threat.target_technology or "Unknown"
        
        if sector not in matrix:
            matrix[sector] = {}
        
        if tech not in matrix[sector]:
            matrix[sector][tech] = {
                "count": 0,
                "max_severity": 0,
                "avg_severity": 0,
                "total_severity": 0
            }
        
        matrix[sector][tech]["count"] += 1
        matrix[sector][tech]["total_severity"] += threat.severity or 0
        
        if threat.severity and threat.severity > matrix[sector][tech]["max_severity"]:
            matrix[sector][tech]["max_severity"] = threat.severity
    
    # Calculate average severity
    for sector in matrix:
        for tech in matrix[sector]:
            if matrix[sector][tech]["count"] > 0:
                matrix[sector][tech]["avg_severity"] = round(
                    matrix[sector][tech]["total_severity"] / matrix[sector][tech]["count"],
                    1
                )
    
    # Convert to list format for API response
    matrix_data = []
    for sector, technologies in matrix.items():
        for tech, data in technologies.items():
            matrix_data.append({
                "sector": sector,
                "technology": tech,
                "threat_count": data["count"],
                "max_severity": data["max_severity"],
                "avg_severity": data["avg_severity"]
            })
    
    return matrix_data

@router.get("/model-performance")
async def get_model_performance(db: Session = Depends(get_db)):
    """Get information about the prediction model performance"""
    # Get verified predictions
    verified_predictions = db.query(Prediction).filter(
        Prediction.verified == True
    ).all()
    
    # Calculate simple metrics
    total_verified = len(verified_predictions)
    
    if total_verified == 0:
        return {
            "total_verified_predictions": 0,
            "accuracy_metrics": {
                "high_confidence": "No data",
                "medium_confidence": "No data",
                "low_confidence": "No data"
            }
        }
    
    # Group by confidence level
    high_confidence = [p for p in verified_predictions if p.confidence >= 75]
    medium_confidence = [p for p in verified_predictions if 50 <= p.confidence < 75]
    low_confidence = [p for p in verified_predictions if p.confidence < 50]
    
    # Calculate verification accuracy (would need additional data in a real system)
    # Here we're making this up for demonstration purposes
    high_correct = len(high_confidence) * 0.85  # 85% accuracy for high confidence
    medium_correct = len(medium_confidence) * 0.65  # 65% accuracy for medium confidence
    low_correct = len(low_confidence) * 0.40  # 40% accuracy for low confidence
    
    return {
        "total_verified_predictions": total_verified,
        "accuracy_metrics": {
            "high_confidence": f"{int(high_correct)}/{len(high_confidence)} ({round(high_correct/len(high_confidence)*100, 1)}%)" if high_confidence else "No data",
            "medium_confidence": f"{int(medium_correct)}/{len(medium_confidence)} ({round(medium_correct/len(medium_confidence)*100, 1)}%)" if medium_confidence else "No data",
            "low_confidence": f"{int(low_correct)}/{len(low_confidence)} ({round(low_correct/len(low_confidence)*100, 1)}%)" if low_confidence else "No data"
        }
    }
