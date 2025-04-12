from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta
import json

from database import get_db, RawThreatData, ThreatSource

router = APIRouter(
    prefix="/threats",
    tags=["threats"],
    responses={404: {"description": "Not found"}},
)

@router.get("/")
async def get_threats(
    days: int = 30,
    source_type: Optional[str] = None,
    severity_min: Optional[float] = None,
    db: Session = Depends(get_db)
):
    """Get recent threat data"""
    query = db.query(RawThreatData)
    
    # Filter by time range
    cutoff_date = datetime.now() - timedelta(days=days)
    query = query.filter(RawThreatData.timestamp >= cutoff_date)
    
    # Join with threat source to filter by source type
    if source_type:
        query = query.join(ThreatSource).filter(ThreatSource.source_type == source_type)
    
    # Filter by minimum severity
    if severity_min is not None:
        query = query.filter(RawThreatData.severity >= severity_min)
    
    # Get the threats
    threats = query.order_by(RawThreatData.timestamp.desc()).all()
    
    return [{
        "id": t.id,
        "timestamp": t.timestamp,
        "data_type": t.data_type,
        "target_sector": t.target_sector,
        "target_technology": t.target_technology,
        "severity": t.severity,
        "source": t.source.name if t.source else None
    } for t in threats]

@router.get("/sources")
async def get_threat_sources(db: Session = Depends(get_db)):
    """Get all threat intelligence sources"""
    sources = db.query(ThreatSource).all()
    
    return [{
        "id": s.id,
        "name": s.name,
        "source_type": s.source_type,
        "url": s.url,
        "is_active": s.is_active
    } for s in sources]

@router.post("/sources")
async def add_threat_source(
    name: str,
    source_type: str,
    url: Optional[str] = None,
    api_key: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Add a new threat intelligence source"""
    source = ThreatSource(
        name=name,
        source_type=source_type,
        url=url,
        api_key=api_key,
        is_active=True
    )
    
    db.add(source)
    db.commit()
    db.refresh(source)
    
    return {
        "id": source.id,
        "name": source.name,
        "source_type": source.source_type,
        "url": source.url,
        "is_active": source.is_active
    }

@router.delete("/sources/{source_id}")
async def delete_threat_source(source_id: int, db: Session = Depends(get_db)):
    """Delete a threat intelligence source"""
    source = db.query(ThreatSource).filter(ThreatSource.id == source_id).first()
    if not source:
        raise HTTPException(status_code=404, detail="Source not found")
    
    db.delete(source)
    db.commit()
    
    return {"message": f"Source {source.name} deleted successfully"}

@router.get("/trends")
async def get_threat_trends(days: int = 90, db: Session = Depends(get_db)):
    """Get threat trends over time"""
    cutoff_date = datetime.now() - timedelta(days=days)
    
    # This would typically be a more complex query with grouping by time periods
    # For simplicity, we'll just get all threats and process them in Python
    threats = db.query(RawThreatData).filter(
        RawThreatData.timestamp >= cutoff_date
    ).all()
    
    # Group threats by week
    threats_by_week = {}
    for threat in threats:
        # Get the start of the week for this threat
        week_start = threat.timestamp - timedelta(days=threat.timestamp.weekday())
        week_key = week_start.strftime("%Y-%m-%d")
        
        if week_key not in threats_by_week:
            threats_by_week[week_key] = {
                "total": 0,
                "high_severity": 0,
                "by_sector": {},
                "by_technology": {}
            }
        
        # Increment counts
        threats_by_week[week_key]["total"] += 1
        
        if threat.severity and threat.severity >= 7.0:
            threats_by_week[week_key]["high_severity"] += 1
        
        # Count by sector
        sector = threat.target_sector or "Unknown"
        if sector not in threats_by_week[week_key]["by_sector"]:
            threats_by_week[week_key]["by_sector"][sector] = 0
        threats_by_week[week_key]["by_sector"][sector] += 1
        
        # Count by technology
        tech = threat.target_technology or "Unknown"
        if tech not in threats_by_week[week_key]["by_technology"]:
            threats_by_week[week_key]["by_technology"][tech] = 0
        threats_by_week[week_key]["by_technology"][tech] += 1
    
    # Convert to list of objects for the API response
    trends = []
    for week, data in threats_by_week.items():
        trends.append({
            "week": week,
            "total_threats": data["total"],
            "high_severity_threats": data["high_severity"],
            "by_sector": data["by_sector"],
            "by_technology": data["by_technology"]
        })
    
    # Sort by week
    trends.sort(key=lambda x: x["week"])
    
    return trends