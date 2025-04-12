import requests
import json
import pandas as pd
import asyncio
import logging
from datetime import datetime, timedelta
from database import SessionLocal, ThreatSource, RawThreatData

logger = logging.getLogger(__name__)

class ThreatIntelLoader:
    def __init__(self):
        self.db = SessionLocal()
        
    async def load_all_sources(self):
        """Load data from all active threat sources"""
        sources = self.db.query(ThreatSource).filter(ThreatSource.is_active == True).all()
        
        for source in sources:
            try:
                if source.source_type == "threat_feed":
                    await self.load_threat_feed(source)
                elif source.source_type == "dark_web":
                    await self.load_dark_web_data(source)
                elif source.source_type == "cve":
                    await self.load_cve_data(source)
            except Exception as e:
                logger.error(f"Error loading data from {source.name}: {str(e)}")
    
    async def load_threat_feed(self, source):
        """Load data from threat intelligence feeds"""
        headers = {}
        if source.api_key:
            headers["Authorization"] = f"Bearer {source.api_key}"
            
        response = requests.get(source.url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            # Process and store the data
            for item in data.get("items", []):
                threat_data = RawThreatData(
                    source_id=source.id,
                    data_type=item.get("type", "unknown"),
                    target_sector=item.get("sector"),
                    target_technology=item.get("technology"),
                    severity=item.get("severity"),
                    raw_data=json.dumps(item)
                )
                self.db.add(threat_data)
            
            self.db.commit()
            logger.info(f"Loaded {len(data.get('items', []))} threats from {source.name}")
        else:
            logger.error(f"Failed to load from {source.name}: {response.status_code}")
    
    async def load_dark_web_data(self, source):
        """Placeholder for dark web data collection"""
        # This would typically involve specialized scraping tools or APIs
        # For demo purposes, we'll just log this
        logger.info(f"Dark web data collection from {source.name} would happen here")
        
    async def load_cve_data(self, source):
        """Load CVE vulnerability data"""
        # Example using the NVD API
        today = datetime.now()
        last_month = today - timedelta(days=30)
        
        params = {
            "pubStartDate": last_month.strftime("%Y-%m-%dT00:00:00:000 UTC-00:00"),
            "pubEndDate": today.strftime("%Y-%m-%dT00:00:00:000 UTC-00:00")
        }
        
        response = requests.get(source.url, params=params)
        if response.status_code == 200:
            data = response.json()
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                
                # Extract severity if available
                severity = None
                metrics = cve.get("metrics", {}).get("cvssMetricV31", [])
                if metrics:
                    severity = metrics[0].get("cvssData", {}).get("baseScore")
                
                # Determine target technology from description
                descriptions = cve.get("descriptions", [])
                description_text = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description_text = desc.get("value", "")
                        break
                
                threat_data = RawThreatData(
                    source_id=source.id,
                    data_type="vulnerability",
                    target_technology=self._extract_technology(description_text),
                    severity=severity,
                    raw_data=json.dumps(item)
                )
                self.db.add(threat_data)
            
            self.db.commit()
            logger.info(f"Loaded {len(data.get('vulnerabilities', []))} CVEs")
        else:
            logger.error(f"Failed to load CVEs: {response.status_code}")
    
    def _extract_technology(self, text):
        """Basic function to extract technology mentions from text"""
        # In a real system, this would use NLP techniques
        # For demo purposes, we'll use a simple approach
        common_techs = ["Windows", "Linux", "Apache", "Nginx", "MySQL", "PostgreSQL", 
                       "MongoDB", "Docker", "Kubernetes", "AWS", "Azure", "WordPress"]
        
        for tech in common_techs:
            if tech.lower() in text.lower():
                return tech
        
        return "Unknown"

# Function to run the data loader periodically
async def scheduled_data_loading():
    loader = ThreatIntelLoader()
    while True:
        await loader.load_all_sources()
        # Run every hour
        await asyncio.sleep(3600)