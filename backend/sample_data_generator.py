# sample_data_generator.py
import random
from datetime import datetime, timedelta
import json
from database import SessionLocal, ThreatSource, RawThreatData

def generate_sample_data():
    """Generate sample threat data for testing"""
    db = SessionLocal()
    
    # Create sample threat sources
    sources = [
        {"name": "NVD CVE Feed", "source_type": "cve", "url": "https://services.nvd.nist.gov/rest/json/cves/1.0"},
        {"name": "Dark Web Monitor", "source_type": "dark_web", "url": None},
        {"name": "Security News Feed", "source_type": "threat_feed", "url": "https://example.com/security-feed"}
    ]
    
    # Add sources to database if they don't exist
    for source_data in sources:
        source = db.query(ThreatSource).filter(ThreatSource.name == source_data["name"]).first()
        if not source:
            source = ThreatSource(**source_data, is_active=True)
            db.add(source)
    
    db.commit()
    
    # Get the sources from the database
    db_sources = db.query(ThreatSource).all()
    
    # Sample sectors and technologies
    sectors = ["Finance", "Healthcare", "Energy", "Manufacturing", "Government", "Retail", "Technology"]
    technologies = ["Windows", "Linux", "Apache", "Nginx", "AWS", "Azure", "Docker", "Kubernetes", "WordPress", "MongoDB"]
    attack_types = ["SQL Injection", "Cross-Site Scripting", "Remote Code Execution", "Denial of Service", "Data Breach"]
    
    # Generate threats for the past 90 days
    start_date = datetime.now() - timedelta(days=90)
    end_date = datetime.now()
    
    current_date = start_date
    while current_date <= end_date:
        # Generate 5-15 threats per day
        num_threats = random.randint(5, 15)
        
        for _ in range(num_threats):
            # Create a threat with random attributes
            source = random.choice(db_sources)
            sector = random.choice(sectors)
            technology = random.choice(technologies)
            attack_type = random.choice(attack_types)
            severity = round(random.uniform(1.0, 10.0), 1)
            
            # Create some variation in timestamps
            hours_offset = random.randint(0, 23)
            minutes_offset = random.randint(0, 59)
            timestamp = current_date.replace(hour=hours_offset, minute=minutes_offset)
            
            # Create sample raw data
            raw_data = {
                "type": attack_type,
                "details": f"Sample {attack_type} threat targeting {technology} in {sector} sector",
                "attackVector": random.choice(["network", "adjacent", "local", "physical"]),
                "exploitability": random.randint(1, 10),
                "impact": random.uniform(1.0, 10.0),
                "cve": f"CVE-{random.randint(2020, 2023)}-{random.randint(10000, 99999)}" if random.random() > 0.3 else None
            }
            
            # Create threat in database
            threat = RawThreatData(
                source_id=source.id,
                timestamp=timestamp,
                data_type=attack_type.lower().replace(" ", "_"),
                target_sector=sector,
                target_technology=technology,
                severity=severity,
                raw_data=json.dumps(raw_data)
            )
            
            db.add(threat)
        
        # Move to next day
        current_date += timedelta(days=1)
    
    db.commit()
    print(f"Generated sample threat data for the past 90 days")

if __name__ == "__main__":
    generate_sample_data()